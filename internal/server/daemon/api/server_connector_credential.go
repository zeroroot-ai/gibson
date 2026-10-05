// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_connector_credential.go
//
// DaemonOperatorService.GetConnectorCredential (gibson#663). The connector
// operator writes the connector-cred Secret that the ToolHive proxy mounts.
// Only the daemon holds the tenant secret store, so the operator reads the
// content of that Secret here: the "authorization" header with the
// short-lived access token, and each declared static credential.
//
// This reverses decision 2 of ADR-0061 ("the token never crosses an RPC").
// It is acceptable because the connector operator can already read that
// Secret, so no new principal sees the token. The refresh token and the Grant
// never leave the daemon.
//
// The security condition: Envoy routes DaemonOperatorService, so the
// platform_operator relation of ext-authz is not enough for this method. The
// handler reads the TLS peer certificate of the connection itself and serves
// only the direct-dial SPIFFE ID of the connector operator. A call through
// the edge arrives on a connection whose peer is Envoy, and it is refused.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// connectorCredSecretKey is the Secret data key the ToolHive MCPRemoteProxy
// forwards as the Authorization header. The value is "Bearer <token>".
const connectorCredSecretKey = "authorization"

// ConnectorSecretResolver is the slice of the tenant secret store the
// credential read needs: one tenant-scoped Resolve. *secrets.Service
// satisfies it.
type ConnectorSecretResolver interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
}

// WithConnectorCredentialSource wires GetConnectorCredential: the tenant
// secret store, and the one SPIFFE ID that may call it (the connector
// operator). Unwired, the RPC answers Unavailable.
func (s *DaemonServer) WithConnectorCredentialSource(store ConnectorSecretResolver, operatorSVID string) *DaemonServer {
	s.connectorCredStore = store
	s.connectorCredPeer = operatorSVID
	return s
}

// errNotTheConnectorOperator is the answer to every caller that is not the
// direct-dial connector operator. It names no detail of the peer.
var errNotTheConnectorOperator = status.Error(codes.PermissionDenied,
	"GetConnectorCredential is served to the connector operator only")

// GetConnectorCredential returns the content of the connector-cred Secret of
// one tenant connector, to the connector operator only.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: the TLS peer of the
// connection must be the connector operator SVID, checked here (gibson#663).
func (s *DaemonServer) GetConnectorCredential(
	ctx context.Context, req *daemonoperatorv1.GetConnectorCredentialRequest,
) (*daemonoperatorv1.GetConnectorCredentialResponse, error) {
	if s.connectorCredStore == nil || s.connectorCredPeer == "" {
		return nil, status.Error(codes.Unavailable, "connector credentials are not configured on this daemon")
	}
	if peerSPIFFEID(ctx) != s.connectorCredPeer {
		return nil, errNotTheConnectorOperator
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	connector := req.GetConnectorId()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector_id is required")
	}
	reader := connectorCredentialReader{secrets: s.connectorCredStore, now: s.connectorCredNow}
	data, withdraw, err := reader.read(auth.WithTenant(ctx, tenant), connector, req.GetCredentials())
	if err != nil {
		// The error names the connector and the secret key, never a value.
		return nil, status.Errorf(codes.Internal, "connector credential: %v", err)
	}
	return &daemonoperatorv1.GetConnectorCredentialResponse{Data: data, Withdraw: withdraw}, nil
}

// connectorCredentialReader builds the content of a connector-cred Secret
// from the tenant secret store.
type connectorCredentialReader struct {
	secrets ConnectorSecretResolver
	// now is the clock the token expiry is measured on. Nil means time.Now.
	now func() time.Time
}

func (r connectorCredentialReader) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// read returns the Secret data, or withdraw=true when the access token is past
// its expiry and nothing else is declared. A connector with no token yet and
// no declared credential gives empty data and withdraw=false: nothing to
// publish. The platform's own expiry bookkeeping decides whether a token may
// be served at all (ADR-0061): a dead token is withheld, never cached.
func (r connectorCredentialReader) read(
	tctx context.Context, connector string, refs []*daemonoperatorv1.ConnectorCredentialRef,
) (map[string][]byte, bool, error) {
	data := make(map[string][]byte, 1+len(refs))
	header, expired, err := r.bearerHeader(tctx, connector)
	if err != nil {
		return nil, false, err
	}
	if header != nil {
		data[connectorCredSecretKey] = header
	}
	for _, ref := range refs {
		if ref.GetTargetEnv() == "" {
			return nil, false, fmt.Errorf("connector %q: credential %q has no target env", connector, ref.GetKey())
		}
		value, err := r.resolveCredentialRef(tctx, connector, ref)
		if err != nil {
			return nil, false, err
		}
		data[ref.GetTargetEnv()] = value
	}
	if len(data) == 0 {
		return nil, expired, nil
	}
	return data, false, nil
}

// bearerHeader resolves the minted access token as "Bearer <token>". It
// returns nil when nothing is minted yet, and expired=true when the token's
// lifetime has passed, in which case the header is withheld.
func (r connectorCredentialReader) bearerHeader(tctx context.Context, connector string) ([]byte, bool, error) {
	meta, err := r.secrets.Resolve(tctx, connectorauth.AccessMetaSecretName(connector))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("resolve access metadata for connector %q: %w", connector, err)
	}
	if len(meta) == 0 {
		return nil, false, nil
	}
	tok, err := connectorauth.UnmarshalAccessToken(meta)
	if err != nil {
		return nil, false, fmt.Errorf("connector %q: %w", connector, err)
	}
	if tok.Expired(r.clock()) {
		return nil, true, nil
	}
	raw, err := r.secrets.Resolve(tctx, connectorauth.AccessSecretName(connector))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("resolve access token for connector %q: %w", connector, err)
	}
	if len(raw) == 0 {
		return nil, false, nil
	}
	return append([]byte("Bearer "), raw...), false, nil
}

// errNoProperty reports a structured credential with no such property.
var errNoProperty = errors.New("the credential has no such property")

// resolveCredentialRef reads the tenant secret a ref names and narrows it to
// its property when set. A missing secret or property is an error, never an
// empty value.
func (r connectorCredentialReader) resolveCredentialRef(
	tctx context.Context, connector string, ref *daemonoperatorv1.ConnectorCredentialRef,
) ([]byte, error) {
	raw, err := r.secrets.Resolve(tctx, ref.GetKey())
	if err != nil {
		return nil, fmt.Errorf("connector %q: resolve credential %q for %s: %w",
			connector, ref.GetKey(), ref.GetTargetEnv(), err)
	}
	if ref.GetProperty() == "" {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		// The JSON error can quote the input, so it is not wrapped.
		return nil, fmt.Errorf("connector %q: credential %q is not a JSON object, cannot read property %q",
			connector, ref.GetKey(), ref.GetProperty())
	}
	v, ok := fields[ref.GetProperty()]
	if !ok {
		return nil, fmt.Errorf("connector %q: credential %q, property %q: %w",
			connector, ref.GetKey(), ref.GetProperty(), errNoProperty)
	}
	var str string
	if err := json.Unmarshal(v, &str); err == nil {
		return []byte(str), nil
	}
	return []byte(v), nil
}
