// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_model_provider_credential.go
//
// DaemonOperatorService.GetModelProviderCredential (gibson#1387, ADR-0172). It
// reuses the mechanism of GetConnectorCredential. Only the daemon holds the
// tenant secret store. The tenant operator reads the content of the credential
// Secret of a model provider here, and it writes that Secret in the namespace
// of the model gateway. The daemon writes no Kubernetes object (ADR-0023). It
// keeps no copy of the value after the call, and it never calls a provider with
// the value. Only the gateway uses it.
//
// The handler serves only the direct-dial SPIFFE identity of the tenant
// operator. A call through the edge arrives on a connection whose peer is
// Envoy, and it is refused.
package api

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The key names of the Secret that agentgateway reads. They come from the
// source of agentgateway (pkg/wellknown). An API key is the value of
// "Authorization". An AWS credential has the three AWS keys.
const (
	ModelCredentialKeyAuthorization = "Authorization"
	ModelCredentialKeyAccessKey     = "accessKey"
	ModelCredentialKeySecretKey     = "secretKey"
	ModelCredentialKeySessionToken  = "sessionToken"
)

// modelProviderTypeBedrock is the provider type that has an AWS credential.
const modelProviderTypeBedrock = "bedrock"

// WithModelProviderCredentialSource wires GetModelProviderCredential: the
// tenant secret store, and the one SPIFFE ID that may call it (the tenant
// operator). Unwired, the RPC answers Unavailable.
func (s *DaemonServer) WithModelProviderCredentialSource(store ConnectorSecretResolver, operatorSVID string) *DaemonServer {
	s.modelCredStore = store
	s.modelCredPeer = operatorSVID
	return s
}

// errNotTheTenantOperator is the answer to each caller that is not the
// direct-dial tenant operator. It names no detail of the peer.
var errNotTheTenantOperator = status.Error(codes.PermissionDenied,
	"GetModelProviderCredential is served to the tenant operator only")

// GetModelProviderCredential returns the content of the credential Secret of
// one model provider, to the tenant operator only.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: the TLS peer of the
// connection must be the tenant operator SVID, checked here (gibson#1387).
func (s *DaemonServer) GetModelProviderCredential(
	ctx context.Context, req *daemonoperatorv1.GetModelProviderCredentialRequest,
) (*daemonoperatorv1.GetModelProviderCredentialResponse, error) {
	if s.modelCredStore == nil || s.modelCredPeer == "" {
		return nil, status.Error(codes.Unavailable, "model provider credentials are not configured on this daemon")
	}
	if peerSPIFFEID(ctx) != s.modelCredPeer {
		return nil, errNotTheTenantOperator
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	tctx := auth.WithTenant(ctx, tenant)
	data, err := modelCredentialFor(tctx, s.modelCredStore, req.GetProviderType(), req.GetCredentialSecret())
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, status.Errorf(codes.NotFound, "the credential secret %q does not exist", req.GetCredentialSecret())
		}
		// The error names the type and the key, never a value.
		return nil, status.Errorf(codes.FailedPrecondition, "the credential secret %q: %v", req.GetCredentialSecret(), err)
	}
	if name := req.GetCaBundleSecret(); name != "" {
		bundle, err := readCABundleSecret(tctx, s.modelCredStore, name)
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		data[cabundle.Key] = bundle
	}
	return &daemonoperatorv1.GetModelProviderCredentialResponse{Data: data}, nil
}

// errEmptyModelCredential reports a tenant secret with no value.
var errEmptyModelCredential = errors.New("the credential is empty")

// The credential fields of a provider in the tenant secret store.
const (
	providerFieldAPIKey        = "api_key"
	providerFieldAWSAccessKey  = "aws_access_key_id"
	providerFieldAWSSigningKey = "aws_secret_access_key"
	providerFieldAWSSession    = "aws_session_token"
)

// modelCredentialFor reads the credential fields of a provider and shapes them
// into the content of the gateway Secret. An API key becomes the key
// Authorization. A Bedrock credential becomes accessKey, secretKey and an
// optional sessionToken. A missing required field gives a NotFound error.
func modelCredentialFor(
	ctx context.Context, store ConnectorSecretResolver, providerType, secretName string,
) (map[string][]byte, error) {
	read := func(field string) ([]byte, error) {
		v, err := store.Resolve(ctx, providerconfig.CredentialFieldKey(secretName, field))
		if err != nil {
			return nil, fmt.Errorf("resolve the field %s: %w", field, err)
		}
		return v, nil
	}
	if providerType != modelProviderTypeBedrock {
		v, err := read(providerFieldAPIKey)
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, errEmptyModelCredential
		}
		return map[string][]byte{ModelCredentialKeyAuthorization: v}, nil
	}
	out := map[string][]byte{}
	for field, key := range map[string]string{
		providerFieldAWSAccessKey: ModelCredentialKeyAccessKey, providerFieldAWSSigningKey: ModelCredentialKeySecretKey,
	} {
		v, err := read(field)
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, fmt.Errorf("a bedrock credential needs the field %q", field)
		}
		out[key] = v
	}
	if v, err := read(providerFieldAWSSession); err == nil && len(v) > 0 {
		out[ModelCredentialKeySessionToken] = v
	}
	return out, nil
}
