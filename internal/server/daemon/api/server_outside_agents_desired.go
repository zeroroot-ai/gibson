// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_outside_agents_desired.go
//
// DaemonOperatorService.GetTenantOutsideAgents and GetOutsideAgentCredential
// (gibson#1403). The daemon holds the outside agent records of a tenant, and it
// cannot write cluster resources (ADR-0023). The tenant operator pulls the
// records of each tenant and renders the backend, the route and the credential
// Secret into the namespace of the Agent gateway. It follows the model provider
// RPCs. Both handlers serve only the direct-dial SPIFFE identity of the tenant
// operator.
package api

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// OutsideAgentCredentialKey is the key of the Secret that agentgateway reads for
// the auth policy of a backend. The gateway sends the value as the header
// Authorization with the prefix "Bearer ". It strips a "Bearer " prefix that
// the value already holds (CRD agentgatewaybackends, policies.auth.secretRef).
const OutsideAgentCredentialKey = "Authorization"

// WithOutsideAgentOperatorSource wires the two outside agent RPCs of the tenant
// operator: the outside agent store. The credential read uses the tenant secret
// store and the peer of WithModelProviderCredentialSource. Unwired, the RPCs
// answer Unavailable.
func (s *DaemonServer) WithOutsideAgentOperatorSource(store outsideagentstore.Store) *DaemonServer {
	s.outsideAgents = store
	return s
}

// outsideAgentOperatorReady checks the wiring and the peer.
func (s *DaemonServer) outsideAgentOperatorReady(ctx context.Context) error {
	if s.outsideAgents == nil || s.modelCredStore == nil || s.modelCredPeer == "" {
		return status.Error(codes.Unavailable, "outside agents are not configured on this daemon")
	}
	if peerSPIFFEID(ctx) != s.modelCredPeer {
		return status.Error(codes.PermissionDenied, "the outside agent RPCs are served to the tenant operator only")
	}
	return nil
}

// GetTenantOutsideAgents returns the outside agents of one tenant.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer check. The operator reads the
// outside agents of each tenant by design.
func (s *DaemonServer) GetTenantOutsideAgents(
	ctx context.Context, req *daemonoperatorv1.GetTenantOutsideAgentsRequest,
) (*daemonoperatorv1.GetTenantOutsideAgentsResponse, error) {
	if err := s.outsideAgentOperatorReady(ctx); err != nil {
		return nil, err
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	entries, err := s.outsideAgents.List(ctx, tenant.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list the outside agents: %v", err)
	}
	out := &daemonoperatorv1.GetTenantOutsideAgentsResponse{}
	for _, e := range entries {
		out.Agents = append(out.Agents, &daemonoperatorv1.DesiredOutsideAgent{
			Name: e.Name, A2AUrl: e.A2AURL, CredentialSecret: e.CredentialSecret, CaBundleSecret: e.CABundleSecret,
		})
	}
	return out, nil
}

// GetOutsideAgentCredential returns the content of the credential Secret of one
// outside agent. It reads the tenant secrets that the record of the agent names:
// the credential under the key Authorization and the CA bundle under the key
// ca.crt. The caller cannot name another tenant secret. An agent with neither
// secret, or a tenant secret that does not exist, gives NotFound.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: the TLS peer of the
// connection must be the tenant operator SVID, checked here (gibson#1403).
func (s *DaemonServer) GetOutsideAgentCredential(
	ctx context.Context, req *daemonoperatorv1.GetOutsideAgentCredentialRequest,
) (*daemonoperatorv1.GetOutsideAgentCredentialResponse, error) {
	if err := s.outsideAgentOperatorReady(ctx); err != nil {
		return nil, err
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	entry, err := s.outsideAgents.Get(ctx, tenant.String(), req.GetName())
	switch {
	case errors.Is(err, outsideagentstore.ErrNotFound):
		return nil, status.Errorf(codes.NotFound, "the outside agent %q does not exist", req.GetName())
	case err != nil:
		return nil, status.Errorf(codes.Internal, "read the outside agent: %v", err)
	}
	if entry.CredentialSecret == "" && entry.CABundleSecret == "" {
		return nil, status.Errorf(codes.NotFound, "the outside agent %q has no credential secret and no CA bundle",
			req.GetName())
	}
	tctx := auth.WithTenant(ctx, tenant)
	data := map[string][]byte{}
	if entry.CredentialSecret != "" {
		// The user saved the secret with SetSecret, so the read uses the same
		// stored-name rule.
		stored := secrets.StoredName(secretsv1.SecretCategory_SECRET_CATEGORY_CRED, entry.CredentialSecret)
		value, err := s.modelCredStore.Resolve(tctx, stored)
		if err != nil {
			slog.WarnContext(ctx, "the credential secret of an outside agent cannot be read",
				"secret", entry.CredentialSecret, "stored_name", stored, "error", err)
			// The error names the secret and never a value.
			return nil, status.Errorf(codes.NotFound, "the credential secret %q cannot be read", entry.CredentialSecret)
		}
		if len(value) == 0 {
			return nil, status.Errorf(codes.NotFound, "the credential secret %q is empty", entry.CredentialSecret)
		}
		data[OutsideAgentCredentialKey] = value
	}
	if entry.CABundleSecret != "" {
		bundle, err := readCABundleSecret(tctx, s.modelCredStore, entry.CABundleSecret)
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		data[cabundle.Key] = bundle
	}
	return &daemonoperatorv1.GetOutsideAgentCredentialResponse{Data: data}, nil
}
