// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// Secret access is assigned by a tenant admin, never declared by the
// component (ADR-0097, gibson#554). This RPC is that assignment: a tenant
// admin grants a plugin principal can_resolve on named secrets of the
// tenant. A grant is removed with PluginAdminService.RevokePluginSecretBinding,
// which also tells the running plugin. The deploy wizard of the dashboard
// calls WriteSecretGrants before it hands out the bootstrap token, so a
// component never starts before its access exists (dashboard#174).

// relationCanResolve is the FGA relation a secret grant writes. model.fga
// admits it only for a plugin_principal.
const relationCanResolve = "can_resolve"

// secretGrantPrincipalPrefix is the only subject type that can hold
// can_resolve. An agent or a tool reaches a secret through a plugin
// (spec non-plugin-secret-isolation).
const secretGrantPrincipalPrefix = "plugin_principal:"

// SecretNameLister lists the names of the secrets that a tenant owns. The
// production adapter wraps secrets.Service.List.
type SecretNameLister interface {
	List(ctx context.Context, tenant auth.TenantID) ([]string, error)
}

// errSecretUnavailable is the one answer for a secret name that the caller's
// tenant does not own. It does not say whether another tenant owns it.
var errSecretUnavailable = status.Error(codes.NotFound, "secret not found in this tenant")

// WriteSecretGrants grants the target plugin principal can_resolve on each
// named secret of the caller's tenant.
func (s *GrantsAdminServer) WriteSecretGrants(ctx context.Context, req *tenantv1.WriteSecretGrantsRequest) (*tenantv1.WriteSecretGrantsResponse, error) {
	target, tenant, err := s.secretGrantTarget(ctx, req.GetTargetPrincipalId())
	if err != nil {
		return nil, err
	}
	names := dedupe(req.GetSecretNames())
	if len(names) == 0 {
		return &tenantv1.WriteSecretGrantsResponse{}, nil
	}
	if err := s.requireOwnedSecrets(ctx, tenant, names); err != nil {
		return nil, err
	}

	tuples := secretGrantTuples(target, tenant, names)
	present, err := s.presentTuples(ctx, tuples)
	if err != nil {
		return nil, err
	}
	var toWrite []authz.Tuple
	for i, t := range tuples {
		if !present[i] {
			toWrite = append(toWrite, t)
		}
	}

	actor, ok := grantActor(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	if err := s.recordGrantAudit(ctx, actor, tenant.String(), target, "secret_grant_added", toWrite); err != nil {
		return nil, status.Error(codes.Unavailable, "the audit record of the grant change could not be written; nothing changed")
	}
	if len(toWrite) > 0 {
		if err := s.authorizer.Write(ctx, toWrite); err != nil {
			s.recordGrantFailure(ctx, actor, tenant.String(), target, "secret_grant_added", toWrite)
			s.logger.ErrorContext(ctx, "grants admin: write secret grants failed",
				slog.String("target", target), slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "the secret grants could not be written")
		}
	}
	return &tenantv1.WriteSecretGrantsResponse{
		Written:        int32(len(toWrite)),
		AlreadyPresent: int32(len(tuples) - len(toWrite)),
	}, nil
}

// secretGrantTarget checks that the secret grant surface is on, that the
// target is a plugin principal, and that it belongs to the caller's tenant.
func (s *GrantsAdminServer) secretGrantTarget(ctx context.Context, targetID string) (string, auth.TenantID, error) {
	if s.authorizer == nil || s.lookup == nil || s.secretNames == nil {
		return "", auth.TenantID{}, status.Error(codes.Unimplemented, "secret grant surface not enabled")
	}
	if !strings.HasPrefix(targetID, secretGrantPrincipalPrefix) {
		return "", auth.TenantID{}, status.Error(codes.InvalidArgument,
			"only a plugin principal can resolve a secret; an agent or a tool reaches a secret through a plugin")
	}
	target, callerTenant, err := s.validateTargetAndTenant(ctx, targetID)
	if err != nil {
		return "", auth.TenantID{}, err
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.String() != callerTenant {
		return "", auth.TenantID{}, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return target.PrincipalID, tenant, nil
}

// requireOwnedSecrets refuses a name that the caller's tenant does not own.
func (s *GrantsAdminServer) requireOwnedSecrets(ctx context.Context, tenant auth.TenantID, names []string) error {
	owned, err := s.secretNames.List(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "grants admin: list tenant secrets failed", slog.String("error", err.Error()))
		var st interface{ GRPCStatus() *status.Status }
		if errors.As(err, &st) && st.GRPCStatus().Code() == codes.Unavailable {
			return status.Error(codes.Unavailable, "the secrets of the tenant could not be read")
		}
		return status.Error(codes.Internal, "the secrets of the tenant could not be read")
	}
	have := make(map[string]struct{}, len(owned))
	for _, n := range owned {
		have[n] = struct{}{}
	}
	for _, n := range names {
		if _, ok := have[n]; !ok {
			return errSecretUnavailable
		}
	}
	return nil
}

// presentTuples reports, for each tuple, whether FGA already holds it.
func (s *GrantsAdminServer) presentTuples(ctx context.Context, tuples []authz.Tuple) ([]bool, error) {
	checks := make([]authz.CheckRequest, len(tuples))
	for i, t := range tuples {
		checks[i] = authz.CheckRequest{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	present, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		return nil, status.Error(codes.Internal, "the existing secret grants could not be read")
	}
	return present, nil
}

// secretGrantTuples builds one can_resolve tuple for each name, always in
// the caller's tenant.
func secretGrantTuples(target string, tenant auth.TenantID, names []string) []authz.Tuple {
	tuples := make([]authz.Tuple, 0, len(names))
	for _, n := range names {
		tuples = append(tuples, authz.Tuple{
			User:     target,
			Relation: relationCanResolve,
			Object:   authz.SecretObject(tenant.String(), n),
		})
	}
	return tuples
}

// dedupe keeps the first of each name, in order.
func dedupe(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
