// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — plugin_admin.go
//
// PluginsAdminServer implements gibson.admin.v1.PluginsAdminService — the
// dashboard's tenant-admin surface for plugin install management. Pairs with
// secrets_admin.go (secrets), grants_admin.go (capability grants), and
// tenant_admin.go (broker config).
//
// A plugin declares itself in code and checks in with a bootstrap token
// (ADR-0097). A tenant admin grants its secrets through GrantsService. This
// server lists the installs and edits or revokes a secret grant.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1.
package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentevents"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// PluginRegistryReader is the narrow read-side contract PluginsAdminServer
// uses against the daemon's plugin install registry (Spec 2). It is a
// subset of internal/component.ComponentInstallRegistry to avoid pulling the full
// dispatch surface into this package.
type PluginRegistryReader interface {
	// ListAll returns all installs (across all plugin names) for tenant. The
	// production wiring filters out installs whose Redis status key has
	// expired.
	ListAll(ctx context.Context, tenant auth.TenantID) ([]ComponentInstallInfo, error)

	// Get returns one install by ID. Returns ErrInstallNotFound when
	// missing.
	Get(ctx context.Context, tenant auth.TenantID, installID string) (*ComponentInstallInfo, error)
}

// ErrInstallNotFound is returned by PluginRegistryReader.Get when the
// requested install does not exist.
var ErrInstallNotFound = errors.New("plugin install not found")

// ComponentInstallInfo is the dashboard-shaped view of one plugin install —
// independent from the lower-level component.InstallInfo to keep the admin
// package free of cross-cutting types.
type ComponentInstallInfo struct {
	InstallID       string
	TenantID        string
	Name            string
	Version         string
	DeclaredMethods []string
	HostID          string
	Status          string // "serving" | "unreachable" | "degraded"
	Address         string
	LastHeartbeatAt time.Time
	CreatedAt       time.Time
	// PrincipalRef is the FGA user the plugin registered as
	// (plugin_principal:<id>): the user its can_resolve tuples name and the
	// key it streams WatchComponentEvents under. Empty for an install
	// recorded before gibson#154; the plugin re-registers on restart.
	PrincipalRef string
}

// BootstrapTokenAuditor records the audit row of a secret grant revocation.
// Tests inject a recorder; production wiring delegates to the secrets audit
// pipeline.
type BootstrapTokenAuditor interface {
	// Record writes the event durably and returns its error. A state change
	// calls it before the change and makes the change only when it returns
	// nil.
	Record(ctx context.Context, event secrets.AuditEvent) error
	// Audit writes the event without a wait. A change that failed after its
	// record calls it with Success false.
	Audit(ctx context.Context, event secrets.AuditEvent)
}

// PluginsAdminServer implements tenantv1.PluginAdminServiceServer (ADR-0058).
type PluginsAdminServer struct {
	tenantv1.UnimplementedPluginAdminServiceServer

	registry PluginRegistryReader
	authzr   authz.Authorizer
	auditor  BootstrapTokenAuditor
	events   componentevents.Publisher
	now      func() time.Time
}

// PluginsAdminConfig groups the constructor's required dependencies.
type PluginsAdminConfig struct {
	Registry         PluginRegistryReader
	Authorizer       authz.Authorizer
	BootstrapAuditor BootstrapTokenAuditor
	// Events carries secret_access_revoked and secret_rotated to the running
	// plugin (gibson#154). Required: a revocation nobody hears is the hole
	// sdk#55 closed.
	Events componentevents.Publisher
	Now    func() time.Time
}

// NewPluginsAdminServer constructs a PluginsAdminServer. All fields except Now
// are required.
func NewPluginsAdminServer(cfg PluginsAdminConfig) (*PluginsAdminServer, error) {
	if cfg.Registry == nil {
		return nil, errors.New("plugins admin: Registry is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("plugins admin: Authorizer is required")
	}
	if cfg.BootstrapAuditor == nil {
		return nil, errors.New("plugins admin: BootstrapAuditor is required")
	}
	if cfg.Events == nil {
		return nil, errors.New("plugins admin: Events is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &PluginsAdminServer{
		registry: cfg.Registry,
		authzr:   cfg.Authorizer,
		auditor:  cfg.BootstrapAuditor,
		events:   cfg.Events,
		now:      now,
	}, nil
}

// ---------------------------------------------------------------------------
// PluginsAdminService RPC implementations
// ---------------------------------------------------------------------------

// ListPluginInstalls returns the tenant's plugin installs.
func (s *PluginsAdminServer) ListPluginInstalls(ctx context.Context, req *tenantv1.ListPluginInstallsRequest) (*tenantv1.ListPluginInstallsResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	infos, err := s.registry.ListAll(ctx, tenant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "registry list: %v", err)
	}

	out := make([]*tenantv1.PluginInstallSummary, 0, len(infos))
	for _, info := range infos {
		if req.GetNameFilter() != "" && info.Name != req.GetNameFilter() {
			continue
		}
		summary := pluginInstallToSummary(info)
		if req.GetStatusFilter() != tenantv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNSPECIFIED {
			if summary.GetStatus() != req.GetStatusFilter() {
				continue
			}
		}
		// Best-effort populate bound_secret_refs by querying FGA for
		// can_resolve tuples on the install's plugin_principal.
		summary.BoundSecretRefs = s.bindingsFor(ctx, tenant, info)
		out = append(out, summary)
	}

	return &tenantv1.ListPluginInstallsResponse{
		Installs: out,
		Total:    int32(len(out)),
	}, nil
}

// GetPluginInstall returns one install by ID.
func (s *PluginsAdminServer) GetPluginInstall(ctx context.Context, req *tenantv1.GetPluginInstallRequest) (*tenantv1.GetPluginInstallResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetInstallId() == "" {
		return nil, status.Error(codes.InvalidArgument, "install_id is required")
	}

	info, err := s.registry.Get(ctx, tenant, req.GetInstallId())
	if err != nil {
		if errors.Is(err, ErrInstallNotFound) {
			return nil, status.Errorf(codes.NotFound, "install %q not found", req.GetInstallId())
		}
		return nil, status.Errorf(codes.Internal, "registry get: %v", err)
	}

	summary := pluginInstallToSummary(*info)
	summary.BoundSecretRefs = s.bindingsFor(ctx, tenant, *info)
	return &tenantv1.GetPluginInstallResponse{Install: summary}, nil
}

// EditPluginSecretBinding rebinds a binding to a different existing secret.
func (s *PluginsAdminServer) EditPluginSecretBinding(ctx context.Context, req *tenantv1.EditPluginSecretBindingRequest) (*tenantv1.EditPluginSecretBindingResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetInstallId() == "" || req.GetDeclaredName() == "" || req.GetNewExistingRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "install_id, declared_name, new_existing_ref are required")
	}

	principal, err := s.installPrincipal(ctx, tenant, req.GetInstallId())
	if err != nil {
		return nil, err
	}

	// Atomic rebind: delete old tuple, write new tuple in a single FGA
	// batch where supported. For our v1 we issue Delete first then Write —
	// a partial failure leaves the binding revoked, which is fail-safe
	// (the plugin loses access rather than gaining unintended access).
	oldTuple := authz.Tuple{
		User:     principal,
		Relation: "can_resolve",
		Object:   authz.SecretObject(tenant.String(), req.GetDeclaredName()),
	}
	newTuple := authz.Tuple{
		User:     principal,
		Relation: "can_resolve",
		Object:   authz.SecretObject(tenant.String(), req.GetNewExistingRef()),
	}
	if err := s.authzr.Delete(ctx, []authz.Tuple{oldTuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "delete old tuple: %v", err)
	}
	if err := s.authzr.Write(ctx, []authz.Tuple{newTuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "write new tuple: %v", err)
	}
	// The declared name now resolves to another value: the plugin drops its
	// cached copy on secret_rotated.
	if err := s.events.Publish(ctx, tenant.String(), principal, componentevents.Event{
		Type: componentevents.TypeSecretRotated, SecretName: req.GetDeclaredName(), OccurredAt: s.now().UTC(),
	}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "binding moved but the plugin was not told; retry: %v", err)
	}
	return &tenantv1.EditPluginSecretBindingResponse{}, nil
}

// RevokePluginSecretBinding removes a single binding and emits a
// secret_access_revoked audit event.
func (s *PluginsAdminServer) RevokePluginSecretBinding(ctx context.Context, req *tenantv1.RevokePluginSecretBindingRequest) (*tenantv1.RevokePluginSecretBindingResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetInstallId() == "" || req.GetDeclaredName() == "" {
		return nil, status.Error(codes.InvalidArgument, "install_id and declared_name are required")
	}

	principal, err := s.installPrincipal(ctx, tenant, req.GetInstallId())
	if err != nil {
		return nil, err
	}
	tuple := authz.Tuple{
		User:     principal,
		Relation: "can_resolve",
		Object:   authz.SecretObject(tenant.String(), req.GetDeclaredName()),
	}
	identity, _ := auth.IdentityFromContext(ctx)
	event := secrets.AuditEvent{
		ActorID:       identity.Subject,
		ActorTenantID: tenant.String(),
		Action:        "secret_access_revoked",
		Effect:        secrets.EffectAllow,
		ResourceType:  "plugin_install",
		ResourceURI:   fmt.Sprintf("plugin_install:tenant-%s:%s:%s", tenant, req.GetInstallId(), req.GetDeclaredName()),
		Decision:      "allow",
		Success:       true,
		OccurredAt:    s.now().UTC(),
	}
	// The audit record is durable before the binding changes. With no record
	// the binding stays (gibson#676).
	if err := s.auditor.Record(ctx, event); err != nil {
		return nil, status.Error(codes.Unavailable, "the audit record could not be written; the binding is unchanged")
	}
	failed := func() {
		event.Success, event.Effect, event.Decision = false, secrets.EffectDeny, "deny"
		s.auditor.Audit(ctx, event)
	}
	if err := s.authzr.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		failed()
		return nil, status.Errorf(codes.Internal, "delete tuple: %v", err)
	}

	// Tell the running plugin. The tuple is already gone, so a failed publish
	// leaves the plugin denied on its next resolve and holding its cache until
	// the operator retries; Unavailable asks for that retry (gibson#154).
	if err := s.events.Publish(ctx, tenant.String(), principal, componentevents.Event{
		Type: componentevents.TypeSecretAccessRevoked, SecretName: req.GetDeclaredName(),
		Reason: "binding revoked by a tenant admin", OccurredAt: s.now().UTC(),
	}); err != nil {
		failed()
		return nil, status.Errorf(codes.Unavailable, "binding revoked but the plugin was not told; retry: %v", err)
	}

	return &tenantv1.RevokePluginSecretBindingResponse{}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// pluginInstallToSummary maps the dashboard-shaped registry view to the
// proto wire-shape.
func pluginInstallToSummary(i ComponentInstallInfo) *tenantv1.PluginInstallSummary {
	return &tenantv1.PluginInstallSummary{
		InstallId:           i.InstallID,
		Name:                i.Name,
		Version:             i.Version,
		DeclaredMethods:     i.DeclaredMethods,
		HostId:              i.HostID,
		Status:              statusToEnum(i.Status),
		Address:             i.Address,
		LastHeartbeatAtUnix: i.LastHeartbeatAt.Unix(),
		CreatedAtUnix:       i.CreatedAt.Unix(),
	}
}

// statusToEnum maps the registry's lowercase string status to the proto
// enum. Unknown values return UNSPECIFIED.
func statusToEnum(s string) tenantv1.PluginInstallStatus {
	switch s {
	case "serving":
		return tenantv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_SERVING
	case "unreachable":
		return tenantv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNREACHABLE
	case "degraded":
		return tenantv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_DEGRADED
	default:
		return tenantv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNSPECIFIED
	}
}

// bindingsFor walks FGA can_resolve tuples for the install's principal and
// returns the (decoded) ref names. Best-effort.
func (s *PluginsAdminServer) bindingsFor(ctx context.Context, tenant auth.TenantID, info ComponentInstallInfo) []string {
	if info.PrincipalRef == "" {
		return nil
	}
	objects, err := s.authzr.ListObjects(ctx, info.PrincipalRef, "can_resolve", "secret")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(objects))
	for _, obj := range objects {
		// obj is "secret:tenant-<id>/<ref>"; strip the prefix.
		if ref := uriToRef(obj); ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

// installPrincipal returns the FGA user the install's plugin registered as.
// It is the one string three things agree on: the can_resolve tuples a
// tenant admin granted, the WatchComponentEvents subscription the
// running plugin holds, and the identity ext-authz authorizes its calls as.
// An install with no recorded principal predates gibson#154 and cannot be
// addressed; the plugin re-registers on restart and the row is filled then.
func (s *PluginsAdminServer) installPrincipal(ctx context.Context, tenant auth.TenantID, installID string) (string, error) {
	info, err := s.registry.Get(ctx, tenant, installID)
	if err != nil {
		if errors.Is(err, ErrInstallNotFound) {
			return "", status.Errorf(codes.NotFound, "install %q not found", installID)
		}
		return "", status.Errorf(codes.Internal, "registry get: %v", err)
	}
	if info.PrincipalRef == "" {
		return "", status.Errorf(codes.FailedPrecondition,
			"install %q has no recorded principal; restart the plugin so it re-registers, then retry", installID)
	}
	return info.PrincipalRef, nil
}
