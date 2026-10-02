// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// metadataDeclaredSecrets is the RegisterComponent metadata key carrying the
// comma-joined refs of the secrets a plugin declared in its manifest. The SDK
// (plugin.Serve) populates it; a ref like "cred:github_token" has a colon but
// never a comma, so comma is a safe separator.
const metadataDeclaredSecrets = "plugin:secrets"

// systemTenantRef is the FGA user the startup seeder writes platform_enabled
// from (reconciler.SeedComponentCatalogGate). relationPlatformEnabled is that
// tuple's relation on a component object (model.fga `type component`).
const (
	systemTenantRef         = "system_tenant:_system"
	relationPlatformEnabled = "platform_enabled"
)

// bindDeclaredSecrets grants a registering CATALOG plugin can_resolve on each
// secret it declared (ADR-0066). It binds the plugin's own principal, only on
// secrets the plugin declared, only in the caller's tenant.
//
// The gate is the signed platform catalog (gibson#554, ADR-0097): the
// component object must carry platform_enabled from the system tenant, which
// the startup seeder writes only for an embedded catalog entry whose image
// passed release-signature verification (reconciler.SeedComponentCatalogGate).
// A check-in must never assign its own trust: a component a developer authored
// has no reviewed declaration behind it, so for every (kind, name) outside the
// catalog the declared list is advisory and this writes nothing. Such a
// component reaches a secret only through a tenant admin's grant.
//
// The gate keys on the name the check-in registers under, not on the caller's
// principal, because no record yet links a plugin principal to the catalog
// entry it was deployed for (gibson#576). A plugin principal is minted only by
// a tenant admin (TenantAdminService.CreateAgentIdentity), so the residual
// reach is an admin-created identity registering under a catalog plugin's name
// inside its own tenant, on that tenant's own secrets.
//
// Best-effort + idempotent: FGA Write is idempotent, and a plugin re-registers
// on every restart, so a transient write failure self-heals on the next start
// (and surfaces meanwhile as a clear can_resolve deny plus this WARN). It never
// fails registration.
func (s *ComponentServiceServer) bindDeclaredSecrets(ctx context.Context, tenant, kind, name string, md map[string]string) {
	// Reading a nil map is safe in Go, so no md-nil guard is needed; an absent
	// or empty key ends the work here.
	raw := strings.TrimSpace(md[metadataDeclaredSecrets])
	if raw == "" {
		return
	}

	// Positive gate: no authorizer, a check error, or a component the platform
	// does not offer, writes nothing. An undecidable gate is a closed gate.
	if s.authorizer == nil {
		s.logger.WarnContext(ctx, "declared-secret binding skipped: no authorizer wired, the catalog gate cannot be asked")
		return
	}
	object := authz.ComponentObject(kind, name)
	offered, err := s.authorizer.Check(ctx, systemTenantRef, relationPlatformEnabled, object)
	if err != nil {
		s.logger.WarnContext(ctx, "declared-secret binding skipped: catalog gate check failed",
			slog.String("fga_object", object),
			slog.String("error", err.Error()))
		return
	}
	if !offered {
		s.logger.InfoContext(ctx, "declared secrets are advisory: component is not in the platform catalog, no can_resolve written",
			slog.String("kind", kind),
			slog.String("name", name),
			slog.String("tenant", tenant))
		return
	}

	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		s.logger.WarnContext(ctx, "declared-secret binding skipped: no caller identity in context")
		return
	}
	fgaUser := componentFGAUser(identity.Subject)
	// model.fga admits can_resolve ONLY for a plugin_principal. Refuse to write a
	// tuple FGA would reject rather than silently no-op.
	if !strings.HasPrefix(fgaUser, "plugin_principal:") {
		s.logger.WarnContext(ctx, "declared-secret binding skipped: caller is not a plugin_principal",
			slog.String("fga_user", fgaUser))
		return
	}

	seen := make(map[string]struct{})
	tuples := make([]authz.Tuple, 0)
	for _, ref := range strings.Split(raw, ",") {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		tuples = append(tuples, authz.Tuple{
			User:     fgaUser,
			Relation: relationCanResolve,
			Object:   authz.SecretObject(tenant, ref),
		})
	}
	if len(tuples) == 0 {
		return
	}

	if err := s.authorizer.Write(ctx, tuples); err != nil {
		s.logger.WarnContext(ctx, "failed to bind plugin can_resolve on declared secrets",
			slog.String("fga_user", fgaUser),
			slog.Int("count", len(tuples)),
			slog.String("error", err.Error()))
		return
	}
	s.logger.InfoContext(ctx, "bound plugin can_resolve on declared secrets",
		slog.String("fga_user", fgaUser),
		slog.Int("count", len(tuples)))
}
