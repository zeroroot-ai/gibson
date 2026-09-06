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

// bindDeclaredSecrets grants the registering plugin can_resolve on each secret
// it declared in its manifest (ADR-0066). This is the SVID pod-plugin
// replacement for the old RegisterPlugin binding, which bound can_resolve from a
// binding list a human tenant-admin submitted at install; RegisterComponent
// carries no such list, so without this a plugin cannot read its own declared
// secret (the GetCredential path denies with no can_resolve tuple).
//
// It binds the plugin's OWN principal (from the caller's signed identity), only
// on secrets the plugin declared, only in the caller's tenant. Safe for
// first-party SVID plugins: they are operator-deployed via GitOps from the
// operator's own integrations fork, so the manifest — and its declared secrets —
// is operator-approved; and can_resolve only reads a value the operator
// separately provisions.
//
// Best-effort + idempotent: FGA Write is idempotent, and a plugin re-registers
// on every restart, so a transient write failure self-heals on the next start
// (and surfaces meanwhile as a clear can_resolve deny plus this WARN). It never
// fails registration.
func (s *ComponentServiceServer) bindDeclaredSecrets(ctx context.Context, tenant string, md map[string]string) {
	// Reading a nil map is safe in Go, so no md-nil guard is needed; an absent
	// or empty key ends the work here.
	raw := strings.TrimSpace(md[metadataDeclaredSecrets])
	if raw == "" {
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

	// FGA write only when the authorizer is wired — a nil authorizer is
	// noop/disabled mode (WithAuthorizer). Positive guard, mirroring the
	// established component-ownership write in service.go, so a plugin with an
	// unwired authorizer simply gets no binding and later fails closed with a
	// clear can_resolve deny rather than this path silently returning early.
	if s.authorizer != nil {
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
}
