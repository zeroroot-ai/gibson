// Package fgalistusers exercises the fgalistusers guard against the
// fixture model in testdata/fga/model.fga.
//
// The NEGATIVE cases are the ones that prove this is a genuine
// model-aware guard rather than a denylist of known-bad relation names:
// component.can_execute (difference over intersection over
// tuple-to-userset) and team.member (a userset that recurses into
// team#admin) must both resolve TRUE and stay silent.
package fgalistusers

import (
	"context"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

type service struct {
	authorizer authz.Authorizer
}

// R1 — `secret.can_resolve` is declared [plugin_principal] only, so a
// user-filtered ListUsers returns an empty result with a nil error on
// every invocation, forever.
func (s *service) pluginsBoundTo(ctx context.Context, object string) ([]string, error) {
	users, err := s.authorizer.ListUsers(ctx, "secret", object, "can_resolve") // want `subject-type mismatch`
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range users {
		out = append(out, strings.TrimPrefix(u, "user:"))
	}
	return out, nil
}

// R2 — the relation is a request-derived variable so R1 cannot see it,
// but the result is filtered on a "team:" prefix a user-filtered
// ListUsers can never produce. The whole reconcile arm is unreachable.
func (s *service) setComponentAccess(ctx context.Context, componentRef, relation string) error {
	existing, err := s.authorizer.ListUsers(ctx, "component", componentRef, relation)
	if err != nil {
		return err
	}
	for _, userRef := range existing {
		if !strings.HasPrefix(userRef, "team:") { // want `result-shape contradiction`
			continue
		}
		_ = userRef
	}
	return nil
}

// R3 — the object type is not constant-foldable, so the call cannot be
// verified. The remedy is to hoist it or name the subject type.
func (s *service) revokePrincipal(ctx context.Context, fgaType, principalID string) error {
	_, err := s.authorizer.ListUsers(ctx, fgaType, principalID, "owner") // want `unresolved arguments`
	return err
}

// R2 reached through INDEXING rather than a range value. Same
// contradiction, different access shape — this fixture pins the
// index arm, which was unreachable in an earlier revision.
func (s *service) setComponentAccessIndexed(ctx context.Context, componentRef, relation string) error {
	existing, err := s.authorizer.ListUsers(ctx, "component", componentRef, relation)
	if err != nil {
		return err
	}
	for i := range existing {
		if strings.HasPrefix(existing[i], "plugin_principal:") { // want `result-shape contradiction`
			_ = i
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// NEGATIVES — must stay silent
// ---------------------------------------------------------------------------

// tenant.member is a union whose direct branch includes [user].
func (s *service) listMembers(ctx context.Context, tenantRef string) ([]string, error) {
	return s.authorizer.ListUsers(ctx, "tenant", tenantRef, "member")
}

// team.member is [user, team#admin] — the userset leg must recurse into
// team.admin rather than being treated as a non-user type.
func (s *service) listTeamMembers(ctx context.Context, teamRef string) ([]string, error) {
	return s.authorizer.ListUsers(ctx, "team", teamRef, "member")
}

// component.can_execute is `(direct_execute and in_tenant_catalog) but
// not any_execute_deny` — the model's most convoluted definition, and
// it resolves TRUE.
func (s *service) listExecutors(ctx context.Context, componentRef string) ([]string, error) {
	return s.authorizer.ListUsers(ctx, "component", componentRef, "can_execute")
}

// A "user:" prefix filter is the one prefix ListUsers CAN produce, so
// it is not a contradiction.
func (s *service) trimUserPrefix(ctx context.Context, tenantRef string) ([]string, error) {
	refs, err := s.authorizer.ListUsers(ctx, "tenant", tenantRef, "member")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range refs {
		out = append(out, strings.TrimPrefix(r, "user:"))
	}
	return out, nil
}

// ListUsersOfType names the subject type explicitly and is out of scope.
func (s *service) pluginsBoundToFixed(ctx context.Context, object string) ([]string, error) {
	return s.authorizer.ListUsersOfType(ctx, "secret", object, "can_resolve", "plugin_principal")
}
