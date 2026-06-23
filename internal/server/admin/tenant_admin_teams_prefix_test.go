package admin

import (
	"testing"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestCreateTeam_NormalizesTenantPrefix locks the daemon-side defense against
// the double-prefix bug class (dashboard#603 / gibson#560). Regardless of
// whether the caller sends a bare slug ("zero-root") or an already-prefixed
// id ("tenant:zero-root"), the daemon must write a single canonical
// (tenant:zero-root, parent, team:<id>) tuple — never "tenant:tenant:zero-root".
func TestCreateTeam_NormalizesTenantPrefix(t *testing.T) {
	cases := []struct {
		name     string
		tenantID string
	}{
		{"bare slug", "zero-root"},
		{"already prefixed (the original bug)", "tenant:zero-root"},
	}

	const wantUser = "tenant:zero-root"
	const wantObject = "team:test"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := &stubAuthorizer{present: map[string]bool{}}
			srv, _, _, _, _, _, _ := newTenantTestServer(t)
			srv.authorizer = sa

			ctx := adminCtx(t, "zero-root")
			_, err := srv.CreateTeam(ctx, &tenantv1.CreateTeamRequest{
				TenantId: tc.tenantID,
				TeamId:   "test",
			})
			if err != nil {
				t.Fatalf("CreateTeam: unexpected error: %v", err)
			}

			if len(sa.wrote) != 1 {
				t.Fatalf("expected exactly 1 written tuple, got %d: %+v", len(sa.wrote), sa.wrote)
			}
			got := sa.wrote[0]
			if got.User != wantUser {
				t.Errorf("tuple user = %q, want %q (no double prefix)", got.User, wantUser)
			}
			if got.Relation != "parent" {
				t.Errorf("tuple relation = %q, want %q", got.Relation, "parent")
			}
			if got.Object != wantObject {
				t.Errorf("tuple object = %q, want %q", got.Object, wantObject)
			}
		})
	}
}
