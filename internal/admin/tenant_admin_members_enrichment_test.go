package admin

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	adminv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/admin/v1"

	"github.com/zeroroot-ai/gibson/internal/idp"
)

// TestListMembers_EnrichmentFailuresAreLogged locks gibson#561: identity
// enrichment is best-effort, but a failed or empty profile lookup must be
// observable in the logs (with the affected user id) and must distinguish a
// failed lookup from a directory that returned an empty profile — otherwise
// blank names on the Members page are undiagnosable.
func TestListMembers_EnrichmentFailuresAreLogged(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:gone-id", "user:blank-id"},
		admins:  map[string]bool{},
	}
	idpC := &membersIdPClient{
		// gone-id → idp.ErrNotFound → reason "profile_not_found".
		failFor: map[string]bool{"gone-id": true},
		// blank-id → lookup succeeds but name/email are empty → "empty_profile".
		profiles: map[string]*idp.UserProfile{
			"blank-id": {AccountID: "blank-id"},
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         &fakeTenantConfigReader{},
		Writer:         &fakeTenantConfigWriter{},
		ProbeFactory:   &fakeProbeFactory{},
		Auditor:        &fakeAuditor{},
		Reloader:       &fakeReloader{},
		SecretsService: &fakeSecretsLister{},
		Authorizer:     az,
		IdPAdminClient: idpC,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.ListMembers(ctx, &adminv1.ListMembersRequest{}); err != nil {
		t.Fatalf("ListMembers: %v", err)
	}

	logs := buf.String()
	for _, want := range []string{"profile_not_found", "empty_profile", "gone-id", "blank-id"} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected log output to contain %q; got:\n%s", want, logs)
		}
	}
}
