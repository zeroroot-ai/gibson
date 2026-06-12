package admin

// Connector-registration tests (gibson#684): a connector manifest registers
// through the same RegisterPlugin saga as a plain plugin, then additionally
// launches the hosted MCP-bridge sandbox; the daemon consumes the bootstrap
// token (the sandbox redeems it), so the response carries no token.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeConnectorLauncher records Launch calls.
type fakeConnectorLauncher struct {
	mu         sync.Mutex
	launched   []fakeLaunch
	launchErr  error
	terminated []string
}

type fakeLaunch struct {
	tenant string
	yaml   string
	token  string
}

func (f *fakeConnectorLauncher) Launch(_ context.Context, tenant auth.TenantID, connectorYAML []byte, bootstrapToken string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.launched = append(f.launched, fakeLaunch{
		tenant: tenant.String(),
		yaml:   string(connectorYAML),
		token:  bootstrapToken,
	})
	if f.launchErr != nil {
		return "", f.launchErr
	}
	return "ns/sbx/uid", nil
}

func (f *fakeConnectorLauncher) Terminate(_ context.Context, sandboxID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.terminated = append(f.terminated, sandboxID)
	return nil
}

// newConnectorTestServer builds a PluginsAdminServer with a connector-shaped
// validator result and the given launcher (nil allowed).
func newConnectorTestServer(t *testing.T, launcher ConnectorLauncher) (*PluginsAdminServer, *fakeZitadel, *fakeAuthorizer) {
	t.Helper()
	val := &fakeManifestValidator{manifest: ValidatedManifest{
		Name:            "github",
		Version:         "0.1.0",
		DeclaredSecrets: []string{"cred:github_token"},
		RuntimeMode:     "setec",
		SetecRequired:   true,
		IsConnector:     true,
	}}
	zit := &fakeZitadel{}
	az := &fakeAuthorizer{}

	srv, err := NewPluginsAdminServer(PluginsAdminConfig{
		Registry:          &fakeComponentInstallRegistry{installs: map[string]ComponentInstallInfo{}},
		ManifestValidator: val,
		ZitadelClient:     zit,
		SecretWriter:      &fakeSecretWriter{},
		Authorizer:        az,
		BootstrapAuditor:  &fakeAuditor{},
		BootstrapTokenTTL: time.Hour,
		ConnectorLauncher: launcher,
	})
	if err != nil {
		t.Fatalf("NewPluginsAdminServer: %v", err)
	}
	return srv, zit, az
}

func connectorRegisterReq() *tenantv1.RegisterPluginRequest {
	return &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("apiVersion: connector.gibson.zeroroot.ai/v1\nkind: Connector"),
		Bindings: []*tenantv1.PluginSecretBinding{
			{DeclaredName: "cred:github_token", Mode: "existing", ExistingRef: "cred:github_token"},
		},
	}
}

func TestRegisterPlugin_Connector_LaunchesSandboxAndConsumesToken(t *testing.T) {
	launcher := &fakeConnectorLauncher{}
	srv, zit, _ := newConnectorTestServer(t, launcher)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, connectorRegisterReq())
	if err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	// The sandbox was launched with the original manifest bytes + the token.
	if len(launcher.launched) != 1 {
		t.Fatalf("expected 1 launch, got %d", len(launcher.launched))
	}
	l := launcher.launched[0]
	if l.tenant != "acme" {
		t.Errorf("launch tenant = %q, want acme", l.tenant)
	}
	if l.yaml != string(connectorRegisterReq().ManifestYaml) {
		t.Errorf("launch got different manifest bytes")
	}
	if l.token == "" {
		t.Error("launch must receive the bootstrap token")
	}
	if len(zit.created) != 1 {
		t.Errorf("expected 1 principal, got %d", len(zit.created))
	}

	// The daemon consumed the single-use token: the response must not carry it.
	if resp.GetBootstrapToken() != "" {
		t.Error("connector response must not return the bootstrap token (sandbox redeems it)")
	}
	if resp.GetBootstrapTokenExpiresAtUnix() != 0 {
		t.Error("connector response must not carry token expiry")
	}
	if resp.GetInstallId() == "" || resp.GetPluginPrincipalId() == "" {
		t.Errorf("install/principal ids missing: %+v", resp)
	}
}

func TestRegisterPlugin_Connector_LaunchFailureRollsBack(t *testing.T) {
	launcher := &fakeConnectorLauncher{launchErr: errors.New("no sandbox capacity")}
	srv, zit, az := newConnectorTestServer(t, launcher)
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RegisterPlugin(ctx, connectorRegisterReq())
	if err == nil {
		t.Fatal("expected error on launch failure")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("want Internal, got %v", err)
	}

	// Rollback: the principal created in step 4 must be deleted, and the FGA
	// tuples written in step 5 must be removed.
	if len(zit.created) != 1 || len(zit.deleted) != 1 {
		t.Errorf("expected created+deleted principal, got created=%d deleted=%d",
			len(zit.created), len(zit.deleted))
	}
	if len(az.writes) != 1 || len(az.deletes) != 1 {
		t.Errorf("expected FGA write then delete, got writes=%d deletes=%d",
			len(az.writes), len(az.deletes))
	}
}

func TestRegisterPlugin_Connector_NoLauncher_FailedPrecondition(t *testing.T) {
	srv, zit, az := newConnectorTestServer(t, nil)
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RegisterPlugin(ctx, connectorRegisterReq())
	if err == nil {
		t.Fatal("expected error when no launcher is wired")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("want FailedPrecondition, got %v", err)
	}
	// Fail-fast: no side effects before the precondition check.
	if len(zit.created) != 0 || len(az.writes) != 0 {
		t.Errorf("expected zero side effects, got principals=%d fga=%d",
			len(zit.created), len(az.writes))
	}
}

func TestRegisterPlugin_PlainPlugin_NeverLaunches(t *testing.T) {
	launcher := &fakeConnectorLauncher{}
	val := &fakeManifestValidator{manifest: ValidatedManifest{
		Name:    "plain",
		Version: "1.0.0",
		// IsConnector false
	}}
	srv, err := NewPluginsAdminServer(PluginsAdminConfig{
		Registry:          &fakeComponentInstallRegistry{installs: map[string]ComponentInstallInfo{}},
		ManifestValidator: val,
		ZitadelClient:     &fakeZitadel{},
		SecretWriter:      &fakeSecretWriter{},
		Authorizer:        &fakeAuthorizer{},
		BootstrapAuditor:  &fakeAuditor{},
		ConnectorLauncher: launcher,
	})
	if err != nil {
		t.Fatalf("NewPluginsAdminServer: %v", err)
	}

	resp, err := srv.RegisterPlugin(ctxWithTenant(t, "acme"), &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("apiVersion: plugin.gibson.zeroroot.ai/v1"),
	})
	if err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if len(launcher.launched) != 0 {
		t.Errorf("plain plugin registration must not launch a sandbox")
	}
	if resp.GetBootstrapToken() == "" {
		t.Error("plain plugin response must still return the bootstrap token")
	}
}

// gibson#685 — remote connector registration: the daemon must NOT launch a
// hosted sandbox and MUST return the one-time bootstrap token so the
// customer's own MCP-bridge can redeem it to enroll.
func TestRegisterPlugin_Connector_Remote_ReturnsTokenNoLaunch(t *testing.T) {
	launcher := &fakeConnectorLauncher{}
	srv, zit, _ := newConnectorTestServer(t, launcher)
	ctx := ctxWithTenant(t, "acme")

	req := connectorRegisterReq()
	req.Remote = true

	resp, err := srv.RegisterPlugin(ctx, req)
	if err != nil {
		t.Fatalf("RegisterPlugin(remote): %v", err)
	}

	// No hosted sandbox launch on the remote path.
	if len(launcher.launched) != 0 {
		t.Fatalf("remote connector must not launch a sandbox, got %d launches", len(launcher.launched))
	}
	// A principal was still provisioned.
	if len(zit.created) != 1 {
		t.Errorf("expected 1 principal, got %d", len(zit.created))
	}
	// The token IS returned so the customer-run bridge can redeem it.
	if resp.GetBootstrapToken() == "" {
		t.Error("remote connector response must return the bootstrap token")
	}
	if resp.GetBootstrapTokenExpiresAtUnix() == 0 {
		t.Error("remote connector response must carry token expiry")
	}
	if resp.GetInstallId() == "" || resp.GetPluginPrincipalId() == "" {
		t.Errorf("install/principal ids missing: %+v", resp)
	}
}

// A remote connector registers even on a daemon with no hosted launcher
// configured (the whole point: the customer runs the bridge).
func TestRegisterPlugin_Connector_Remote_NoLauncherConfigured(t *testing.T) {
	srv, _, _ := newConnectorTestServer(t, nil) // launcher == nil
	ctx := ctxWithTenant(t, "acme")

	req := connectorRegisterReq()
	req.Remote = true

	resp, err := srv.RegisterPlugin(ctx, req)
	if err != nil {
		t.Fatalf("remote connector must register without a hosted launcher: %v", err)
	}
	if resp.GetBootstrapToken() == "" {
		t.Error("remote connector must return the bootstrap token")
	}
}

// remote=true is rejected for a plain (non-connector) plugin manifest.
func TestRegisterPlugin_Remote_RejectedForPlainPlugin(t *testing.T) {
	srv, _, _ := newConnectorTestServer(t, &fakeConnectorLauncher{})
	// Override the validator to report a non-connector manifest.
	srv.validator = &fakeManifestValidator{manifest: ValidatedManifest{Name: "plain-plugin", IsConnector: false}}
	ctx := ctxWithTenant(t, "acme")

	req := connectorRegisterReq()
	req.Remote = true

	_, err := srv.RegisterPlugin(ctx, req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("remote=true on a plain plugin must be InvalidArgument, got %v", err)
	}
}
