package admin

// Remote-connector registration tests (gibson#685, ADR-0048 remote path):
// remote=true registers a connector for execution in the customer's own
// network — no hosted sandbox launch, and the response carries the one-time
// bootstrap token for the customer-run bridge to redeem.

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

func remoteConnectorRegisterReq() *tenantv1.RegisterPluginRequest {
	req := connectorRegisterReq()
	req.Remote = true
	return req
}

func TestRegisterPlugin_RemoteConnector_ReturnsTokenAndNeverLaunches(t *testing.T) {
	launcher := &fakeConnectorLauncher{}
	srv, zit, _ := newConnectorTestServer(t, launcher)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, remoteConnectorRegisterReq())
	if err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	if len(launcher.launched) != 0 {
		t.Fatalf("remote registration must not launch a sandbox; got %d launches", len(launcher.launched))
	}
	if len(zit.created) != 1 {
		t.Errorf("expected 1 principal, got %d", len(zit.created))
	}

	// The customer-run bridge needs the single-use token: it must be returned.
	if resp.GetBootstrapToken() == "" {
		t.Error("remote connector response must carry the bootstrap token")
	}
	if resp.GetBootstrapTokenExpiresAtUnix() == 0 {
		t.Error("remote connector response must carry the token expiry")
	}
	if resp.GetInstallId() == "" || resp.GetPluginPrincipalId() == "" {
		t.Errorf("install/principal ids missing: %+v", resp)
	}
}

func TestRegisterPlugin_RemoteConnector_WorksWithoutLauncher(t *testing.T) {
	// A daemon without sandbox.connector configured (launcher == nil) must
	// still accept remote registrations — that is the deployment shape the
	// remote path exists for.
	srv, _, _ := newConnectorTestServer(t, nil)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, remoteConnectorRegisterReq())
	if err != nil {
		t.Fatalf("RegisterPlugin without launcher: %v", err)
	}
	if resp.GetBootstrapToken() == "" {
		t.Error("remote connector response must carry the bootstrap token")
	}
}

func TestRegisterPlugin_RemoteOnPlainPlugin_InvalidArgument(t *testing.T) {
	zit := &fakeZitadel{}
	srv, err := NewPluginsAdminServer(PluginsAdminConfig{
		Registry:          &fakeComponentInstallRegistry{installs: map[string]ComponentInstallInfo{}},
		ManifestValidator: &fakeManifestValidator{manifest: ValidatedManifest{Name: "plain", Version: "1.0.0"}},
		ZitadelClient:     zit,
		SecretWriter:      &fakeSecretWriter{},
		Authorizer:        &fakeAuthorizer{},
		BootstrapAuditor:  &fakeAuditor{},
		BootstrapTokenTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPluginsAdminServer: %v", err)
	}
	ctx := ctxWithTenant(t, "acme")

	_, err = srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("name: plain"),
		Remote:       true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for remote on a plain plugin, got %v", err)
	}
	if len(zit.created) != 0 {
		t.Errorf("no principal must be created on rejected registration; got %d", len(zit.created))
	}
}

func TestRegisterPlugin_RemoteConnector_DryRunCreatesNothing(t *testing.T) {
	launcher := &fakeConnectorLauncher{}
	srv, zit, _ := newConnectorTestServer(t, launcher)
	ctx := ctxWithTenant(t, "acme")

	req := remoteConnectorRegisterReq()
	req.DryRun = true
	resp, err := srv.RegisterPlugin(ctx, req)
	if err != nil {
		t.Fatalf("RegisterPlugin dry_run: %v", err)
	}
	if resp.GetBootstrapToken() != "" || resp.GetInstallId() != "" {
		t.Errorf("dry_run must not mint anything: %+v", resp)
	}
	if len(zit.created) != 0 || len(launcher.launched) != 0 {
		t.Error("dry_run must create no principal and launch nothing")
	}
}
