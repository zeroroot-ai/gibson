// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// setZitadelEnv renders the env a correct chart gives the daemon (ADR-0092).
func setZitadelEnv(t *testing.T, connectURL, claim string) {
	t.Helper()
	t.Setenv(envIDPProvider, "zitadel")
	t.Setenv(envIDPAdminIssuer, "https://"+claim)
	t.Setenv(envIDPAdminClientID, "gibson-daemon")
	t.Setenv(envIDPAdminClientSecret, "admin-secret")
	t.Setenv(envZitadelOrgID, "org-1")
	t.Setenv(zitadelconn.EnvURL, connectURL)
	t.Setenv(zitadelconn.EnvExternalDomain, claim)
}

// Before ADR-0092 an empty discovery URL silently sent every call to the
// public edge, which rejected the owner creation on staging. The endpoint is
// now required, and its absence stops the daemon at startup.
func TestInitIDPAdminClient_RequiresTheZitadelEndpoint(t *testing.T) {
	setZitadelEnv(t, "", "app.zitadel.invalid")
	_, err := initIDPAdminClient(context.Background())
	if err == nil || !strings.Contains(err.Error(), zitadelconn.EnvURL) {
		t.Fatalf("want an error naming %s, got %v", zitadelconn.EnvURL, err)
	}
}

func TestInitIDPAdminClient_ReachesZitadelByServiceName(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	setZitadelEnv(t, srv.URL, srv.Domain)

	client, err := initIDPAdminClient(context.Background())
	if err != nil {
		t.Fatalf("initIDPAdminClient: %v", err)
	}
	if c, ok := client.(io.Closer); ok {
		t.Cleanup(func() { _ = c.Close() })
	}
	if srv.Refused() != 0 {
		t.Errorf("%d request(s) did not name the instance", srv.Refused())
	}
	if !srv.HasPath(http.MethodPost, "/oauth/v2/token") {
		t.Errorf("the startup probe did not reach the in-cluster token endpoint: %v", srv.Paths())
	}
}

func TestInitIDPAdminClient_StartupProbeFailureStopsTheDaemon(t *testing.T) {
	setZitadelEnv(t, "http://127.0.0.1:1", "app.zitadel.invalid") // nothing listens
	_, err := initIDPAdminClient(context.Background())
	if err == nil || !strings.Contains(err.Error(), "startup probe failed") {
		t.Fatalf("want a startup probe failure, got %v", err)
	}
}

// baseAuthorizer implements the plain authz.Authorizer methods only — no
// ReadTuples, no WriteAndDelete — so embedding it never accidentally
// satisfies TupleReader or AtomicWriter.
type baseAuthorizer struct{}

func (baseAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (baseAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (baseAuthorizer) Write(context.Context, []authz.Tuple) error  { return nil }
func (baseAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (baseAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (baseAuthorizer) ListUsers(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (baseAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}
func (baseAuthorizer) StoreID() string { return "" }
func (baseAuthorizer) ModelID() string { return "" }
func (baseAuthorizer) Close() error    { return nil }

// fullAuthorizer also implements TupleReader and AtomicWriter, so
// tenantrole.AuthzTuples accepts it.
type fullAuthorizer struct{ baseAuthorizer }

func (fullAuthorizer) ReadTuples(context.Context, string, string, string) ([]authz.Tuple, error) {
	return nil, nil
}
func (fullAuthorizer) WriteAndDelete(context.Context, []authz.Tuple, []authz.Tuple) error {
	return nil
}

// readerOnlyAuthorizer implements TupleReader but not AtomicWriter, so
// tenantrole.AuthzTuples must still refuse it.
type readerOnlyAuthorizer struct{ baseAuthorizer }

func (readerOnlyAuthorizer) ReadTuples(context.Context, string, string, string) ([]authz.Tuple, error) {
	return nil, nil
}

func setTenantRoleSyncerEnv(t *testing.T, connectURL, claim, projectID string) {
	t.Helper()
	t.Setenv(envIDPProvider, "zitadel")
	t.Setenv(envIDPAdminClientID, "gibson-daemon")
	t.Setenv(envIDPAdminClientSecret, "admin-secret")
	t.Setenv(envIDPZitadelProjectID, projectID)
	t.Setenv(zitadelconn.EnvURL, connectURL)
	t.Setenv(zitadelconn.EnvExternalDomain, claim)
}

func TestInitTenantRoleSyncer_NoProviderReturnsNilNil(t *testing.T) {
	t.Setenv(envIDPProvider, "")
	syncer, err := initTenantRoleSyncer(context.Background(), fullAuthorizer{})
	if err != nil || syncer != nil {
		t.Fatalf("initTenantRoleSyncer with no provider = (%v, %v), want (nil, nil)", syncer, err)
	}
}

func TestInitTenantRoleSyncer_RejectsAnUnsupportedProvider(t *testing.T) {
	t.Setenv(envIDPProvider, "okta")
	_, err := initTenantRoleSyncer(context.Background(), fullAuthorizer{})
	if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("initTenantRoleSyncer with an unsupported provider: err = %v", err)
	}
}

func TestInitTenantRoleSyncer_RequiresTheProjectID(t *testing.T) {
	setTenantRoleSyncerEnv(t, "http://ignored.invalid", "app.zitadel.invalid", "")
	_, err := initTenantRoleSyncer(context.Background(), fullAuthorizer{})
	if err == nil || !strings.Contains(err.Error(), envIDPZitadelProjectID) {
		t.Fatalf("initTenantRoleSyncer with no project id: err = %v, want it to name %s", err, envIDPZitadelProjectID)
	}
}

func TestInitTenantRoleSyncer_RequiresClientCredentials(t *testing.T) {
	setTenantRoleSyncerEnv(t, "http://ignored.invalid", "app.zitadel.invalid", "PROJ-1")
	t.Setenv(envIDPAdminClientID, "")
	_, err := initTenantRoleSyncer(context.Background(), fullAuthorizer{})
	if err == nil || !strings.Contains(err.Error(), envIDPAdminClientID) {
		t.Fatalf("initTenantRoleSyncer with no client id: err = %v, want it to name %s", err, envIDPAdminClientID)
	}
}

func TestInitTenantRoleSyncer_RequiresTheZitadelEndpoint(t *testing.T) {
	setTenantRoleSyncerEnv(t, "", "app.zitadel.invalid", "PROJ-1")
	_, err := initTenantRoleSyncer(context.Background(), fullAuthorizer{})
	if err == nil || !strings.Contains(err.Error(), zitadelconn.EnvURL) {
		t.Fatalf("initTenantRoleSyncer with no connect URL: err = %v, want it to name %s", err, zitadelconn.EnvURL)
	}
}

func TestInitTenantRoleSyncer_WrapsAnAuthzTuplesConstructionError(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	setTenantRoleSyncerEnv(t, srv.URL, srv.Domain, "PROJ-1")

	_, err := initTenantRoleSyncer(context.Background(), readerOnlyAuthorizer{})
	if err == nil || !strings.Contains(err.Error(), "AtomicWriter") {
		t.Fatalf("initTenantRoleSyncer with an authorizer missing AtomicWriter: err = %v", err)
	}
}

func TestInitTenantRoleSyncer_BuildsASyncerWhenEverythingIsSet(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	setTenantRoleSyncerEnv(t, srv.URL, srv.Domain, "PROJ-1")

	syncer, err := initTenantRoleSyncer(context.Background(), fullAuthorizer{})
	if err != nil {
		t.Fatalf("initTenantRoleSyncer: %v", err)
	}
	if syncer == nil {
		t.Fatal("initTenantRoleSyncer returned a nil Syncer with no error")
	}
}
