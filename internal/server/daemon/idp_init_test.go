// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

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
