// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

type readinessProbe func(ctx context.Context) error

func (f readinessProbe) Probe(ctx context.Context) error { return f(ctx) }

// A source that is dead when the daemon starts must keep the daemon not
// ready. The old check read the cached health map, which is empty before the
// first secret operation, and reported healthy (hosted#174).
func TestSecretSourceReadiness_ADeadSourceAtStartIsNotReady(t *testing.T) {
	check := secretSourceReadiness(readinessProbe(func(context.Context) error {
		return errors.New("dial tcp 10.0.0.1:8200: connect: connection refused")
	}))
	got := check(context.Background())
	if got.IsHealthy() {
		t.Fatalf("a dead source at start reads healthy: %+v", got)
	}
	if !strings.Contains(got.Message, "connection refused") {
		t.Fatalf("message %q does not name the cause", got.Message)
	}
}

func TestSecretSourceReadiness_IsAStartGateOnly(t *testing.T) {
	alive := false
	probe := readinessProbe(func(context.Context) error {
		if !alive {
			return errors.New("no answer")
		}
		return nil
	})
	check := secretSourceReadiness(probe)
	if check(context.Background()).IsHealthy() {
		t.Fatal("ready before the source answered")
	}
	alive = true
	if !check(context.Background()).IsHealthy() {
		t.Fatal("not ready after the source answered")
	}

	// The source stops answering after the start. The pod stays ready, so a
	// short outage does not empty the Service. The platform health shows it.
	alive = false
	if !check(context.Background()).IsHealthy() {
		t.Fatal("a later outage of the source made the daemon not ready")
	}
	health, err := api.NewDaemonServer(nil, nil, nil).WithSecretPlaneProbe(probe).
		AdminGetPlatformHealth(context.Background(), &tenantv1.AdminGetPlatformHealthRequest{})
	if err != nil {
		t.Fatalf("AdminGetPlatformHealth: %v", err)
	}
	if got := health.GetPlanes()[0].GetState(); got != tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_UNHEALTHY {
		t.Fatalf("platform health = %s, want UNHEALTHY", got)
	}
}

func TestSecretSourceReadiness_TheProbeIsBounded(t *testing.T) {
	check := secretSourceReadiness(readinessProbe(func(ctx context.Context) error {
		dl, ok := ctx.Deadline()
		if !ok || time.Until(dl) > api.SecretPlaneProbeTimeout {
			return errors.New("the probe has no bound")
		}
		return nil
	}))
	if got := check(context.Background()); !got.IsHealthy() {
		t.Fatalf("the probe ran without the bound: %+v", got)
	}
}

// openbao is a stand-in for the health endpoint of the platform OpenBao. Its
// status code is the state of the server: 200 active, 503 sealed.
func openbao(t *testing.T, status *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" || r.URL.Query().Get("standbyok") != "true" {
			http.Error(w, "unexpected request "+r.URL.String(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(*status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A new install has no broker config row: nothing writes one for the system
// tenant, and the first tenant waits for the daemon. The probe asks the
// configured backend and not a row, so the daemon gets ready as soon as the
// backend answers. Before gibson#1078 it asked the broker of the system
// tenant and never got ready.
func TestSecretBackendProbe_ANewInstallIsReadyWhenTheBackendAnswers(t *testing.T) {
	status := http.StatusOK
	srv := openbao(t, &status)
	check := secretSourceReadiness(newOpenBaoHealthProbe(srv.URL + "/"))
	if got := check(context.Background()); !got.IsHealthy() {
		t.Fatalf("the backend answered and the daemon is not ready: %+v", got)
	}
}

// A dead backend at start keeps the daemon not ready, and the message names
// why. Then the backend answers, and a later outage does not flip readiness;
// the platform health shows that outage (hosted#174).
func TestSecretBackendProbe_IsAStartGateOnTheConfiguredBackend(t *testing.T) {
	status := http.StatusServiceUnavailable
	srv := openbao(t, &status)
	probe := newOpenBaoHealthProbe(srv.URL)
	check := secretSourceReadiness(probe)

	got := check(context.Background())
	if got.IsHealthy() {
		t.Fatalf("a sealed backend at start reads ready: %+v", got)
	}
	if !strings.Contains(got.Message, "sealed") {
		t.Fatalf("message %q does not name the cause", got.Message)
	}

	status = http.StatusOK
	if got := check(context.Background()); !got.IsHealthy() {
		t.Fatalf("not ready after the backend answered: %+v", got)
	}

	status = http.StatusServiceUnavailable
	if got := check(context.Background()); !got.IsHealthy() {
		t.Fatalf("a later outage of the backend made the daemon not ready: %+v", got)
	}
	health, err := api.NewDaemonServer(nil, nil, nil).WithSecretPlaneProbe(probe).
		AdminGetPlatformHealth(context.Background(), &tenantv1.AdminGetPlatformHealthRequest{})
	if err != nil {
		t.Fatalf("AdminGetPlatformHealth: %v", err)
	}
	if got := health.GetPlanes()[0].GetState(); got != tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_UNHEALTHY {
		t.Fatalf("platform health of a sealed backend = %s, want UNHEALTHY", got)
	}
}

// A backend that does not answer at all is not ready either.
func TestSecretBackendProbe_AnUnreachableBackendIsNotReady(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close()
	got := secretSourceReadiness(newOpenBaoHealthProbe(addr))(context.Background())
	if got.IsHealthy() {
		t.Fatalf("an unreachable backend reads ready: %+v", got)
	}
}

// With no configured backend the daemon cannot prove a secret source, so it
// is not ready. A missing address must never read as a pass.
func TestSecretBackendProbe_NoAddressIsNotReady(t *testing.T) {
	got := secretSourceReadiness(newOpenBaoHealthProbe(""))(context.Background())
	if got.IsHealthy() {
		t.Fatalf("no configured backend reads ready: %+v", got)
	}
	if !strings.Contains(got.Message, "security.secret_source.address") {
		t.Fatalf("message %q does not name the missing key", got.Message)
	}
}
