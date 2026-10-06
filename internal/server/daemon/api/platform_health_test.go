// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

type probeFunc func(ctx context.Context) error

func (f probeFunc) Probe(ctx context.Context) error { return f(ctx) }

func platformHealth(t *testing.T, s *DaemonServer) *tenantv1.PlatformPlaneHealth {
	t.Helper()
	resp, err := s.AdminGetPlatformHealth(context.Background(), &tenantv1.AdminGetPlatformHealthRequest{})
	if err != nil {
		t.Fatalf("AdminGetPlatformHealth: %v", err)
	}
	if len(resp.GetPlanes()) != 1 || resp.GetPlanes()[0].GetPlane() != planeSecret {
		t.Fatalf("planes = %+v, want one secret_plane", resp.GetPlanes())
	}
	return resp.GetPlanes()[0]
}

func TestAdminGetPlatformHealth_AnsweringSourceIsHealthy(t *testing.T) {
	s := (&DaemonServer{logger: slog.Default()}).WithSecretPlaneProbe(probeFunc(func(context.Context) error { return nil }))
	got := platformHealth(t, s)
	if got.GetState() != tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_HEALTHY || got.GetDetail() != "" {
		t.Fatalf("got %+v, want HEALTHY with no detail", got)
	}
	if got.GetCheckedAtUnix() == 0 {
		t.Fatal("the probe time is not set")
	}
}

func TestAdminGetPlatformHealth_SilentSourceIsUnhealthy(t *testing.T) {
	s := (&DaemonServer{logger: slog.Default()}).WithSecretPlaneProbe(probeFunc(func(context.Context) error {
		return errors.New("could not get secret data from provider")
	}))
	got := platformHealth(t, s)
	if got.GetState() != tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_UNHEALTHY {
		t.Fatalf("got %+v, want UNHEALTHY", got)
	}
	if !strings.Contains(got.GetDetail(), "could not get secret data") {
		t.Fatalf("detail %q does not name the cause", got.GetDetail())
	}
}

func TestAdminGetPlatformHealth_TheProbeHasADeadline(t *testing.T) {
	s := (&DaemonServer{logger: slog.Default()}).WithSecretPlaneProbe(probeFunc(func(ctx context.Context) error {
		dl, ok := ctx.Deadline()
		if !ok || time.Until(dl) > SecretPlaneProbeTimeout {
			return errors.New("the probe has no bound")
		}
		return nil
	}))
	if got := platformHealth(t, s); got.GetState() != tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_HEALTHY {
		t.Fatalf("the probe ran without a deadline: %+v", got)
	}
}

func TestAdminGetPlatformHealth_NoProbeIsUnknownNotHealthy(t *testing.T) {
	got := platformHealth(t, &DaemonServer{logger: slog.Default()})
	if got.GetState() != tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_UNKNOWN {
		t.Fatalf("got %+v, want UNKNOWN", got)
	}
}
