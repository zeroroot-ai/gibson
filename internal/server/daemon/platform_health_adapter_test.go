// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
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

func TestSecretSourceReadiness_ReadyOnlyAfterAProbePasses(t *testing.T) {
	alive := false
	check := secretSourceReadiness(readinessProbe(func(context.Context) error {
		if !alive {
			return errors.New("no answer")
		}
		return nil
	}))
	if check(context.Background()).IsHealthy() {
		t.Fatal("ready before the source answered")
	}
	alive = true
	if !check(context.Background()).IsHealthy() {
		t.Fatal("not ready after the source answered")
	}
	alive = false
	if check(context.Background()).IsHealthy() {
		t.Fatal("still ready after the source stopped answering")
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
