// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/zeroroot-ai/sdk/capabilitygrant"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestBuildComponentVerifier_PinsStableAudience — the component token audience
// is a fixed protocol constant both SDKs mint (gibson#1246), pinned in code
// rather than configured. Enabling the component path (keys URL set) builds a
// verifier with NO EXT_AUTHZ_CGJWT_COMPONENT_AUDIENCE env at all — the former
// requirement is retired. NewComponentVerifier rejects an empty audience list,
// so a successful build proves the pinned constant reached it.
func TestBuildComponentVerifier_PinsStableAudience(t *testing.T) {
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://daemon:8086/capabilitygrant/v1/keys")

	v, err := buildComponentVerifier(discardLogger(), &http.Client{}, testReplayStore(t))
	if err != nil {
		t.Fatalf("buildComponentVerifier: %v", err)
	}
	if v == nil {
		t.Fatal("buildComponentVerifier returned no verifier despite the component path being enabled")
	}
	// Pin the wire value: the daemon-side audience pin must equal exactly what
	// both SDKs sign, or every component RPC 401s.
	if capabilitygrant.AudienceGibsonDaemon != "zeroroot.ai/gibson-daemon" {
		t.Fatalf("AudienceGibsonDaemon = %q, want zeroroot.ai/gibson-daemon",
			capabilitygrant.AudienceGibsonDaemon)
	}
}

// TestBuildComponentVerifier_RefusesNoReplayStore: with the component path
// enabled, a verifier with no replay store is not built.
func TestBuildComponentVerifier_RefusesNoReplayStore(t *testing.T) {
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://daemon:8086/capabilitygrant/v1/keys")

	if v, err := buildComponentVerifier(discardLogger(), &http.Client{}, nil); err == nil {
		t.Fatalf("buildComponentVerifier = %v, nil: a missing replay store must be an error", v)
	}
}

// testReplayStore returns a replay store on a Redis of its own.
func testReplayStore(t *testing.T) cgjwt.ReplayStore {
	t.Helper()
	mr := miniredis.RunT(t)
	sc, err := requiredStateClient(context.Background(), "redis://"+mr.Addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	return cgjwt.NewRedisReplayStore(sc)
}
