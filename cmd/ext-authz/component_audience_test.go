// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

// TestBuildComponentVerifier_DisabledPath — when the keys URL is unset the
// component path is off entirely and no verifier is built.
func TestBuildComponentVerifier_DisabledPath(t *testing.T) {
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "")

	v, err := buildComponentVerifier(discardLogger(), &http.Client{}, testReplayStore(t))
	if err != nil {
		t.Fatalf("buildComponentVerifier with the component path disabled: %v", err)
	}
	if v != nil {
		t.Fatal("component verifier built despite EXT_AUTHZ_CGJWT_KEYS_URL being unset")
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
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store, err := cgjwt.NewRedisReplayStore(client)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
