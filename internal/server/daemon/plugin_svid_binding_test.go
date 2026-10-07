// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// TestResolvePluginSVIDBinding covers every decision branch of the pure
// SVID-enrollment binding resolver (ADR-0066). No tenant is a part of the
// binding: the tenant comes from the identity of each plugin instance
// (gibson#815). The binding gates only on SPIRE and the CG wiring.
func TestResolvePluginSVIDBinding(t *testing.T) {
	const socket = "/run/spire/sockets/api.sock"

	t.Run("no workload socket is silent", func(t *testing.T) {
		for _, s := range []string{"", "  "} {
			if _, reason, ok := resolvePluginSVIDBinding("", s, true); ok || reason != "" {
				t.Errorf("socket %q: ok=%v reason=%q, want disabled and silent", s, ok, reason)
			}
		}
	})

	t.Run("CG not wired disables with reason", func(t *testing.T) {
		_, reason, ok := resolvePluginSVIDBinding("", socket, false)
		if ok || reason == "" {
			t.Errorf("cg not wired: ok=%v reason=%q, want disabled+reason", ok, reason)
		}
	})

	t.Run("invalid trust domain disables with reason", func(t *testing.T) {
		_, reason, ok := resolvePluginSVIDBinding("NOT A DOMAIN", socket, true)
		if ok || reason == "" {
			t.Errorf("bad TD: ok=%v reason=%q, want disabled+reason", ok, reason)
		}
	})

	t.Run("fully configured, explicit trust domain", func(t *testing.T) {
		b, reason, ok := resolvePluginSVIDBinding("example.org", socket, true)
		if !ok || reason != "" {
			t.Fatalf("ok=%v reason=%q, want enabled", ok, reason)
		}
		if b.trustDomain.Name() != "example.org" {
			t.Errorf("trust domain = %q, want example.org", b.trustDomain.Name())
		}
		if b.socketAddr != "unix://"+socket {
			t.Errorf("socketAddr = %q", b.socketAddr)
		}
	})

	t.Run("an empty trust domain disables with a reason", func(t *testing.T) {
		// No code holds a trust domain as a literal (ADR-0164), so an empty
		// value has no default.
		if _, reason, ok := resolvePluginSVIDBinding("", socket, true); ok || reason == "" {
			t.Errorf("ok=%v reason=%q, want disabled with a reason", ok, reason)
		}
	})
}

// TestBuildPluginSVIDEnroller_NilWithNoWorkloadAPI: a daemon with no SPIFFE
// workload API builds no enroller.
func TestBuildPluginSVIDEnroller_NilWithNoWorkloadAPI(t *testing.T) {
	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon-test"
	d := &daemonImpl{
		config: &config.Config{Auth: config.AuthConfig{SPIFFE: nil}},
		logger: observability.NewLogger(logCfg),
	}
	if e := d.buildPluginSVIDEnroller(context.Background()); e != nil {
		t.Fatalf("enroller = %v, want nil (no SPIFFE workload API)", e)
	}
}

// TestBuildPluginSVIDEnroller_NilWhenCGNotWired: the workload API is set but
// the CapabilityGrantService is absent, so the path is disabled with a logged
// reason.
func TestBuildPluginSVIDEnroller_NilWhenCGNotWired(t *testing.T) {
	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon-test"
	d := &daemonImpl{
		config: &config.Config{Auth: config.AuthConfig{SPIFFE: &config.SPIFFEConfig{WorkloadAPISocket: "/run/spire/sockets/api.sock"}}},
		logger: observability.NewLogger(logCfg),
	}
	if e := d.buildPluginSVIDEnroller(context.Background()); e != nil {
		t.Fatalf("enroller = %v, want nil (CG not wired)", e)
	}
}
