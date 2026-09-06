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
// SVID-enrollment binding resolver (ADR-0066). The owner is NOT part of the
// binding — it is resolved dynamically at enrol time — so the binding gates
// only on the install tenant + SPIRE + CG wiring.
func TestResolvePluginSVIDBinding(t *testing.T) {
	const socket = "/run/spire/sockets/api.sock"

	t.Run("no install tenant is silent bootstrap-only", func(t *testing.T) {
		_, reason, ok := resolvePluginSVIDBinding("", "", socket, true)
		if ok || reason != "" {
			t.Errorf("unset tenant: ok=%v reason=%q, want disabled+silent", ok, reason)
		}
		// A blank/whitespace tenant is still "not configured", still silent.
		if _, r, o := resolvePluginSVIDBinding("  ", "", socket, true); o || r != "" {
			t.Errorf("blank tenant: ok=%v reason=%q, want disabled+silent", o, r)
		}
	})

	t.Run("configured but CG not wired disables with reason", func(t *testing.T) {
		_, reason, ok := resolvePluginSVIDBinding("primary", "", socket, false)
		if ok || reason == "" {
			t.Errorf("cg not wired: ok=%v reason=%q, want disabled+reason", ok, reason)
		}
	})

	t.Run("configured but no workload socket disables with reason", func(t *testing.T) {
		_, reason, ok := resolvePluginSVIDBinding("primary", "", "  ", true)
		if ok || reason == "" {
			t.Errorf("no socket: ok=%v reason=%q, want disabled+reason", ok, reason)
		}
	})

	t.Run("invalid trust domain disables with reason", func(t *testing.T) {
		_, reason, ok := resolvePluginSVIDBinding("primary", "NOT A DOMAIN", socket, true)
		if ok || reason == "" {
			t.Errorf("bad TD: ok=%v reason=%q, want disabled+reason", ok, reason)
		}
	})

	t.Run("fully configured, explicit trust domain", func(t *testing.T) {
		b, reason, ok := resolvePluginSVIDBinding("primary", "example.org", socket, true)
		if !ok || reason != "" {
			t.Fatalf("ok=%v reason=%q, want enabled", ok, reason)
		}
		if b.tenantID != "primary" {
			t.Errorf("binding tenant = %q, want primary", b.tenantID)
		}
		if b.trustDomain.Name() != "example.org" {
			t.Errorf("trust domain = %q, want example.org", b.trustDomain.Name())
		}
		if b.socketAddr != "unix://"+socket {
			t.Errorf("socketAddr = %q", b.socketAddr)
		}
	})

	t.Run("empty trust domain defaults to zeroroot.ai", func(t *testing.T) {
		b, _, ok := resolvePluginSVIDBinding("primary", "", socket, true)
		if !ok || b.trustDomain.Name() != "zeroroot.ai" {
			t.Errorf("ok=%v td=%q, want zeroroot.ai default", ok, b.trustDomain.Name())
		}
	})
}

// TestBuildPluginSVIDEnroller_NilWhenUnconfigured: with no install-tenant env
// set, the daemon builds no enroller (bootstrap-only), exercising the method's
// config-gathering + disabled branch without a live SPIRE socket.
func TestBuildPluginSVIDEnroller_NilWhenUnconfigured(t *testing.T) {
	t.Setenv("GIBSON_PLATFORM_TENANT", "")

	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon-test"
	d := &daemonImpl{
		config: &config.Config{Auth: config.AuthConfig{SPIFFE: &config.SPIFFEConfig{WorkloadAPISocket: "/run/spire/sockets/api.sock"}}},
		logger: observability.NewLogger(logCfg),
	}
	if e := d.buildPluginSVIDEnroller(context.Background()); e != nil {
		t.Fatalf("enroller = %v, want nil (unconfigured → bootstrap-only)", e)
	}
}

// TestBuildPluginSVIDEnroller_NilWhenPartiallyConfigured: the install tenant is
// set but the SPIFFE workload API is absent → disabled with a logged reason,
// still nil. (No owner env exists any more — the owner is resolved at enrol.)
func TestBuildPluginSVIDEnroller_NilWhenPartiallyConfigured(t *testing.T) {
	t.Setenv("GIBSON_PLATFORM_TENANT", "primary")

	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon-test"
	d := &daemonImpl{
		config: &config.Config{Auth: config.AuthConfig{SPIFFE: nil}}, // no workload API
		logger: observability.NewLogger(logCfg),
	}
	if e := d.buildPluginSVIDEnroller(context.Background()); e != nil {
		t.Fatalf("enroller = %v, want nil (no SPIFFE workload API)", e)
	}
}
