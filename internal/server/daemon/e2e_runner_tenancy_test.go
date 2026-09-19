// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// The exit-test runner's tenant membership is fixture state: it exists so the
// dispatch gate judges the runner's runs the way it judges a member's
// (gibson#14). This file is UNTAGGED, so each assertion runs in whichever
// build the test run selects: the fixture build seeds, the production build
// never writes.

func TestEnsureTenantMember(t *testing.T) {
	ctx := context.Background()
	want := authz.Tuple{User: "user:zeroroot.ai/platform/e2e-runner", Relation: "member", Object: "tenant:primary"}

	t.Run("absent tuple is written", func(t *testing.T) {
		fa := &fakeAuthorizer{deny: true}
		if err := ensureTenantMember(ctx, fa, want.User, "primary", slog.Default()); err != nil {
			t.Fatal(err)
		}
		if len(fa.written) != 1 || fa.written[0] != want {
			t.Fatalf("wrote %v, want exactly %v", fa.written, want)
		}
	})
	t.Run("present tuple is left alone", func(t *testing.T) {
		fa := &fakeAuthorizer{}
		if err := ensureTenantMember(ctx, fa, want.User, "primary", slog.Default()); err != nil {
			t.Fatal(err)
		}
		if len(fa.written) != 0 {
			t.Fatalf("an existing membership was written again: %v", fa.written)
		}
	})
	t.Run("check error is reported", func(t *testing.T) {
		fa := &fakeAuthorizer{checkErr: context.DeadlineExceeded}
		if err := ensureTenantMember(ctx, fa, want.User, "primary", slog.Default()); err == nil {
			t.Fatal("a failed check must be reported")
		}
	})
	t.Run("write error is reported", func(t *testing.T) {
		fa := &fakeAuthorizer{deny: true, writeErr: context.DeadlineExceeded}
		if err := ensureTenantMember(ctx, fa, want.User, "primary", slog.Default()); err == nil {
			t.Fatal("a failed write must be reported")
		}
	})
}

func TestSeedE2ERunnerTenancy_ProductionBuildWritesNothing(t *testing.T) {
	if isTestFixturesBuild {
		t.Skip("fixture build")
	}
	t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
	t.Setenv("GIBSON_PLATFORM_TENANT", "primary")
	fa := &fakeAuthorizer{deny: true}
	seedE2ERunnerTenancy(context.Background(), fa, slog.Default())
	if len(fa.written) != 0 || len(fa.checks) != 0 {
		t.Fatalf("a production build must not touch FGA for a test identity: wrote %v, checked %v", fa.written, fa.checks)
	}
}

func TestSeedE2ERunnerTenancy_FixtureBuildMakesTheRunnerAMember(t *testing.T) {
	if !isTestFixturesBuild {
		t.Skip("production build")
	}
	t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
	t.Setenv("GIBSON_PLATFORM_TENANT", "primary")
	fa := &fakeAuthorizer{deny: true} // the tuple is absent
	seedE2ERunnerTenancy(context.Background(), fa, slog.Default())
	want := authz.Tuple{User: "user:zeroroot.ai/platform/e2e-runner", Relation: "member", Object: "tenant:primary"}
	if len(fa.written) != 1 || fa.written[0] != want {
		t.Fatalf("wrote %v, want exactly %v: the gate's caller shape is user:<svid without scheme> (callbackFGAUser)", fa.written, want)
	}
}

func TestSeedE2ERunnerTenancy_FixtureBuildGates(t *testing.T) {
	if !isTestFixturesBuild {
		t.Skip("production build")
	}
	t.Run("runtime flag off", func(t *testing.T) {
		t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "false")
		t.Setenv("GIBSON_PLATFORM_TENANT", "primary")
		fa := &fakeAuthorizer{deny: true}
		seedE2ERunnerTenancy(context.Background(), fa, slog.Default())
		if len(fa.written) != 0 || len(fa.checks) != 0 {
			t.Fatalf("GIBSON_TEST_FIXTURES_ENABLED=false must seed nothing: wrote %v, checked %v", fa.written, fa.checks)
		}
	})
	t.Run("no platform tenant", func(t *testing.T) {
		t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
		t.Setenv("GIBSON_PLATFORM_TENANT", "")
		var buf bytes.Buffer
		fa := &fakeAuthorizer{deny: true}
		seedE2ERunnerTenancy(context.Background(), fa, slog.New(slog.NewTextHandler(&buf, nil)))
		if len(fa.written) != 0 {
			t.Fatalf("an empty tenant must seed nothing: wrote %v", fa.written)
		}
		if !strings.Contains(buf.String(), "GIBSON_PLATFORM_TENANT is unset") {
			t.Fatalf("an empty tenant must be named in the log, got: %s", buf.String())
		}
	})
	t.Run("write error is logged", func(t *testing.T) {
		t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
		t.Setenv("GIBSON_PLATFORM_TENANT", "primary")
		var buf bytes.Buffer
		fa := &fakeAuthorizer{deny: true, writeErr: context.DeadlineExceeded}
		seedE2ERunnerTenancy(context.Background(), fa, slog.New(slog.NewTextHandler(&buf, nil)))
		if !strings.Contains(buf.String(), "seed failed") {
			t.Fatalf("a failed seed must be logged, or the runner silently stops at the gate; got: %s", buf.String())
		}
	})
}
