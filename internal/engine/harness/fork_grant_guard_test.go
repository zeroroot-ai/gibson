// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// The renewal path uses the same fork check as the callback listener: the
// grant of a forked source works only in the source sandbox.
func TestForkGrantGuard_RefusesAForkedGrantOutsideTheSource(t *testing.T) {
	l := newForkLedger(t)
	if err := l.BeginFork(context.Background(), "jti-src", "ns/src-1/u0", time.Hour); err != nil {
		t.Fatal(err)
	}
	g := NewForkGrantGuard(l, testIdentity(), discardLogger())
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	claims := sdkcg.Claims{JTI: "jti-src", Tenant: tenant}

	if err := g.CheckGrant(forkCtx("jti-src", "tok-fork-1", ""), claims); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a fork: code = %v, want FailedPrecondition", status.Code(err))
	}
	if err := g.CheckGrant(forkCtx("jti-src", "", ""), claims); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity token: code = %v, want Unauthenticated", status.Code(err))
	}
	if err := g.CheckGrant(forkCtx("jti-src", "tok-src", ""), claims); err != nil {
		t.Fatalf("the source sandbox: %v", err)
	}
	other := sdkcg.Claims{JTI: "jti-other", Tenant: tenant}
	if err := g.CheckGrant(forkCtx("jti-other", "tok-fork-1", ""), other); err != nil {
		t.Fatalf("a grant with no fork record: %v", err)
	}
}
