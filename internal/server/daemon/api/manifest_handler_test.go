// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for GetCapabilityManifest's impersonation gate and for the
// attribution it puts on the subject it hands to the Builder.
package api

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/manifest"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
)

// recordingBuilder captures the subject the handler resolved.
type recordingBuilder struct {
	calls   int
	subject manifest.ManifestSubject
}

func (b *recordingBuilder) Build(_ context.Context, subject manifest.ManifestSubject) (*manifestpb.CapabilityManifest, error) {
	b.calls++
	b.subject = subject
	return &manifestpb.CapabilityManifest{
		ManifestId: "m-1",
		Subject:    subject.FGARef(),
		TenantId:   subject.TenantID,
	}, nil
}

func manifestCtx(subject string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{
		Subject: subject,
		Tenant:  auth.MustNewTenantID("acme"),
	})
}

// TestGetCapabilityManifest_NilAuthorizer_DeniesImpersonation is the
// fail-open regression. The admin check used to be wrapped in
// `if s.authorizer != nil`, so an unwired authorizer skipped it entirely and
// every caller could impersonate.
func TestGetCapabilityManifest_NilAuthorizer_DeniesImpersonation(t *testing.T) {
	b := &recordingBuilder{}
	srv := &DaemonServer{
		logger:          testSlogLogger,
		manifestBuilder: b,
		authorizer:      nil, // the unwired seam
	}

	_, err := srv.GetCapabilityManifest(manifestCtx("u-mallory"),
		&manifestpb.GetCapabilityManifestRequest{AgentPrincipalId: "ap-7"})

	if err == nil {
		t.Fatal("impersonation was allowed with no authorizer wired")
	}
	if grpcCode(err) != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied", grpcCode(err))
	}
	if b.calls != 0 {
		t.Errorf("Builder was invoked %d times for a denied request", b.calls)
	}
}

// TestGetCapabilityManifest_NonAdmin_DeniesImpersonation keeps the wired
// path honest — a denial must come from the FGA answer, not from the
// authorizer merely being absent.
func TestGetCapabilityManifest_NonAdmin_DeniesImpersonation(t *testing.T) {
	b := &recordingBuilder{}
	srv := &DaemonServer{
		logger:          testSlogLogger,
		manifestBuilder: b,
		authorizer:      newFakeAuthorizer(), // no allow() — Check returns false
	}

	_, err := srv.GetCapabilityManifest(manifestCtx("u-mallory"),
		&manifestpb.GetCapabilityManifestRequest{AgentPrincipalId: "ap-7"})

	if grpcCode(err) != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied", grpcCode(err))
	}
	if b.calls != 0 {
		t.Errorf("Builder was invoked %d times for a denied request", b.calls)
	}
}

// TestGetCapabilityManifest_Admin_RecordsImpersonation: the allowed path
// must carry both the acting admin and the impersonated principal, or the
// issuance audit record cannot name either.
func TestGetCapabilityManifest_Admin_RecordsImpersonation(t *testing.T) {
	b := &recordingBuilder{}
	srv := &DaemonServer{
		logger:          testSlogLogger,
		manifestBuilder: b,
		authorizer:      newFakeAuthorizer().allow("user:u-admin", "admin", "tenant:acme"),
	}

	if _, err := srv.GetCapabilityManifest(manifestCtx("u-admin"),
		&manifestpb.GetCapabilityManifestRequest{AgentPrincipalId: "ap-7"}); err != nil {
		t.Fatalf("admin impersonation was denied: %v", err)
	}

	if b.calls != 1 {
		t.Fatalf("Builder invoked %d times, want 1", b.calls)
	}
	if got := b.subject.ImpersonatedAgentPrincipalID; got != "ap-7" {
		t.Errorf("ImpersonatedAgentPrincipalID = %q, want %q — impersonation is invisible without it", got, "ap-7")
	}
	if got := b.subject.Actor.FGARef(); got != "user:u-admin" {
		t.Errorf("Actor = %q, want the acting admin %q", got, "user:u-admin")
	}
	if b.subject.Actor.FGARef() == b.subject.FGARef() {
		t.Error("impersonated request attributed to the impersonated principal")
	}
}

// TestGetCapabilityManifest_SelfIssuance_AttributesToTheCaller asserts that a
// caller issuing their own manifest is recorded as both the Actor and the
// subject — no impersonation fields set.
func TestGetCapabilityManifest_SelfIssuance_AttributesToTheCaller(t *testing.T) {
	b := &recordingBuilder{}
	srv := &DaemonServer{logger: testSlogLogger, manifestBuilder: b}

	if _, err := srv.GetCapabilityManifest(manifestCtx("u-alice"),
		&manifestpb.GetCapabilityManifestRequest{}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := b.subject.Actor.FGARef(); got != "user:u-alice" {
		t.Errorf("Actor = %q, want %q", got, "user:u-alice")
	}
	if b.subject.ImpersonatedAgentPrincipalID != "" {
		t.Errorf("self-issuance marked as impersonation: %q", b.subject.ImpersonatedAgentPrincipalID)
	}
}

// TestGetCapabilityManifest_AgentCaller_AttributesToTheAgentPrincipal asserts
// that an agent-principal caller issuing its own manifest is attributed to
// that agent principal.
func TestGetCapabilityManifest_AgentCaller_AttributesToTheAgentPrincipal(t *testing.T) {
	b := &recordingBuilder{}
	srv := &DaemonServer{logger: testSlogLogger, manifestBuilder: b}

	if _, err := srv.GetCapabilityManifest(manifestCtx("agent_principal:ap-9"),
		&manifestpb.GetCapabilityManifestRequest{}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := b.subject.Actor.FGARef(); got != "agent_principal:ap-9" {
		t.Errorf("Actor = %q, want %q", got, "agent_principal:ap-9")
	}
}

// TestGetCapabilityManifest_AgentCaller_MayNotImpersonate asserts that an
// agent-principal caller requesting a manifest for a different agent
// principal is refused with PermissionDenied and the builder is never
// invoked.
func TestGetCapabilityManifest_AgentCaller_MayNotImpersonate(t *testing.T) {
	b := &recordingBuilder{}
	srv := &DaemonServer{
		logger:          testSlogLogger,
		manifestBuilder: b,
		authorizer:      newFakeAuthorizer().allow("user:agent_principal:ap-9", "admin", "tenant:acme"),
	}

	_, err := srv.GetCapabilityManifest(manifestCtx("agent_principal:ap-9"),
		&manifestpb.GetCapabilityManifestRequest{AgentPrincipalId: "ap-7"})

	if grpcCode(err) != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied", grpcCode(err))
	}
	if b.calls != 0 {
		t.Errorf("Builder was invoked %d times for a denied request", b.calls)
	}
}
