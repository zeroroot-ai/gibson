// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests that a manifest issuance records who asked for it.
//
// Before this, RecordIssuance took no actor and the Builder passed none, so
// an admin previewing another principal's manifest produced an audit record
// indistinguishable from that principal fetching its own.
package manifest

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
)

// recordingAudit captures the Issuance the Builder reports.
type recordingAudit struct {
	calls    int
	issuance Issuance
	err      error
}

func (a *recordingAudit) RecordIssuance(_ context.Context, _ *manifestpb.CapabilityManifest, issuance Issuance, _ []byte) error {
	a.calls++
	a.issuance = issuance
	return a.err
}

// builderWithAudit is newTestBuilder plus an AuditWriter. It rebuilds rather
// than reuses so the audit dependency can be injected.
func builderWithAudit(t *testing.T, fga FGAResolver, reg RegistrySource, aud AuditWriter) Builder {
	t.Helper()
	b, _, _ := newTestBuilder(t, fga, reg)
	mb, ok := b.(*manifestBuilder)
	if !ok {
		t.Fatalf("newTestBuilder returned %T, want *manifestBuilder", b)
	}
	mb.deps.Audit = aud
	return mb
}

func auditTestFGA() *fakeFGA {
	return &fakeFGA{
		resolve: func(_ context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
			return []capabilitygrant.Capability{
				{Name: "execute:tool:nmap", ComponentRef: "component:tool/nmap", Kind: "tool"},
			}, nil
		},
		intersection: func(_ context.Context, apID, ownerID, tenantID string) ([]capabilitygrant.ComponentRef, error) {
			return []capabilitygrant.ComponentRef{{Name: "nmap", Kind: "tool"}}, nil
		},
	}
}

func auditTestRegistry() *fakeRegistry {
	return &fakeRegistry{infos: []component.ComponentInfo{
		{Kind: "tool", Name: "nmap", Version: "1.0", TenantID: "_system"},
	}}
}

// TestIssuance_SelfIssuanceRecordsTheSubjectAsActor: with no explicit actor,
// the caller is the subject and the record should say so.
func TestIssuance_SelfIssuanceRecordsTheSubjectAsActor(t *testing.T) {
	aud := &recordingAudit{}
	b := builderWithAudit(t, auditTestFGA(), auditTestRegistry(), aud)

	if _, err := b.Build(context.Background(), ManifestSubject{
		Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-acme",
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	if aud.calls != 1 {
		t.Fatalf("RecordIssuance called %d times, want 1", aud.calls)
	}
	if got := aud.issuance.Actor.FGARef(); got != "user:alice" {
		t.Errorf("Actor = %q, want %q", got, "user:alice")
	}
	if got := aud.issuance.Subject; got != "user:alice" {
		t.Errorf("Subject = %q, want %q", got, "user:alice")
	}
	if aud.issuance.TenantID != "tenant-acme" {
		t.Errorf("TenantID = %q, want %q", aud.issuance.TenantID, "tenant-acme")
	}
	if aud.issuance.Impersonated() {
		t.Errorf("self-issuance reported as impersonated: %+v", aud.issuance)
	}
}

// TestIssuance_ImpersonationRecordsAdminAndImpersonatedPrincipal is the
// defect this change exists for: an admin preview must name both parties.
func TestIssuance_ImpersonationRecordsAdminAndImpersonatedPrincipal(t *testing.T) {
	aud := &recordingAudit{}
	b := builderWithAudit(t, auditTestFGA(), auditTestRegistry(), aud)

	if _, err := b.Build(context.Background(), ManifestSubject{
		Type:                         SubjectTypeAgentPrincipal,
		ID:                           "ap-7",
		TenantID:                     "tenant-acme",
		OwnerUserID:                  "admin-1",
		ImpersonatedAgentPrincipalID: "ap-7",
		Actor:                        Actor{Type: SubjectTypeUser, ID: "admin-1"},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := aud.issuance.Actor.FGARef(); got != "user:admin-1" {
		t.Errorf("Actor = %q, want the impersonating admin %q", got, "user:admin-1")
	}
	if got := aud.issuance.Subject; got != "agent_principal:ap-7" {
		t.Errorf("Subject = %q, want %q", got, "agent_principal:ap-7")
	}
	if got := aud.issuance.ImpersonatedAgentPrincipalID; got != "ap-7" {
		t.Errorf("ImpersonatedAgentPrincipalID = %q, want %q", got, "ap-7")
	}
	if !aud.issuance.Impersonated() {
		t.Error("an admin preview must be recorded as impersonation")
	}
	if aud.issuance.Actor.FGARef() == aud.issuance.Subject {
		t.Error("impersonated issuance attributed to the impersonated principal — the exact defect this test guards")
	}
}

// TestIssuance_ImpersonationWithoutActorIsRefused: silently attributing an
// impersonated issuance to the subject would read as a clean self-issuance,
// which is worse than no attribution.
func TestIssuance_ImpersonationWithoutActorIsRefused(t *testing.T) {
	aud := &recordingAudit{}
	b := builderWithAudit(t, auditTestFGA(), auditTestRegistry(), aud)

	_, err := b.Build(context.Background(), ManifestSubject{
		Type:                         SubjectTypeAgentPrincipal,
		ID:                           "ap-7",
		TenantID:                     "tenant-acme",
		OwnerUserID:                  "admin-1",
		ImpersonatedAgentPrincipalID: "ap-7",
		// Actor deliberately absent.
	})
	if err == nil {
		t.Fatal("Build accepted an impersonated issuance with no actor")
	}
	if aud.calls != 0 {
		t.Errorf("RecordIssuance called %d times for a refused Build", aud.calls)
	}
}

// TestIssuance_AuditFailureDoesNotFailTheBuild preserves the documented
// best-effort contract while the signature changes around it.
func TestIssuance_AuditFailureDoesNotFailTheBuild(t *testing.T) {
	aud := &recordingAudit{err: errors.New("audit backend down")}
	b := builderWithAudit(t, auditTestFGA(), auditTestRegistry(), aud)

	if _, err := b.Build(context.Background(), ManifestSubject{
		Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-acme",
	}); err != nil {
		t.Fatalf("an audit write failure must not fail Build: %v", err)
	}
	if aud.calls != 1 {
		t.Fatalf("RecordIssuance called %d times, want 1", aud.calls)
	}
}
