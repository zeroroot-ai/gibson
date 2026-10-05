// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// Model-access objects are tenant-namespaced (hosted#358). These tests pin
// that a grant names only the caller's own tenant, as subject and as target.

func TestTargetKindToFGA_IsInTheCallersTenant(t *testing.T) {
	provider, err := targetKindToFGA("acme", tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER, "anthropic")
	if err != nil || provider != "provider:acme/anthropic" {
		t.Errorf("provider target = %q, %v; want provider:acme/anthropic", provider, err)
	}
	// A model name keeps its own ':' and '/'.
	model, err := targetKindToFGA("acme", tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL, "meta/llama3:8b")
	if err != nil || model != "model:acme/meta/llama3:8b" {
		t.Errorf("model target = %q, %v; want model:acme/meta/llama3:8b", model, err)
	}
	for name, tc := range map[string]struct {
		kind tenantv1.GrantTargetKind
		id   string
	}{
		"no kind":        {tenantv1.GrantTargetKind_GRANT_TARGET_KIND_UNSPECIFIED, "anthropic"},
		"empty id":       {tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER, ""},
		"userset marker": {tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL, "opus#member"},
		"whitespace":     {tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL, "opus 4"},
	} {
		if got, err := targetKindToFGA("acme", tc.kind, tc.id); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: targetKindToFGA = %q, %v; want InvalidArgument", name, got, err)
		}
	}
}

func TestFGATargetToProto_SkipsWhatIsNotTheCallersTenant(t *testing.T) {
	kind, id, ok := fgaTargetToProto("acme", "provider:acme/anthropic")
	if !ok || kind != tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER || id != "anthropic" {
		t.Errorf("provider = %v, %q, %v", kind, id, ok)
	}
	kind, id, ok = fgaTargetToProto("acme", "model:acme/meta/llama3:8b")
	if !ok || kind != tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL || id != "meta/llama3:8b" {
		t.Errorf("model = %v, %q, %v", kind, id, ok)
	}
	for _, obj := range []string{"provider:victim-co/anthropic", "provider:anthropic", "model:acme/", "team:acme/eng"} {
		if _, _, ok := fgaTargetToProto("acme", obj); ok {
			t.Errorf("fgaTargetToProto(acme, %q) reported the object as the caller's", obj)
		}
	}
}

// TestSubjectKindToFGA_ATenantGrantNamesTheCallersTenant: the tenant subject
// is the caller's tenant. An empty id means the same. Another tenant's id is
// refused, where it used to become that tenant's member set.
func TestSubjectKindToFGA_ATenantGrantNamesTheCallersTenant(t *testing.T) {
	for _, id := range []string{"acme", ""} {
		got, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT, id)
		if err != nil || got != "tenant:acme#member" {
			t.Errorf("subjectKindToFGA(tenant, %q) = %q, %v; want tenant:acme#member", id, got, err)
		}
	}
	got, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT, "victim-co")
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("subjectKindToFGA(tenant, victim-co) = %q, %v; want InvalidArgument", got, err)
	}
}

// TestListAccess_ShowsTheDefaultTenantGrant: an administrator who lists the
// tenant's grants with no subject id sees the default grant of each provider,
// as bare names, and sees nothing from outside the tenant's namespace. This is
// the row an administrator revokes to turn a provider off (hosted#358).
func TestListAccess_ShowsTheDefaultTenantGrant(t *testing.T) {
	a := newFakeAuthorizer().
		allow("user:"+testViewerSubject, "admin", "tenant:acme").
		withObjects("tenant:acme#member", "can_use", "provider", "provider:acme/anthropic", "provider:victim-co/openai", "provider:anthropic")
	srv := &DaemonServer{logger: testSlogLogger, authorizer: a}

	resp, err := srv.ListAccess(missionViewerCtx(), &tenantv1.ListAccessRequest{
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT,
	})
	if err != nil {
		t.Fatalf("ListAccess: %v", err)
	}
	if len(resp.GetGrants()) != 1 {
		t.Fatalf("grants = %v, want the one default grant of the caller's tenant", resp.GetGrants())
	}
	g := resp.GetGrants()[0]
	if g.GetTargetKind() != tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER || g.GetTargetId() != "anthropic" {
		t.Errorf("grant target = %v %q, want provider anthropic", g.GetTargetKind(), g.GetTargetId())
	}
}
