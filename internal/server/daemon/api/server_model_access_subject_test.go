// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestSubjectKindToFGA_TeamSubjectIsTenantNamespaced pins that a model-access
// grant naming a team resolves to the caller's own namespaced team object.
//
// Team FGA object ids are tenant-namespaced (`team:<tenant>/<id>`, see
// internal/server/admin/team_object_ref.go). A grant written against the bare
// `team:<id>#member` would address a global object no team RPC creates any
// more, so the grant would exist and never resolve — a silent failure, which is
// the worst shape for an access-control write.
func TestSubjectKindToFGA_TeamSubjectIsTenantNamespaced(t *testing.T) {
	got, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TEAM, "eng")
	if err != nil {
		t.Fatalf("subjectKindToFGA: %v", err)
	}
	if got != "team:acme/eng#member" {
		t.Errorf("subject = %q, want team:acme/eng#member", got)
	}
}

// TestSubjectKindToFGA_RejectsAForgedTeamSubject covers the injection the
// namespace would otherwise invite: the id is caller-supplied and lands inside
// an FGA reference, so a subject_id carrying a separator, a type prefix or a
// userset marker could name an object other than the caller's own team.
func TestSubjectKindToFGA_RejectsAForgedTeamSubject(t *testing.T) {
	for _, tc := range []struct{ name, id string }{
		{"empty", ""},
		{"escapes the namespace", "../victim-co/eng"},
		{"names another tenant", "victim-co/eng"},
		{"userset marker", "eng#member"},
		{"type prefix", "team:eng"},
		{"whitespace", " eng"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TEAM, tc.id)
			if err == nil {
				t.Fatalf("subjectKindToFGA(%q) = %q, want a rejection", tc.id, got)
			}
			if status_grpc.Code(err) != codes.InvalidArgument {
				t.Errorf("code = %v, want InvalidArgument (err: %v)", status_grpc.Code(err), err)
			}
		})
	}
}

// TestSubjectKindToFGA_OtherKindsUnchanged is the control: only the team kind
// gains a namespace. A change that namespaced everything would break user and
// tenant grants while every team assertion above still passed.
func TestSubjectKindToFGA_OtherKindsUnchanged(t *testing.T) {
	user, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER, "alice")
	if err != nil || user != "user:alice" {
		t.Errorf("user subject = %q, %v; want user:alice", user, err)
	}
	tenant, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT, "acme")
	if err != nil || tenant != "tenant:acme#member" {
		t.Errorf("tenant subject = %q, %v; want tenant:acme#member", tenant, err)
	}
	if _, err := subjectKindToFGA("acme", tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_UNSPECIFIED, "x"); err == nil ||
		!strings.Contains(err.Error(), "subject_kind") {
		t.Errorf("unspecified kind = %v, want a subject_kind rejection", err)
	}
}
