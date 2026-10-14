package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
)

// The owner of a self-serve tenant is born inside the tenant org
// (gibson#1188). A person belongs to one Zitadel org for life, and ext-authz
// reads the tenant from the org in the token (ADR-0093 decision 4). These
// tests pin the order: the org first, then the owner inside it, and the org
// is removed when the owner cannot be made.

func TestSignup_MakesTheTenantOrgBeforeTheOwner(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createOrgFn = func(_ context.Context, name string) (string, error) {
		if len(h.idp.createHumanReqs) != 0 {
			t.Fatalf("the org must be created before the owner; %d owner(s) exist", len(h.idp.createHumanReqs))
		}
		if name != "Acme Red Team" {
			t.Fatalf("org name = %q, want the workspace name", name)
		}
		return "org-tenant", nil
	}
	session := requestVerifiedSession(t, h, "team")

	if _, err := signupWithSession(t, h, session); err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if len(h.idp.createdOrgs) != 1 {
		t.Fatalf("orgs created = %d, want 1", len(h.idp.createdOrgs))
	}
	if len(h.idp.createHumanReqs) != 1 {
		t.Fatalf("owners created = %d, want 1", len(h.idp.createHumanReqs))
	}
	if got := h.idp.createHumanReqs[0].OrgID; got != "org-tenant" {
		t.Fatalf("owner OrgID = %q, want the tenant org; an owner elsewhere never reaches the workspace", got)
	}
	if len(h.idp.deletedOrgs) != 0 {
		t.Fatalf("a signup that succeeded removed orgs %v", h.idp.deletedOrgs)
	}
}

func TestSignup_TakenOrgNameRefusesTheWorkspaceNameAndMakesNoOwner(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createOrgFn = func(_ context.Context, _ string) (string, error) {
		return "", idp.ErrAlreadyExists
	}
	session := requestVerifiedSession(t, h, "team")

	_, err := signupWithSession(t, h, session)
	if got := status.Code(err); got != codes.AlreadyExists {
		t.Fatalf("Signup code = %v (%v), want AlreadyExists for a taken workspace name", got, err)
	}
	if len(h.idp.createHumanReqs) != 0 {
		t.Fatalf("an owner was created for a workspace that has no org: %+v", h.idp.createHumanReqs)
	}
}

func TestSignup_RemovesTheOrgWhenTheOwnerCannotBeMade(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, errors.New("boom")
	}
	session := requestVerifiedSession(t, h, "team")

	if _, err := signupWithSession(t, h, session); err == nil {
		t.Fatal("Signup must fail when the owner cannot be made")
	}
	if len(h.idp.createdOrgs) != 1 || len(h.idp.deletedOrgs) != 1 || h.idp.deletedOrgs[0] != "org-1" {
		t.Fatalf("created %v, deleted %v; want the one org of this signup removed",
			h.idp.createdOrgs, h.idp.deletedOrgs)
	}
}

func TestRegister_MakesTheTenantOrgBeforeTheOwner(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.createOrgFn = func(_ context.Context, name string) (string, error) {
		if len(h.idp.createHumanReqs) != 0 {
			t.Fatalf("the org must be created before the owner; %d owner(s) exist", len(h.idp.createHumanReqs))
		}
		if name != "Acme Research" {
			t.Fatalf("org name = %q, want the workspace name", name)
		}
		return "org-tenant", nil
	}

	if _, err := h.srv.Register(context.Background(), registerRequest()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(h.idp.createHumanReqs) != 1 {
		t.Fatalf("owners created = %d, want 1", len(h.idp.createHumanReqs))
	}
	if got := h.idp.createHumanReqs[0].OrgID; got != "org-tenant" {
		t.Fatalf("owner OrgID = %q, want the tenant org", got)
	}
	if len(h.idp.deletedOrgs) != 0 {
		t.Fatalf("a registration that succeeded removed orgs %v", h.idp.deletedOrgs)
	}
}

func TestRegister_RemovesTheOrgWhenTheOwnerCannotBeMade(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, errors.New("boom")
	}

	if _, err := h.srv.Register(context.Background(), registerRequest()); err == nil {
		t.Fatal("Register must fail when the owner cannot be made")
	}
	if len(h.idp.createdOrgs) != 1 || len(h.idp.deletedOrgs) != 1 {
		t.Fatalf("created %v, deleted %v; want the one org removed", h.idp.createdOrgs, h.idp.deletedOrgs)
	}
}
