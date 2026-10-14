package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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

func TestSignup_RemovesTheOwnerAndTheOrgWhenTheQueueRefuses(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	h.queue.insertErr = errors.New("postgres down")
	session := requestVerifiedSession(t, h, "team")

	if _, err := signupWithSession(t, h, session); err == nil {
		t.Fatal("Signup must fail when the tenant cannot be queued")
	}
	if len(h.idp.deletedUsers) != 1 || h.idp.deletedUsers[0] != "user-owner" {
		t.Fatalf("deleted users = %v, want the owner of the failed signup", h.idp.deletedUsers)
	}
	if len(h.idp.deletedOrgs) != 1 || h.idp.deletedOrgs[0] != "org-1" {
		t.Fatalf("deleted orgs = %v, want the org of the failed signup", h.idp.deletedOrgs)
	}
}

func TestAdminRejectRegistration_RemovesTheWorkspaceOrg(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	if _, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
		&tenantv1.AdminRejectRegistrationRequest{RegistrationId: regID, Reason: "not a colleague"}); err != nil {
		t.Fatalf("AdminRejectRegistration: %v", err)
	}
	if len(h.idp.createdOrgs) != 1 || len(h.idp.deletedOrgs) != 1 || h.idp.deletedOrgs[0] != "org-1" {
		t.Fatalf("created %v, deleted %v; want the org of the refused registration removed",
			h.idp.createdOrgs, h.idp.deletedOrgs)
	}
}

func TestSignup_OrgCreateFailuresMapToCodes(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	for _, tc := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{"unreachable", idp.ErrUnreachable, codes.Unavailable},
		{"other", errors.New("boom"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignupHarness(t)
			h.idp.createOrgFn = func(_ context.Context, _ string) (string, error) { return "", tc.err }
			session := requestVerifiedSession(t, h, "team")
			_, err := signupWithSession(t, h, session)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.want)
			}
			if len(h.idp.createHumanReqs) != 0 {
				t.Fatal("an owner was created with no org")
			}
		})
	}
}

func TestSignup_AFailedOrgCleanupStillFailsTheSignup(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, errors.New("boom")
	}
	h.idp.deleteOrgErr = errors.New("zitadel down")
	session := requestVerifiedSession(t, h, "team")
	if _, err := signupWithSession(t, h, session); status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
	if len(h.idp.deletedOrgs) != 1 {
		t.Fatalf("deleted orgs = %v, want one attempt", h.idp.deletedOrgs)
	}
}

func TestRegister_TakenOrgNameIsRefusedBeforeAnyAccount(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.createOrgFn = func(_ context.Context, _ string) (string, error) { return "", idp.ErrAlreadyExists }
	_, err := h.srv.Register(context.Background(), registerRequest())
	if got := status.Code(err); got != codes.AlreadyExists {
		t.Fatalf("code = %v (%v), want AlreadyExists", got, err)
	}
	if len(h.idp.createHumanReqs) != 0 {
		t.Fatal("an account was created for a taken workspace name")
	}
}

func TestAdminRejectRegistration_NeedsTheIdentityProvider(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	h.srv.idpAdminClient = nil
	_, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
		&tenantv1.AdminRejectRegistrationRequest{RegistrationId: regID, Reason: "x"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable: a reject with no IdP cannot free the workspace", status.Code(err))
	}
}

func TestAdminRejectRegistration_KeepsAnAccountOfThePlatformOrg(t *testing.T) {
	h, _ := newApprovalHarness(t)
	regID := registerPending(t, h)
	// The fake made org-1 for this registration. When that is the platform
	// org, the account predates the tenant org and nothing is deleted.
	t.Setenv(envIDPZitadelOrgID, "org-1")
	if _, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
		&tenantv1.AdminRejectRegistrationRequest{RegistrationId: regID, Reason: "x"}); err != nil {
		t.Fatalf("AdminRejectRegistration: %v", err)
	}
	if len(h.idp.deletedOrgs) != 0 {
		t.Fatalf("the platform org was deleted: %v", h.idp.deletedOrgs)
	}
}

func TestAdminRejectRegistration_ToleratesCleanupFailures(t *testing.T) {
	for name, set := range map[string]func(f *fakeIDPClient){
		"org lookup fails": func(f *fakeIDPClient) { f.orgOfUserErr = idp.ErrNotFound },
		"org delete fails": func(f *fakeIDPClient) { f.deleteOrgErr = errors.New("zitadel down") },
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newApprovalHarness(t)
			regID := registerPending(t, h)
			set(h.idp)
			if _, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
				&tenantv1.AdminRejectRegistrationRequest{RegistrationId: regID, Reason: "x"}); err != nil {
				t.Fatalf("the rejection is recorded even when the cleanup fails: %v", err)
			}
		})
	}
}
