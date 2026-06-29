package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

const testAttemptID = "11111111-2222-4333-8444-555555555555"

// newSignupServer creates a DaemonServer wired for the SaaS self-serve signup
// path (PolicySelfServe). All existing tests in this file exercise the
// self-serve flow and need the gate open. Tests that verify the gate itself
// (self-hosted fail-safe) live in signup_seam_gate_test.go and configure
// the policy explicitly.
func newSignupServer(t *testing.T, idpc *fakeIDPClient) *DaemonServer {
	t.Helper()
	s := &DaemonServer{logger: testSlogLogger}
	s.idpAdminClient = idpc
	// Enable self-serve so existing tests are not gated (SaaS profile).
	s.signupPolicy = signup.PolicySelfServe
	return s
}

func validSignupReq() *tenantv1.SignupRequest {
	return &tenantv1.SignupRequest{
		AttemptId:      testAttemptID,
		OwnerEmail:     "owner@example.com",
		WorkspaceName:  "Acme Red Team",
		Tier:           "team",
		OwnerFirstName: "Ada",
		OwnerLastName:  "Lovelace",
		Password:       "s3cret-passw0rd!",
	}
}

func TestSignup_HappyPath(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{UserID: "user-owner", AlreadyExisted: false}, nil
		},
	}
	s := newSignupServer(t, idpc)

	resp, err := s.Signup(context.Background(), validSignupReq())
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if resp.TenantId != "acme-red-team" {
		t.Errorf("TenantId = %q, want acme-red-team (slugified)", resp.TenantId)
	}
	if resp.AlreadyExisted {
		t.Errorf("AlreadyExisted = true, want false")
	}
	if resp.OwnerUserId != "user-owner" {
		t.Errorf("OwnerUserId = %q, want user-owner", resp.OwnerUserId)
	}
	if len(idpc.createHumanReqs) != 1 {
		t.Fatalf("expected 1 CreateHumanUser call, got %d", len(idpc.createHumanReqs))
	}
	req := idpc.createHumanReqs[0]
	if req.Email != "owner@example.com" || req.GivenName != "Ada" || req.FamilyName != "Lovelace" {
		t.Errorf("create req profile mismatch: %+v", req)
	}
	if req.Password != "s3cret-passw0rd!" {
		t.Errorf("password not forwarded to idp")
	}
	if !req.EmailVerified {
		t.Errorf("EmailVerified = false, want true (dashboard signup default)")
	}
	if len(idpc.sentVerificationFor) != 1 || idpc.sentVerificationFor[0] != "user-owner" {
		t.Errorf("expected verification email for user-owner, got %v", idpc.sentVerificationFor)
	}
}

func TestSignup_ResumeReturnsAlreadyExisted(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{UserID: "user-existing", AlreadyExisted: true}, nil
		},
	}
	s := newSignupServer(t, idpc)

	resp, err := s.Signup(context.Background(), validSignupReq())
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if !resp.AlreadyExisted {
		t.Errorf("AlreadyExisted = false, want true on resume")
	}
	if resp.OwnerUserId != "user-existing" {
		t.Errorf("OwnerUserId = %q", resp.OwnerUserId)
	}
}

func TestSignup_VerificationEmailErrorIsNonFatal(t *testing.T) {
	idpc := &fakeIDPClient{
		sendVerificationErr: errors.New("SMTP not configured"),
	}
	s := newSignupServer(t, idpc)

	resp, err := s.Signup(context.Background(), validSignupReq())
	if err != nil {
		t.Fatalf("Signup should succeed despite verification email error: %v", err)
	}
	if resp.TenantId == "" {
		t.Errorf("expected a tenant slug back")
	}
}

func TestSignup_Validation(t *testing.T) {
	s := newSignupServer(t, &fakeIDPClient{})

	cases := []struct {
		name   string
		mutate func(*tenantv1.SignupRequest)
	}{
		{"missing attempt_id", func(r *tenantv1.SignupRequest) { r.AttemptId = "" }},
		{"bad attempt_id", func(r *tenantv1.SignupRequest) { r.AttemptId = "not-a-uuid" }},
		{"missing email", func(r *tenantv1.SignupRequest) { r.OwnerEmail = "" }},
		{"missing workspace", func(r *tenantv1.SignupRequest) { r.WorkspaceName = "" }},
		{"missing tier", func(r *tenantv1.SignupRequest) { r.Tier = "" }},
		{"missing password", func(r *tenantv1.SignupRequest) { r.Password = "" }},
		{"workspace yields empty slug", func(r *tenantv1.SignupRequest) { r.WorkspaceName = "***" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validSignupReq()
			tc.mutate(req)
			_, err := s.Signup(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("want InvalidArgument, got %v", err)
			}
		})
	}
}

func TestSignup_IdPNotConfigured(t *testing.T) {
	// Set PolicySelfServe so the seam gate passes; we're testing the
	// idpAdminClient-nil code path that runs AFTER the gate check.
	s := &DaemonServer{
		logger:       testSlogLogger,
		signupPolicy: signup.PolicySelfServe, // gate open — testing past-gate behavior
		// idpAdminClient is nil — the handler should return Unavailable.
	}
	_, err := s.Signup(context.Background(), validSignupReq())
	if status.Code(err) != codes.Unavailable {
		t.Errorf("want Unavailable, got %v", err)
	}
}

func TestSignup_IdPUnreachableMapsUnavailable(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{}, idp.ErrUnreachable
		},
	}
	s := newSignupServer(t, idpc)
	_, err := s.Signup(context.Background(), validSignupReq())
	if status.Code(err) != codes.Unavailable {
		t.Errorf("want Unavailable, got %v", err)
	}
}

func TestSignup_IdPPermissionMapsInternal(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{}, idp.ErrPermission
		},
	}
	s := newSignupServer(t, idpc)
	_, err := s.Signup(context.Background(), validSignupReq())
	if status.Code(err) != codes.Internal {
		t.Errorf("want Internal, got %v", err)
	}
}

func TestSignupSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme Red Team":   "acme-red-team",
		"  Hello  World ": "hello-world",
		"a/b\\c":          "a-b-c",
		"--lead-trail--":  "lead-trail",
		"***":             "",
		"MiXeD":           "mixed",
	}
	for in, want := range cases {
		if got := signupSlugify(in); got != want {
			t.Errorf("signupSlugify(%q) = %q, want %q", in, got, want)
		}
	}
}
