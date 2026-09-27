// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// mfaResetTestIDP embeds fakeIDPClient (already satisfies idp.AdminClient)
// and overrides GetUserProfile so ResetUserMFA's notice-email path can be
// exercised — fakeIDPClient.GetUserProfile is hard-wired to idp.ErrNotFound
// for the tests that already depend on that shape.
type mfaResetTestIDP struct {
	*fakeIDPClient
	profile    *idp.UserProfile
	profileErr error
}

func (f *mfaResetTestIDP) GetUserProfile(_ context.Context, _ string) (*idp.UserProfile, error) {
	if f.profileErr != nil {
		return nil, f.profileErr
	}
	return f.profile, nil
}

// fakeMFAResetMailer records SendMFAReset calls.
type fakeMFAResetMailer struct {
	sent []mailer.MFAResetEmail
	err  error
}

func (f *fakeMFAResetMailer) SendMFAReset(_ context.Context, e mailer.MFAResetEmail) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, e)
	return nil
}

func resetMFAServer(az authzIface, idpC idp.AdminClient, mailerC mfaResetSender) *DaemonServer {
	srv := &DaemonServer{
		logger:         slog.Default(),
		authorizer:     az,
		idpAdminClient: idpC,
		appURL:         "https://app.example.com",
	}
	// Route through WithMFAResetMailer (rather than setting the field
	// directly) so the setter itself is exercised, matching production wiring
	// in grpc.go.
	srv.WithMFAResetMailer(mailerC)
	return srv
}

func TestResetUserMFA_AdminOverMember(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{
		fakeIDPClient: &fakeIDPClient{
			revokeResult:       idp.RevokeUserSessionsResult{SessionsTerminated: 3, GrantsRevoked: 3},
			clearFactorsResult: idp.ClearHumanFactorsResult{OTPCleared: true, U2FCleared: 2, PasskeysCleared: 1},
		},
		profile: &idp.UserProfile{Email: "bob@example.com"},
	}
	mailerC := &fakeMFAResetMailer{}
	srv := resetMFAServer(az, idpC, mailerC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	resp, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if resp.GetSessionsTerminated() != 3 {
		t.Errorf("SessionsTerminated = %d, want 3", resp.GetSessionsTerminated())
	}
	if !resp.GetOtpCleared() || resp.GetU2FCleared() != 2 || resp.GetPasskeysCleared() != 1 {
		t.Errorf("factor counts = %+v", resp)
	}
	if !resp.GetNotified() {
		t.Error("expected Notified=true")
	}
	if len(idpC.revokedUsers) != 1 || idpC.revokedUsers[0] != "bob" {
		t.Fatalf("expected RevokeUserSessions(bob), got %v", idpC.revokedUsers)
	}
	if len(idpC.clearedFactorsUsers) != 1 || idpC.clearedFactorsUsers[0] != "bob" {
		t.Fatalf("expected ClearHumanFactors(bob), got %v", idpC.clearedFactorsUsers)
	}
	if len(mailerC.sent) != 1 {
		t.Fatalf("expected exactly one email sent, got %d", len(mailerC.sent))
	}
	// The email goes to the RESET USER's own address, never to the caller.
	if mailerC.sent[0].To != "bob@example.com" {
		t.Errorf("email To = %q, want bob@example.com (never the acting admin)", mailerC.sent[0].To)
	}
	if mailerC.sent[0].SignInURL != "https://app.example.com/login" {
		t.Errorf("SignInURL = %q", mailerC.sent[0].SignInURL)
	}
}

func TestResetUserMFA_OwnerCanResetOwnMFA(t *testing.T) {
	// Scope: "including the Owner's". The Owner holds admin (owner implies
	// admin in model.fga) and is themselves a tenant member.
	az := newFakeAuthorizer().allow("user:owner1", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}
	srv := resetMFAServer(az, idpC, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "owner1")

	if _, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "owner1"}); err != nil {
		t.Fatalf("owner resetting their own MFA: %v", err)
	}
	if len(idpC.revokedUsers) != 1 || idpC.revokedUsers[0] != "owner1" {
		t.Fatalf("expected RevokeUserSessions(owner1), got %v", idpC.revokedUsers)
	}
}

// TestResetUserMFA_CrossTenantTargetDenied is the acceptance test named in
// hosted#206: a tenant-B admin cannot reset a tenant-A user. The coarse
// ext-authz gate already proves the caller is admin of THEIR OWN tenant
// (acme); the handler's own FGA "member" check on tenant:acme is what
// refuses a target who belongs only to a different tenant.
func TestResetUserMFA_CrossTenantTargetDenied(t *testing.T) {
	az := newFakeAuthorizer().allow("user:eve", "member", "tenant:beta") // NOT acme
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}
	srv := resetMFAServer(az, idpC, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "eve"})
	if status_grpc.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
	if len(idpC.revokedUsers) != 0 || len(idpC.clearedFactorsUsers) != 0 {
		t.Fatalf("IdP must NOT be touched when the target is not in the caller's tenant: revoked=%v cleared=%v",
			idpC.revokedUsers, idpC.clearedFactorsUsers)
	}
}

func TestResetUserMFA_MissingTarget(t *testing.T) {
	srv := resetMFAServer(newFakeAuthorizer(), &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestResetUserMFA_NoIdentity(t *testing.T) {
	srv := resetMFAServer(newFakeAuthorizer(), &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}, nil)

	_, err := srv.ResetUserMFA(context.Background(), &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestResetUserMFA_NoIdPConfigured(t *testing.T) {
	srv := &DaemonServer{logger: slog.Default(), authorizer: newFakeAuthorizer()}
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

func TestResetUserMFA_NoAuthorizerConfigured(t *testing.T) {
	srv := &DaemonServer{logger: slog.Default(), idpAdminClient: &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}}
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

func TestResetUserMFA_RevokeSessionsError(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{revokeErr: errBoom}}
	srv := resetMFAServer(az, idpC, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
	// A revoke failure must not proceed to clear factors.
	if len(idpC.clearedFactorsUsers) != 0 {
		t.Errorf("ClearHumanFactors must not run after a revoke failure, got %v", idpC.clearedFactorsUsers)
	}
}

func TestResetUserMFA_ClearFactorsError(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{clearFactorsErr: errBoom}}
	srv := resetMFAServer(az, idpC, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

// TestResetUserMFA_NoMailerConfigured proves the reset still completes and
// simply reports notified=false when no mail transport is wired.
func TestResetUserMFA_NoMailerConfigured(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profile: &idp.UserProfile{Email: "bob@example.com"}}
	srv := resetMFAServer(az, idpC, nil) // no mailer
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	resp, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if resp.GetNotified() {
		t.Error("expected Notified=false with no mailer configured")
	}
}

// TestResetUserMFA_NoEmailOnFile proves a directory miss degrades to
// notified=false rather than failing the whole (already-completed) reset.
func TestResetUserMFA_NoEmailOnFile(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profileErr: idp.ErrNotFound}
	mailerC := &fakeMFAResetMailer{}
	srv := resetMFAServer(az, idpC, mailerC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	resp, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if resp.GetNotified() {
		t.Error("expected Notified=false when the profile lookup fails")
	}
	if len(mailerC.sent) != 0 {
		t.Errorf("expected no email sent, got %v", mailerC.sent)
	}
}

// TestResetUserMFA_CallerNeverReceivesNotice proves the acting admin is
// never the recipient, even when the admin and target share a tenant and
// the admin's own email happens to resolve.
func TestResetUserMFA_CallerNeverReceivesNotice(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profile: &idp.UserProfile{Email: "bob@example.com"}}
	mailerC := &fakeMFAResetMailer{}
	srv := resetMFAServer(az, idpC, mailerC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	for _, sent := range mailerC.sent {
		if sent.To == "admin1" {
			t.Fatalf("the acting admin must never receive the reset notice, got To=%q", sent.To)
		}
	}
}

// TestResetUserMFA_MailerSendFails proves a transport failure while sending
// the notice degrades to notified=false (the reset itself already
// succeeded) rather than failing the whole call or panicking.
func TestResetUserMFA_MailerSendFails(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profile: &idp.UserProfile{Email: "bob@example.com"}}
	mailerC := &fakeMFAResetMailer{err: errBoom}
	srv := resetMFAServer(az, idpC, mailerC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	resp, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if resp.GetNotified() {
		t.Error("expected Notified=false when the mail transport fails")
	}
}

// TestResetUserMFA_SignInLinkUsesPublicAppURLNeverIssuer guards against the
// exact class of bug found and fixed in gibson#254 for the Platform-owner
// setup link (built there from spec.zitadel.issuer, the in-cluster URL, so
// the emailed link pointed nowhere a browser could reach). ResetUserMFA's
// link must come from s.appURL (GIBSON_APP_URL, the public product-surface
// origin) and must never be influenced by gibsonPublicURL (the API-plane
// origin) or any Zitadel issuer value, neither of which this handler even
// has a field path to reach.
func TestResetUserMFA_SignInLinkUsesPublicAppURLNeverIssuer(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profile: &idp.UserProfile{Email: "bob@example.com"}}
	mailerC := &fakeMFAResetMailer{}
	srv := resetMFAServer(az, idpC, mailerC)
	// Deliberately set the API-plane origin to a value that would produce an
	// unreachable link if it ever leaked into the sign-in URL, so this test
	// fails loudly if a future edit reintroduces that bug.
	srv.gibsonPublicURL = "https://internal-cluster-only.invalid"
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if len(mailerC.sent) != 1 {
		t.Fatalf("expected one email sent, got %d", len(mailerC.sent))
	}
	const wantPrefix = "https://app.example.com/"
	got := mailerC.sent[0].SignInURL
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("SignInURL = %q, want it to start with the public app URL %q, never the internal/API-plane origin", got, wantPrefix)
	}
}
