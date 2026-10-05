// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/alicebob/miniredis/v2"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
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
	// profiles answers per user id when set, so a test can give the caller
	// and the target different addresses and tell them apart in the mail.
	profiles map[string]*idp.UserProfile
}

func (f *mfaResetTestIDP) GetUserProfile(_ context.Context, userID string) (*idp.UserProfile, error) {
	if f.profileErr != nil {
		return nil, f.profileErr
	}
	if p, ok := f.profiles[userID]; ok {
		return p, nil
	}
	return f.profile, nil
}

// testAuditLogger is an AuditLogger over an in-process miniredis, the same
// shape production wires (grpc.go). ResetUserMFA refuses to run without one.
func testAuditLogger(t *testing.T) *audit.AuditLogger {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatalf("state client against miniredis: %v", err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return audit.NewAuditLogger(ctx, sc, &audittest.Recorder{}, slog.Default())
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

func resetMFAServer(t *testing.T, az authzIface, idpC idp.AdminClient, mailerC mfaResetSender) *DaemonServer {
	t.Helper()
	srv := &DaemonServer{
		logger:         slog.Default(),
		authorizer:     az,
		idpAdminClient: idpC,
		appURL:         "https://app.example.com",
	}
	// Route through the setters (rather than setting the fields directly) so
	// the setters themselves are exercised, matching production wiring in
	// grpc.go.
	srv.WithMFAResetMailer(mailerC)
	srv.WithAuditLogger(testAuditLogger(t))
	return srv
}

// TestResetUserMFA_RefusesWithoutAuditLog: a reset without its record is not
// performed (hosted#206). Nothing is revoked and nobody is mailed.
func TestResetUserMFA_RefusesWithoutAuditLog(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profile: &idp.UserProfile{Email: "bob@example.com"}}
	mailerC := &fakeMFAResetMailer{}
	srv := &DaemonServer{logger: slog.Default(), authorizer: az, idpAdminClient: idpC, appURL: "https://app.example.com"}
	srv.WithMFAResetMailer(mailerC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable without an audit log, got %v", err)
	}
	if len(mailerC.sent) != 0 {
		t.Fatalf("expected no notice when the reset was refused, got %v", mailerC.sent)
	}
}

// TestResetUserMFA_WritesAuditRecord reads the record back from the stream:
// who reset whom, in which tenant, with the counts the reset reported.
func TestResetUserMFA_WritesAuditRecord(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{
		fakeIDPClient: &fakeIDPClient{
			revokeResult:       idp.RevokeUserSessionsResult{SessionsTerminated: 2, GrantsRevoked: 2},
			clearFactorsResult: idp.ClearHumanFactorsResult{OTPCleared: true, PasskeysCleared: 1},
		},
		profile: &idp.UserProfile{Email: "bob@example.com"},
	}
	srv := resetMFAServer(t, az, idpC, &fakeMFAResetMailer{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}

	// The logger writes asynchronously; give the drain loop a moment.
	var entries []audit.AuditEntry
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		entries, err = srv.auditLogger.Query(context.Background(), "acme", audit.AuditQueryOptions{Action: auditActionTenantUserMFAReset, Limit: 10})
		if err != nil {
			t.Fatalf("audit Query: %v", err)
		}
		if len(entries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one %s record for tenant acme, got %d", auditActionTenantUserMFAReset, len(entries))
	}
	e := entries[0]
	if e.ActorID != "admin1" || e.Resource != "user" || e.ResourceID != "bob" {
		t.Errorf("record = actor %q resource %q/%q, want admin1 user/bob", e.ActorID, e.Resource, e.ResourceID)
	}
	if e.Details["target_user_id"] != "bob" {
		t.Errorf("details.target_user_id = %v, want bob", e.Details["target_user_id"])
	}
	if e.Details["notified"] != true {
		t.Errorf("details.notified = %v, want true", e.Details["notified"])
	}
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
	srv := resetMFAServer(t, az, idpC, mailerC)
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
	srv := resetMFAServer(t, az, idpC, nil)
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
	srv := resetMFAServer(t, az, idpC, nil)
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
	srv := resetMFAServer(t, newFakeAuthorizer(), &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestResetUserMFA_NoIdentity(t *testing.T) {
	srv := resetMFAServer(t, newFakeAuthorizer(), &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}, nil)

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
	srv := resetMFAServer(t, az, idpC, nil)
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
	srv := resetMFAServer(t, az, idpC, nil)
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
	srv := resetMFAServer(t, az, idpC, nil) // no mailer
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
	srv := resetMFAServer(t, az, idpC, mailerC)
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
	// The caller and the target both resolve to an address, so a wrong
	// recipient would be visible. The old form compared against the user id
	// "admin1", which no mail ever carries, so it could not fail.
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profiles: map[string]*idp.UserProfile{
		"admin1": {Email: "admin1@example.com"},
		"bob":    {Email: "bob@example.com"},
	}}
	mailerC := &fakeMFAResetMailer{}
	srv := resetMFAServer(t, az, idpC, mailerC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if len(mailerC.sent) != 1 {
		t.Fatalf("expected exactly one notice, got %d: %v", len(mailerC.sent), mailerC.sent)
	}
	if got := mailerC.sent[0].To; got != "bob@example.com" {
		t.Fatalf("the notice must go to the target only, got To=%q", got)
	}
}

// TestResetUserMFA_MailerSendFails proves a transport failure while sending
// the notice degrades to notified=false (the reset itself already
// succeeded) rather than failing the whole call or panicking.
func TestResetUserMFA_MailerSendFails(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profile: &idp.UserProfile{Email: "bob@example.com"}}
	mailerC := &fakeMFAResetMailer{err: errBoom}
	srv := resetMFAServer(t, az, idpC, mailerC)
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
	srv := resetMFAServer(t, az, idpC, mailerC)
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

// TestResetUserMFA_StampsSessionRevocation pins that a reset refuses the
// target's already-issued tokens: ending the IdP sessions does not end a
// signed JWT, so the reset must also advance both active_session tuples
// (hosted#208: the invitee's pre-reset token was still ACCEPTED).
func TestResetUserMFA_StampsSessionRevocation(t *testing.T) {
	az := newConditionalFakeAuthorizer()
	az.allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}
	srv := resetMFAServer(t, az, idpC, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	got := objectsOf(az.written())
	want := []string{"user:bob", "tenant:acme"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stamped objects = %v, want %v", got, want)
	}
	for _, tu := range az.written() {
		if tu.User != "user:bob" || tu.Relation != "active_session" {
			t.Errorf("stamped %s %s %s, want user:bob active_session", tu.User, tu.Relation, tu.Object)
		}
	}
}

// TestResetUserMFA_StampFailureIsInternal pins that a reset whose revocation
// stamp fails reports an error rather than a success that leaves the old
// tokens valid.
func TestResetUserMFA_StampFailureIsInternal(t *testing.T) {
	base := newConditionalFakeAuthorizer()
	base.allow("user:bob", "member", "tenant:acme")
	az := &conditionalFakeAuthorizerWithError{conditionalFakeAuthorizer: base, updateErr: errors.New("fga boom")}
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}}
	srv := resetMFAServer(t, az, idpC, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	_, err := srv.ResetUserMFA(ctx, &tenantv1.ResetUserMFARequest{TargetUserId: "bob"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("ResetUserMFA code = %v (err=%v), want Internal", status_grpc.Code(err), err)
	}
	if len(idpC.clearedFactorsUsers) != 0 {
		t.Errorf("factors cleared for %v after a failed revocation stamp, want none", idpC.clearedFactorsUsers)
	}
}
