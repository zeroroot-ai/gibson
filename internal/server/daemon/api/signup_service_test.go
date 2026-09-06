// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_service_test.go — behavioural tests for SignupService.
//
// The three properties under test, in the order the flow enforces them:
//
//  1. A signup request for an address that already has an account discloses
//     nothing to the requester and changes nothing about that account.
//  2. Provisioning is unreachable without a redeemed verification token.
//  3. The verification token is single-use and expires; so does the completion
//     session derived from it.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/plans"
	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

const testAttemptID = "11111111-2222-4333-8444-555555555555"

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeSignupMailer records which of the two messages was sent, and to whom.
type fakeSignupMailer struct {
	verifications []mailer.VerificationEmail
	collisions    []mailer.AccountExistsEmail
	err           error
}

func (f *fakeSignupMailer) SendSignupVerification(_ context.Context, v mailer.VerificationEmail) error {
	if f.err != nil {
		return f.err
	}
	f.verifications = append(f.verifications, v)
	return nil
}

func (f *fakeSignupMailer) SendAccountExists(_ context.Context, a mailer.AccountExistsEmail) error {
	if f.err != nil {
		return f.err
	}
	f.collisions = append(f.collisions, a)
	return nil
}

// allowAllLimiter admits everything. Limiter behaviour has its own tests; these
// tests are about ordering and disclosure.
type allowAllLimiter struct{ calls int }

func (l *allowAllLimiter) Peek(_ context.Context, _ string, _ ratelimit.Window) error {
	return nil
}

func (l *allowAllLimiter) Check(_ context.Context, _ string, _ ratelimit.Window) error {
	l.calls++
	return nil
}

// denyLimiter reports every key as exhausted.
type denyLimiter struct{}

func (denyLimiter) Peek(_ context.Context, _ string, _ ratelimit.Window) error {
	return ratelimit.ErrRateLimited
}

func (denyLimiter) Check(_ context.Context, _ string, _ ratelimit.Window) error {
	return ratelimit.ErrRateLimited
}

// brokenLimiter simulates an unreachable Redis, to prove the surface fails
// closed rather than falling open.
type brokenLimiter struct{}

func (brokenLimiter) Peek(_ context.Context, _ string, _ ratelimit.Window) error {
	return ratelimit.ErrLimiterUnavailable
}

func (brokenLimiter) Check(_ context.Context, _ string, _ ratelimit.Window) error {
	return ratelimit.ErrLimiterUnavailable
}

// memVerificationStore is an in-memory signupVerificationStore that models the
// same predicates the SQL enforces: redemption requires status=pending and an
// unexpired row, completion requires a live session under the attempt cap.
//
// It exists so handler tests can exercise ordering without a database. The real
// store's statements are pinned separately in signup_verification_store_test.go.
type memVerificationStore struct {
	rows map[string]*memRow // keyed by row id
	// tokens/sessions map raw values to row ids, standing in for the hash
	// indexes.
	tokens          map[string]string
	sessions        map[string]string
	now             func() time.Time
	issueErr        error
	purgeErr        error
	lastSentErr     error
	redeemErr       error
	attachErr       error
	claimErr        error
	markConsumedErr error
}

type memRow struct {
	SignupVerification
	status         string
	sessionExpires time.Time
	lastSent       time.Time
	sentOnce       bool
}

func newMemStore() *memVerificationStore {
	return &memVerificationStore{
		rows:     map[string]*memRow{},
		tokens:   map[string]string{},
		sessions: map[string]string{},
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (m *memVerificationStore) Issue(_ context.Context, p IssueParams) (SignupVerification, string, error) {
	if m.issueErr != nil {
		return SignupVerification{}, "", m.issueErr
	}
	id := p.Email + "|" + p.AttemptID
	raw := "tok-" + id
	m.rows[id] = &memRow{
		SignupVerification: SignupVerification{
			ID: id, AttemptID: p.AttemptID, Email: p.Email,
			WorkspaceName: p.WorkspaceName, Tier: p.Tier,
			OwnerFirstName: p.OwnerFirstName, OwnerLastName: p.OwnerLastName,
			ExpiresAt: m.now().Add(SignupVerificationTTL),
		},
		status: signupStatusPending,
	}
	m.tokens[raw] = id
	return m.rows[id].SignupVerification, raw, nil
}

func (m *memVerificationStore) MarkSent(_ context.Context, id string) error {
	if r, ok := m.rows[id]; ok {
		r.lastSent = m.now()
		r.sentOnce = true
	}
	return nil
}

func (m *memVerificationStore) MarkSendFailed(_ context.Context, id string) error {
	if r, ok := m.rows[id]; ok && r.status == signupStatusPending {
		r.status = signupStatusSendFailed
	}
	return nil
}

func (m *memVerificationStore) MarkConsumedByID(_ context.Context, id string) error {
	if r, ok := m.rows[id]; ok && r.status == signupStatusPending {
		r.status = signupStatusConsumed
	}
	return nil
}

func (m *memVerificationStore) LastSentAt(_ context.Context, email string) (time.Time, bool, error) {
	if m.lastSentErr != nil {
		return time.Time{}, false, m.lastSentErr
	}
	var newest time.Time
	found := false
	for _, r := range m.rows {
		if r.Email == email && r.sentOnce && r.lastSent.After(newest) {
			newest, found = r.lastSent, true
		}
	}
	return newest, found, nil
}

func (m *memVerificationStore) RedeemToken(_ context.Context, raw string) (SignupVerification, string, error) {
	if m.redeemErr != nil {
		return SignupVerification{}, "", m.redeemErr
	}
	id, ok := m.tokens[raw]
	if !ok {
		return SignupVerification{}, "", ErrSignupVerificationNotFound
	}
	r := m.rows[id]
	// The same predicate the SQL uses: only a pending, unexpired row redeems.
	if r.status != signupStatusPending || !r.ExpiresAt.After(m.now()) {
		return SignupVerification{}, "", ErrSignupVerificationNotFound
	}
	r.status = signupStatusVerified
	session := "sess-" + id
	r.sessionExpires = m.now().Add(SignupSessionTTL)
	m.sessions[session] = id
	return r.SignupVerification, session, nil
}

func (m *memVerificationStore) liveSession(raw string) (*memRow, bool) {
	id, ok := m.sessions[raw]
	if !ok {
		return nil, false
	}
	r := m.rows[id]
	if r.status != signupStatusVerified || !r.sessionExpires.After(m.now()) {
		return nil, false
	}
	return r, true
}

func (m *memVerificationStore) GetByVerifiedSession(_ context.Context, raw string) (SignupVerification, error) {
	r, ok := m.liveSession(raw)
	if !ok {
		return SignupVerification{}, ErrSignupVerificationNotFound
	}
	return r.SignupVerification, nil
}

func (m *memVerificationStore) AttachStripeCustomer(_ context.Context, raw, customerID string) error {
	if m.attachErr != nil {
		return m.attachErr
	}
	r, ok := m.liveSession(raw)
	if !ok {
		return ErrSignupVerificationNotFound
	}
	// Mirrors the two binding predicates the real UPDATE carries (pinned by
	// TestAttachStripeCustomer_BindsTheCustomerToTheSession): one customer per
	// session, and one session per customer. The model is only worth testing
	// handlers against while it agrees with the statement.
	if r.StripeCustomerID != "" && r.StripeCustomerID != customerID {
		return ErrSignupVerificationNotFound
	}
	for _, other := range m.rows {
		if other != r && other.StripeCustomerID == customerID {
			return ErrSignupVerificationNotFound
		}
	}
	r.StripeCustomerID = customerID
	return nil
}

func (m *memVerificationStore) ClaimCompletion(_ context.Context, raw string) (SignupVerification, error) {
	if m.claimErr != nil {
		return SignupVerification{}, m.claimErr
	}
	r, ok := m.liveSession(raw)
	if !ok || r.CompletionCount >= SignupMaxCompletionAttempts {
		return SignupVerification{}, ErrSignupVerificationNotFound
	}
	r.CompletionCount++
	return r.SignupVerification, nil
}

func (m *memVerificationStore) MarkConsumed(_ context.Context, raw string) error {
	if m.markConsumedErr != nil {
		return m.markConsumedErr
	}
	r, ok := m.liveSession(raw)
	if !ok {
		return ErrSignupVerificationNotFound
	}
	r.status = signupStatusConsumed
	return nil
}

func (m *memVerificationStore) PurgeExpired(_ context.Context) (expired, deleted int64, err error) {
	if m.purgeErr != nil {
		return 0, 0, m.purgeErr
	}
	for _, r := range m.rows {
		if (r.status == signupStatusPending || r.status == signupStatusVerified) && !r.ExpiresAt.After(m.now()) {
			r.status = signupStatusExpired
			expired++
		}
	}
	return expired, deleted, nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type signupHarness struct {
	srv    *DaemonServer
	store  *memVerificationStore
	mail   *fakeSignupMailer
	idp    *fakeIDPClient
	clock  func() time.Time
	nowPtr *time.Time
}

func newSignupHarness(t *testing.T) *signupHarness {
	t.Helper()
	now := time.Now().UTC()
	h := &signupHarness{
		store:  newMemStore(),
		mail:   &fakeSignupMailer{},
		idp:    &fakeIDPClient{},
		nowPtr: &now,
	}
	h.clock = func() time.Time { return *h.nowPtr }
	h.store.now = h.clock

	h.srv = &DaemonServer{logger: testSlogLogger}
	h.srv.signupPolicy = signup.PolicySelfServe
	h.srv.idpAdminClient = h.idp
	h.srv.signupClock = h.clock
	// The API-plane origin and the product-surface origin are DIFFERENT hosts.
	// Setting both distinctly here is what lets the link assertions below catch
	// a regression back to building user-facing links from the API origin,
	// where the route does not exist.
	h.srv.gibsonPublicURL = "https://api.example.test"
	h.srv.WithAppURL("https://app.example.test")
	h.srv.WithSignupVerificationStore(h.store).
		WithSignupMailer(h.mail).
		WithSignupLimiter(&allowAllLimiter{})
	return h
}

// advance moves the harness clock forward.
func (h *signupHarness) advance(d time.Duration) { *h.nowPtr = h.nowPtr.Add(d) }

// tokenFromLink recovers the raw token the way a recipient's browser would:
// by reading the query string of the mailed URL.
//
// Deliberately not by reaching into the store. The token has to survive the
// round trip through a URL to be usable at all, and a test that skipped that
// step would not notice an escaping bug that makes every emailed link dead.
func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse continue URL %q: %v", link, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("continue URL carries no token: %q", link)
	}
	return tok
}

func validRequestReq() *tenantv1.RequestEmailVerificationRequest {
	return &tenantv1.RequestEmailVerificationRequest{
		AttemptId:      testAttemptID,
		OwnerEmail:     "owner@example.com",
		WorkspaceName:  "Acme Red Team",
		Tier:           "team",
		OwnerFirstName: "Ada",
		OwnerLastName:  "Lovelace",
		ClientIp:       "203.0.113.7",
	}
}

// validSignupReq is kept for the seam-gate tests, which only exercise the
// policy gate that runs before anything else.
func validSignupReq() *tenantv1.SignupRequest {
	return &tenantv1.SignupRequest{
		AttemptId:            testAttemptID,
		VerifiedSessionToken: "sess-owner@example.com|" + testAttemptID,
		Password:             "s3cret-passw0rd!",
		ClientIp:             "203.0.113.7",
	}
}

// TestEmailedLinksTargetTheProductSurface — the link has to land somewhere a
// person can actually complete the signup.
//
// The daemon knows two public origins and they are different hosts: the API
// plane (api.<domain>), which serves gRPC-over-Envoy and 404s every product
// path, and the product surface (app.<domain>), which serves the signup pages.
// Building the user-facing link from the first one produced a link nobody could
// use, and pushed the token through an edge that access-logs request paths.
//
// The path is pinned too. SignupVerifyPath must name a route the dashboard
// serves; a rename on either side without the other is a total signup outage,
// so it is asserted here rather than left to a deploy to discover.
func TestEmailedLinksTargetTheProductSurface(t *testing.T) {
	h := newSignupHarness(t)
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	link := h.mail.verifications[0].ContinueURL

	if !strings.HasPrefix(link, "https://app.example.test/") {
		t.Errorf("verification link = %q, want the product-surface origin", link)
	}
	if strings.Contains(link, "api.example.test") {
		t.Errorf("verification link points at the API plane: %q", link)
	}
	if !strings.HasPrefix(link, "https://app.example.test"+SignupVerifyPath+"?token=") {
		t.Errorf("verification link = %q, want %q with a token query", link, SignupVerifyPath)
	}

	// The account-exists notice carries no token, but its links must reach the
	// product surface for the same reason.
	h2 := newSignupHarness(t)
	h2.idp.findUserFn = func(_ context.Context, _ string) (string, error) { return "user-existing", nil }
	if _, err := h2.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if len(h2.mail.collisions) != 1 {
		t.Fatalf("expected one account-exists notice, got %d", len(h2.mail.collisions))
	}
	for _, u := range []string{h2.mail.collisions[0].SignInURL, h2.mail.collisions[0].PasswordReset} {
		if !strings.HasPrefix(u, "https://app.example.test/") {
			t.Errorf("notice link = %q, want the product-surface origin", u)
		}
	}
}

// requestAndRedeem walks the happy path up to a live completion session.
func (h *signupHarness) requestAndRedeem(t *testing.T) string {
	t.Helper()
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if len(h.mail.verifications) != 1 {
		t.Fatalf("expected one verification email, got %d", len(h.mail.verifications))
	}
	// The raw token only ever exists in the link. Recover it the way the
	// recipient would: by opening the URL that was mailed.
	token := tokenFromLink(t, h.mail.verifications[0].ContinueURL)

	resp, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{
		Token: token, ClientIp: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("RedeemEmailVerification: %v", err)
	}
	return resp.GetVerifiedSessionToken()
}

// ---------------------------------------------------------------------------
// (a) An existing address is neither disclosed nor modified
// ---------------------------------------------------------------------------

// TestRequestEmailVerification_ExistingAddressIsNotDisclosed proves the two
// halves of the disclosure property at once:
//
//   - the response bytes are IDENTICAL for an address that has an account and
//     one that does not, and
//   - the existing account is never touched: no CreateHumanUser call, so no
//     password write of any kind.
//
// The response comparison is on the marshalled message rather than on named
// fields, so adding a field that varies by branch fails this test rather than
// slipping past it.
func TestRequestEmailVerification_ExistingAddressIsNotDisclosed(t *testing.T) {
	// Branch 1: no account for this address.
	fresh := newSignupHarness(t)
	freshResp, freshErr := fresh.srv.RequestEmailVerification(context.Background(), validRequestReq())
	if freshErr != nil {
		t.Fatalf("unregistered address: %v", freshErr)
	}

	// Branch 2: the address already has an account.
	taken := newSignupHarness(t)
	taken.idp.findUserFn = func(_ context.Context, _ string) (string, error) {
		return "user-existing", nil
	}
	takenResp, takenErr := taken.srv.RequestEmailVerification(context.Background(), validRequestReq())
	if takenErr != nil {
		t.Fatalf("registered address: %v", takenErr)
	}

	freshBytes, err := proto.Marshal(freshResp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	takenBytes, err := proto.Marshal(takenResp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(freshBytes, takenBytes) {
		t.Errorf("responses differ between an unregistered and a registered address:\n unregistered=%v\n registered=%v",
			freshBytes, takenBytes)
	}

	// Both branches perform one directory lookup and send exactly one message,
	// so they are alike in shape as well as in payload.
	if len(fresh.idp.findUserCalls) != 1 || len(taken.idp.findUserCalls) != 1 {
		t.Errorf("lookup counts differ: unregistered=%d registered=%d",
			len(fresh.idp.findUserCalls), len(taken.idp.findUserCalls))
	}
	if got := len(fresh.mail.verifications) + len(fresh.mail.collisions); got != 1 {
		t.Errorf("unregistered address: sent %d messages, want 1", got)
	}
	if got := len(taken.mail.verifications) + len(taken.mail.collisions); got != 1 {
		t.Errorf("registered address: sent %d messages, want 1", got)
	}

	// The disclosure that an account exists goes to the mailbox, and only there.
	if len(taken.mail.collisions) != 1 {
		t.Fatalf("registered address should receive the account-exists notice, got %+v", taken.mail)
	}
	if len(taken.mail.verifications) != 0 {
		t.Errorf("registered address must not receive a verification link")
	}

	// THE credential property: nothing about the existing account changed.
	// CreateHumanUser is the only call that carries a password, and it is never
	// reached on this path.
	if len(taken.idp.createHumanReqs) != 0 {
		t.Errorf("a signup for an existing address reached the credential path: %+v", taken.idp.createHumanReqs)
	}
}

// TestRequestEmailVerification_CollisionNoticeCarriesNoToken proves the
// account-exists notice cannot be used to take over the account it describes:
// it has no continue link, and the row it was issued against is retired so its
// token can never be redeemed.
func TestRequestEmailVerification_CollisionNoticeCarriesNoToken(t *testing.T) {
	h := newSignupHarness(t)
	h.idp.findUserFn = func(_ context.Context, _ string) (string, error) { return "user-existing", nil }

	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	notice := h.mail.collisions[0]
	if notice.SignInURL == "" {
		t.Errorf("the notice should point at sign-in")
	}

	// The token generated for the retired row must not redeem.
	raw := "tok-owner@example.com|" + testAttemptID
	if _, _, err := h.store.RedeemToken(context.Background(), raw); !errors.Is(err, ErrSignupVerificationNotFound) {
		t.Errorf("the collision row's token redeemed; want not-redeemable, got %v", err)
	}
}

// TestSignup_ExistingAddressWritesNoPassword covers the race the flow cannot
// prevent: the address acquires an account between the verification email and
// completion. The RPC must fail and must not write the submitted password onto
// the pre-existing account.
func TestSignup_ExistingAddressWritesNoPassword(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)

	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, idp.ErrAlreadyExists
	}

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId:            testAttemptID,
		VerifiedSessionToken: session,
		Password:             "some-passw0rd!",
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("status = %v, want AlreadyExists", err)
	}
	// The one call that carries a password was rejected by the IdP; the daemon
	// makes no follow-up call to set it by another route.
	if len(h.idp.createHumanReqs) != 1 {
		t.Errorf("CreateHumanUser calls = %d, want exactly 1", len(h.idp.createHumanReqs))
	}
}

// ---------------------------------------------------------------------------
// (b) Provisioning is unreachable without verification
// ---------------------------------------------------------------------------

// TestSignup_RequiresVerifiedSession proves the ordering rule: every route into
// Signup that lacks a redeemed token is denied BEFORE any identity is created
// and before anything is enqueued.
func TestSignup_RequiresVerifiedSession(t *testing.T) {
	cases := []struct {
		name    string
		session string
	}{
		{"no session at all", ""},
		{"fabricated session", "sess-not-a-real-session"},
		{"session for another attempt", "sess-someone-else@example.com|" + testAttemptID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignupHarness(t)
			_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
				AttemptId:            testAttemptID,
				VerifiedSessionToken: tc.session,
				Password:             "s3cret-passw0rd!",
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("status = %v, want PermissionDenied", err)
			}
			if len(h.idp.createHumanReqs) != 0 {
				t.Errorf("an unverified signup reached identity creation: %+v", h.idp.createHumanReqs)
			}
		})
	}
}

// TestRequestEmailVerification_CreatesNothingButTheRowAndTheMail pins the other
// half of the ordering rule: the FIRST phase must not create an identity. Every
// expensive artefact now sits behind redemption.
func TestRequestEmailVerification_CreatesNothingButTheRowAndTheMail(t *testing.T) {
	h := newSignupHarness(t)
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if len(h.idp.createHumanReqs) != 0 {
		t.Errorf("phase 1 created an identity: %+v", h.idp.createHumanReqs)
	}
	if len(h.store.rows) != 1 {
		t.Errorf("rows = %d, want exactly one verification row", len(h.store.rows))
	}
	if len(h.mail.verifications) != 1 {
		t.Errorf("expected exactly one verification email")
	}
}

// TestSignup_SessionOverridesClientSuppliedIdentity proves the completion RPC
// takes the owner address and workspace from the verification row, not from the
// caller. The request message has no field for either — this test locks that in
// by asserting the values reaching the IdP came from the row.
func TestSignup_SessionOverridesClientSuppliedIdentity(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}

	resp, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId:            testAttemptID,
		VerifiedSessionToken: session,
		Password:             "s3cret-passw0rd!",
	})
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if resp.GetTenantId() != "acme-red-team" {
		t.Errorf("TenantId = %q, want the slug derived from the verified row", resp.GetTenantId())
	}
	// The response must carry the RESOLVED canonical plan id (gibson#1325), not
	// the raw "team" verification-row string echoed back: it is the id the gate
	// accepted and the operator was enqueued with, so the caller bills on the
	// same id by construction instead of re-deriving the tier itself.
	wantPlan, ok := plans.Lookup("team")
	if !ok {
		t.Fatal("plans.Lookup(\"team\") missing — test fixture out of sync with the plan set")
	}
	if resp.GetPlanId() != wantPlan.ID {
		t.Errorf("PlanId = %q, want the resolved plan id %q", resp.GetPlanId(), wantPlan.ID)
	}
	if len(h.idp.createHumanReqs) != 1 {
		t.Fatalf("CreateHumanUser calls = %d", len(h.idp.createHumanReqs))
	}
	got := h.idp.createHumanReqs[0]
	if got.Email != "owner@example.com" {
		t.Errorf("Email = %q, want the verified address", got.Email)
	}
	if !got.EmailVerified {
		t.Errorf("EmailVerified = false; the address WAS verified by this flow, so the claim to the IdP should say so")
	}
	if got.GivenName != "Ada" || got.FamilyName != "Lovelace" {
		t.Errorf("profile came from somewhere other than the verified row: %+v", got)
	}
}

// TestSignup_EnqueueFailureIsFatal proves an enqueue miss fails the call rather
// than returning success. The session is about to be spent, so a silent miss
// would strand a tenant with an owner identity and no provisioning record.
func TestSignup_EnqueueFailureIsFatal(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	// entitlementsDB() returns nil with no platform DB wired, which makes
	// enqueue a silent no-op rather than an error, so drive the error path with
	// a closed handle instead.
	h.srv.platformDB = closedDB(t)

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId:            testAttemptID,
		VerifiedSessionToken: session,
		Password:             "s3cret-passw0rd!",
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status = %v, want Internal when the tenant cannot be enqueued", err)
	}
}

// ---------------------------------------------------------------------------
// (c) Single-use and expiring
// ---------------------------------------------------------------------------

// TestRedeemEmailVerification_TokenIsSingleUse proves a second click on the
// same link fails, and fails with exactly the response an unknown token gets.
func TestRedeemEmailVerification_TokenIsSingleUse(t *testing.T) {
	h := newSignupHarness(t)
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	token := tokenFromLink(t, h.mail.verifications[0].ContinueURL)

	first, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{Token: token})
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if first.GetVerifiedSessionToken() == "" {
		t.Fatalf("first redemption returned no session")
	}

	_, secondErr := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{Token: token})
	if status.Code(secondErr) != codes.PermissionDenied {
		t.Fatalf("second redemption status = %v, want PermissionDenied", secondErr)
	}

	// Indistinguishable from a token that never existed — same code AND same
	// message, so redemption cannot be used to probe which tokens are real.
	_, unknownErr := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{Token: "tok-never-issued"})
	if status.Code(unknownErr) != status.Code(secondErr) {
		t.Errorf("codes differ: reused=%v unknown=%v", status.Code(secondErr), status.Code(unknownErr))
	}
	if status.Convert(unknownErr).Message() != status.Convert(secondErr).Message() {
		t.Errorf("messages differ:\n reused = %q\n unknown = %q",
			status.Convert(secondErr).Message(), status.Convert(unknownErr).Message())
	}
}

// TestRedeemEmailVerification_TokenExpires proves the emailed link stops
// working after its TTL, with the same opaque denial.
func TestRedeemEmailVerification_TokenExpires(t *testing.T) {
	h := newSignupHarness(t)
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	token := tokenFromLink(t, h.mail.verifications[0].ContinueURL)

	h.advance(SignupVerificationTTL + time.Minute)

	_, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{Token: token})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied on an expired link", err)
	}
}

// TestSignup_SessionIsSingleUseAndExpires proves the completion session is
// spent on success (so a copied cookie cannot provision a second tenant) and
// dies with its own, much shorter TTL.
func TestSignup_SessionIsSingleUseAndExpires(t *testing.T) {
	t.Run("consumed on success", func(t *testing.T) {
		h := newSignupHarness(t)
		session := h.requestAndRedeem(t)
		h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
		}
		if _, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
			AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
		}); err != nil {
			t.Fatalf("first Signup: %v", err)
		}

		_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
			AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("replayed session status = %v, want PermissionDenied", err)
		}
		if len(h.idp.createHumanReqs) != 1 {
			t.Errorf("the replay reached identity creation: %d calls", len(h.idp.createHumanReqs))
		}
	})

	t.Run("expires", func(t *testing.T) {
		h := newSignupHarness(t)
		session := h.requestAndRedeem(t)
		h.advance(SignupSessionTTL + time.Minute)

		_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
			AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied on an expired session", err)
		}
		if len(h.idp.createHumanReqs) != 0 {
			t.Errorf("an expired session reached identity creation")
		}
	})

	t.Run("completion attempts are capped", func(t *testing.T) {
		h := newSignupHarness(t)
		session := h.requestAndRedeem(t)
		h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{}, idp.ErrUnreachable
		}
		for i := range SignupMaxCompletionAttempts {
			_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
				AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
			})
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("attempt %d: status = %v, want Unavailable", i, err)
			}
		}
		// The budget is spent; further attempts are denied as not-redeemable.
		_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
			AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("status after the cap = %v, want PermissionDenied", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Fail-closed behaviour and validation
// ---------------------------------------------------------------------------

// TestRequestEmailVerification_FailsClosed proves that a missing dependency
// refuses the signup rather than proceeding without the control it provides,
// and that the refusal leaves no trace: no identity and no verification row.
//
// "no mail transport" wants FailedPrecondition, not Unavailable: it is a
// deployment misconfiguration (no delivering GIBSON_EMAIL_PROVIDER wired),
// not a transient condition worth retrying, and it is where the requirement
// is enforced now that the daemon no longer refuses to boot over it
// (gibson#1228 / PR #1228 — the daemon warns at startup instead; see
// resolveSignupMailer in internal/server/daemon/signup_mailer.go).
func TestRequestEmailVerification_FailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*signupHarness)
		want    codes.Code
	}{
		{"limiter unreachable", func(h *signupHarness) { h.srv.WithSignupLimiter(brokenLimiter{}) }, codes.Unavailable},
		{"no limiter wired", func(h *signupHarness) { h.srv.signupLimiter = nil }, codes.Unavailable},
		{"over budget", func(h *signupHarness) { h.srv.WithSignupLimiter(denyLimiter{}) }, codes.ResourceExhausted},
		{"no store wired", func(h *signupHarness) { h.srv.signupVerifications = nil }, codes.Unavailable},
		{"no mail transport", func(h *signupHarness) { h.srv.signupMailer = nil }, codes.FailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignupHarness(t)
			tc.corrupt(h)
			_, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq())
			if status.Code(err) != tc.want {
				t.Fatalf("status = %v, want %v", err, tc.want)
			}
			if len(h.idp.createHumanReqs) != 0 {
				t.Errorf("a refused request still created an identity")
			}
			if len(h.store.rows) != 0 {
				t.Errorf("a refused request still persisted a verification row: %d rows", len(h.store.rows))
			}
			if len(h.mail.verifications)+len(h.mail.collisions) != 0 {
				t.Errorf("a refused request still sent mail")
			}
		})
	}
}

// TestRequestEmailVerification_NoMailerMessageIsOperatorFacing pins the exact
// wording callers see when no delivering mail transport is configured — it
// must name the problem (no delivering transport) without hinting at retrying,
// since retrying changes nothing until an operator fixes the deployment.
func TestRequestEmailVerification_NoMailerMessageIsOperatorFacing(t *testing.T) {
	h := newSignupHarness(t)
	h.srv.signupMailer = nil

	_, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq())
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("status = %v, want FailedPrecondition", err)
	}
	const want = "self-serve signup unavailable: no delivering email transport configured"
	if status.Convert(err).Message() != want {
		t.Errorf("message = %q, want %q", status.Convert(err).Message(), want)
	}
}

// TestRequestEmailVerification_SendFailureIsFatal proves the caller is never
// told to check an inbox for a message that was not sent.
func TestRequestEmailVerification_SendFailureIsFatal(t *testing.T) {
	h := newSignupHarness(t)
	h.mail.err = errors.New("smtp refused")

	_, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable when the send fails", err)
	}
	// The row is retired so its token can never be redeemed — it was never in
	// anyone's mailbox.
	raw := "tok-owner@example.com|" + testAttemptID
	if _, _, rerr := h.store.RedeemToken(context.Background(), raw); !errors.Is(rerr, ErrSignupVerificationNotFound) {
		t.Errorf("an undelivered token is still redeemable: %v", rerr)
	}
}

// TestRequestEmailVerification_ResendCooldown proves a rapid resend for the
// same address is refused, and refused with the same code a rate-limit hit
// returns so the two are not distinguishable.
func TestRequestEmailVerification_ResendCooldown(t *testing.T) {
	h := newSignupHarness(t)
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq())
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("status = %v, want ResourceExhausted inside the cooldown", err)
	}

	h.advance(SignupResendCooldown + time.Second)
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
}

// TestRequestEmailVerification_Validation covers the input rejections. Every
// one of them is decidable from the request alone, so none of them leaks
// whether the address is registered.
func TestRequestEmailVerification_Validation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*tenantv1.RequestEmailVerificationRequest)
	}{
		{"missing attempt_id", func(r *tenantv1.RequestEmailVerificationRequest) { r.AttemptId = "" }},
		{"bad attempt_id", func(r *tenantv1.RequestEmailVerificationRequest) { r.AttemptId = "not-a-uuid" }},
		{"missing email", func(r *tenantv1.RequestEmailVerificationRequest) { r.OwnerEmail = "" }},
		{"malformed email", func(r *tenantv1.RequestEmailVerificationRequest) { r.OwnerEmail = "not-an-email" }},
		{"missing workspace", func(r *tenantv1.RequestEmailVerificationRequest) { r.WorkspaceName = "" }},
		{"missing tier", func(r *tenantv1.RequestEmailVerificationRequest) { r.Tier = "" }},
		{"workspace yields empty slug", func(r *tenantv1.RequestEmailVerificationRequest) { r.WorkspaceName = "***" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignupHarness(t)
			req := validRequestReq()
			tc.mutate(req)
			if _, err := h.srv.RequestEmailVerification(context.Background(), req); status.Code(err) != codes.InvalidArgument {
				t.Errorf("status = %v, want InvalidArgument", err)
			}
		})
	}
}

// TestRequestEmailVerification_NormalizesEmail proves the address is normalized
// once, at the entry point. If the request path and the lookup path normalized
// differently, the account-exists branch would miss and a duplicate signup
// would fall through to the verification link.
func TestRequestEmailVerification_NormalizesEmail(t *testing.T) {
	h := newSignupHarness(t)
	req := validRequestReq()
	req.OwnerEmail = "  Owner@Example.COM  "

	if _, err := h.srv.RequestEmailVerification(context.Background(), req); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if len(h.idp.findUserCalls) != 1 || h.idp.findUserCalls[0] != "owner@example.com" {
		t.Errorf("directory lookup used %v, want the normalized address", h.idp.findUserCalls)
	}
	if h.mail.verifications[0].To != "owner@example.com" {
		t.Errorf("mail sent to %q, want the normalized address", h.mail.verifications[0].To)
	}
}

// TestSignup_ValidationBeforeAnySideEffect keeps the cheap rejections cheap:
// a malformed completion request must not spend a completion attempt or reach
// the IdP.
func TestSignup_ValidationBeforeAnySideEffect(t *testing.T) {
	cases := []struct {
		name string
		req  *tenantv1.SignupRequest
		want codes.Code
	}{
		{"missing attempt_id", &tenantv1.SignupRequest{VerifiedSessionToken: "s", Password: "p"}, codes.InvalidArgument},
		{"bad attempt_id", &tenantv1.SignupRequest{AttemptId: "nope", VerifiedSessionToken: "s", Password: "p"}, codes.InvalidArgument},
		{"missing password", &tenantv1.SignupRequest{AttemptId: testAttemptID, VerifiedSessionToken: "s"}, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignupHarness(t)
			if _, err := h.srv.Signup(context.Background(), tc.req); status.Code(err) != tc.want {
				t.Errorf("status = %v, want %v", err, tc.want)
			}
			if len(h.idp.createHumanReqs) != 0 {
				t.Errorf("a malformed request reached the IdP")
			}
		})
	}
}

// TestSignup_AttemptIDMustMatchTheVerifiedSession stops a session issued for
// one signup attempt being replayed under another attempt id.
func TestSignup_AttemptIDMustMatchTheVerifiedSession(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId:            "99999999-2222-4333-8444-555555555555",
		VerifiedSessionToken: session,
		Password:             "s3cret-passw0rd!",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied on an attempt-id mismatch", err)
	}
	if len(h.idp.createHumanReqs) != 0 {
		t.Errorf("the mismatched attempt reached identity creation")
	}
}

// TestAttachSignupCustomer_RequiresLiveSession keeps billing objects behind the
// same proof everything else is behind.
func TestAttachSignupCustomer_RequiresLiveSession(t *testing.T) {
	h := newSignupHarness(t)
	if _, err := h.srv.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
		VerifiedSessionToken: "sess-fabricated",
		StripeCustomerId:     "cus_123",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied without a live session", err)
	}

	session := h.requestAndRedeem(t)
	if _, err := h.srv.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
		VerifiedSessionToken: session,
		StripeCustomerId:     "cus_123",
	}); err != nil {
		t.Fatalf("AttachSignupCustomer: %v", err)
	}
	row, err := h.store.GetByVerifiedSession(context.Background(), session)
	if err != nil {
		t.Fatalf("GetByVerifiedSession: %v", err)
	}
	if row.StripeCustomerID != "cus_123" {
		t.Errorf("StripeCustomerID = %q, want cus_123", row.StripeCustomerID)
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

// ---------------------------------------------------------------------------
// Token confidentiality
// ---------------------------------------------------------------------------

// TestSignupFlow_TokenNeverAppearsInLogs drives the full request → redeem →
// signup flow with every handler log captured, and proves the raw token and
// the session it redeems to are never among them.
//
// This holds independently of which mail transport is configured — the
// daemon never routes a verification token through its own structured
// logger, only through the mailed link (mailer.VerificationEmail.ContinueURL,
// which is out of scope for the daemon's logs by construction: LogMailer
// refuses to log a body at all, see mailer.TestLogMailer_NeverWritesTheMessageBody,
// and RequireDelivering means LogMailer is never wired as the signup
// transport in the first place). This test pins the daemon side of that
// property against the real handlers rather than the mailer in isolation.
func TestSignupFlow_TokenNeverAppearsInLogs(t *testing.T) {
	var logBuf bytes.Buffer
	h := newSignupHarness(t)
	h.srv.logger = slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if len(h.mail.verifications) != 1 {
		t.Fatalf("expected one verification email, got %d", len(h.mail.verifications))
	}
	token := tokenFromLink(t, h.mail.verifications[0].ContinueURL)
	if token == "" {
		t.Fatal("no token recovered from the mailed link")
	}

	redeemResp, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{
		Token: token, ClientIp: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("RedeemEmailVerification: %v", err)
	}
	session := redeemResp.GetVerifiedSessionToken()
	if session == "" {
		t.Fatal("no session returned by RedeemEmailVerification")
	}

	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	const password = "s3cret-passw0rd!"
	if _, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: password,
	}); err != nil {
		t.Fatalf("Signup: %v", err)
	}

	out := logBuf.String()
	for _, secret := range []string{token, session, password} {
		if strings.Contains(out, secret) {
			t.Errorf("log output leaks a secret value %q:\n%s", secret, out)
		}
	}
}
