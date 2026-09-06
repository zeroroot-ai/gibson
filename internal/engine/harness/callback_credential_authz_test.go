// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Regression tests for gibson#1245: HarnessCallbackService/GetCredential had NO
// per-secret authorization decision at EITHER layer.
//
//   - The gateway never sees it. The harness callback listener is a separate
//     :50001 SPIFFE-mTLS listener that ext-authz does not front, so the registry
//     rule that enforces can_resolve on the other secret-resolving RPCs never runs.
//   - The handler did a bare credentialStore read with no Check.
//
// Any caller that reached the RPC therefore got any secret in its
// header-asserted tenant. These tests pin the restored decision: user = the
// caller's typed FGA principal, relation = can_resolve, object =
// authz.SecretObject(tenant, name) — the same triple the gateway uses and the
// same one the tenant-operator and the daemon's secret writers seed tuples
// against.

package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recordingAuthorizer captures the (user, relation, object) triple the handler
// asks FGA about, so the tests can assert the SHAPE of the question — a check
// whose object is shaped differently from what the tuple writers produce would
// pass an "it denied" assertion while never matching a real grant.
type recordingAuthorizer struct {
	// Embedded so this fake only has to override Check. Any other method is a
	// nil-pointer panic — deliberate: the handler must ask FGA exactly one
	// question, and a test that silently exercised another path would be lying.
	authz.Authorizer

	allow bool
	err   error

	gotUser     string
	gotRelation string
	gotObject   string
	calls       int
}

func (r *recordingAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	r.calls++
	r.gotUser, r.gotRelation, r.gotObject = user, relation, object
	if r.err != nil {
		return false, r.err
	}
	return r.allow, nil
}

// stubCredentialStore returns a fixed secret for any name. Reaching it at all is
// the failure this suite guards against for unauthorized callers.
type stubCredentialStore struct{ served int }

func (s *stubCredentialStore) GetCredential(context.Context, string) (*types.Credential, string, error) {
	s.served++
	return &types.Credential{Name: "cred:openai-prod"}, "super-secret-value", nil
}

// callerCtx builds a request context carrying the identity the SDK auth
// interceptor would have placed there from the x-gibson-identity-* headers.
func callerCtx(t *testing.T, subject, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	require.NoError(t, err)
	return auth.WithIdentity(context.Background(), auth.Identity{
		Subject:  subject,
		Issuer:   auth.IssuerOIDC,
		Tenant:   tid,
		IssuedAt: time.Now(),
	})
}

func newCredentialTestService(t *testing.T, a authz.Authorizer, store CredentialStore) *HarnessCallbackService {
	t.Helper()
	logger, _ := newBufferLogger()
	s := NewHarnessCallbackServiceWithRegistry(logger, NewCallbackHarnessRegistry())
	s.componentAuthorizer = a
	s.credentialStore = store
	return s
}

// TestGetCredential_DeniedWithoutCanResolve is the core regression test: a
// caller with no can_resolve tuple on the requested secret must get
// PERMISSION_DENIED, and the credential store must never be touched.
//
// Per internal/platform/authz/model.fga the `secret` type declares
// `can_resolve: [plugin_principal]` and nothing else — agent_principal and
// tool_principal have NO relation to secret at all, so FGA answers false for
// them structurally, not by policy default (spec non-plugin-secret-isolation).
func TestGetCredential_DeniedWithoutCanResolve(t *testing.T) {
	fga := &recordingAuthorizer{allow: false}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	ctx := callerCtx(t, "agent_principal:agent-abc-123", "acme")
	_, err := s.GetCredential(ctx, &harnesspb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "REGRESSION (gibson#1245): GetCredential must deny a caller with no "+
		"can_resolve on the requested secret. It previously did a bare store read with no Check, "+
		"and the callback listener is not fronted by ext-authz, so there was no decision at either layer")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 0, store.served, "the credential store must NEVER be reached for a denied caller")

	// The question asked must be the one the tuple writers answer.
	assert.Equal(t, "agent_principal:agent-abc-123", fga.gotUser,
		"a component's Subject is already a typed FGA principal ref (ADR-0045) and must be used "+
			"verbatim — the model rejects the user: type for these principals")
	assert.Equal(t, "can_resolve", fga.gotRelation)
	assert.Equal(t, authz.SecretObject("acme", "cred:openai-prod"), fga.gotObject,
		"the object must be the canonical authz.SecretObject form (gibson#1024/#1035); any other "+
			"shape would never match a tuple the writers produced")
}

// TestGetCredential_AllowedWithCanResolve is the paired control: a plugin
// principal that DOES hold can_resolve on this secret is served. Without this,
// the deny test above could pass on a guard that denies everything.
func TestGetCredential_AllowedWithCanResolve(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	ctx := callerCtx(t, "plugin_principal:plugin-github-1", "acme")
	resp, err := s.GetCredential(ctx, &harnesspb.GetCredentialRequest{
		Name:    "cred:openai-prod",
		Context: &harnesspb.ContextInfo{MissionId: "m-1", AgentName: "a-1"},
	})

	require.NoError(t, err, "a caller holding can_resolve must still be served — breaking secret "+
		"resolution for legitimate plugin principals is a shipping blocker")
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
	assert.Equal(t, 1, store.served, "an authorized caller must reach the credential store")
	assert.Equal(t, "plugin_principal:plugin-github-1", fga.gotUser)
}

// TestGetCredential_NilContextServedForPluginStartupSecret: a first-party plugin
// resolving its OWN declared startup secret has no mission and no agent, so its
// GetCredential Context is nil. That must NOT fail — Context is only a log field;
// resolution is tenant+name scoped and authz is can_resolve (ADR-0066).
func TestGetCredential_NilContextServedForPluginStartupSecret(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	ctx := callerCtx(t, "plugin_principal:plugin-github-1", "acme")
	resp, err := s.GetCredential(ctx, &harnesspb.GetCredentialRequest{
		Name:    "cred:github_token",
		Context: nil, // no mission/agent — a plugin startup-secret resolution
	})

	require.NoError(t, err, "a plugin resolving its own startup secret has no mission context; "+
		"a nil Context must be served, not rejected")
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error, "nil Context must not surface as an INVALID_ARGUMENT error")
	assert.Equal(t, 1, store.served, "the authorized caller must reach the credential store")
}

// TestGetCredential_DeniedForDifferentSecret proves the decision is PER-SECRET,
// not per-caller: the same principal is allowed one secret and denied another.
func TestGetCredential_DeniedForDifferentSecret(t *testing.T) {
	granted := authz.SecretObject("acme", "cred:openai-prod")

	const caller = "plugin_principal:plugin-github-1"
	perSecret := &perObjectAuthorizer{allowedUser: caller, allowedObject: granted}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, perSecret, store)
	ctx := callerCtx(t, caller, "acme")

	_, err := s.GetCredential(ctx, &harnesspb.GetCredentialRequest{
		Name:    "cred:openai-prod",
		Context: &harnesspb.ContextInfo{MissionId: "m-1", AgentName: "a-1"},
	})
	require.NoError(t, err, "the granted secret must be served")

	_, err = s.GetCredential(ctx, &harnesspb.GetCredentialRequest{
		Name:    "cred:stripe-live",
		Context: &harnesspb.ContextInfo{MissionId: "m-1", AgentName: "a-1"},
	})
	require.Error(t, err, "REGRESSION (gibson#1245): the decision must be per-SECRET. A caller granted "+
		"one secret must not thereby read every secret in its tenant")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 1, store.served, "only the granted secret may reach the store")
}

// perObjectAuthorizer allows can_resolve on exactly one (user, object) pair,
// so TestGetCredential_DeniedForDifferentSecret exercises the real decision
// triple instead of ignoring who is asking.
type perObjectAuthorizer struct {
	authz.Authorizer
	allowedUser   string
	allowedObject string
}

func (p *perObjectAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	return user == p.allowedUser && relation == "can_resolve" && object == p.allowedObject, nil
}

// --- fail-closed axes ---

func TestGetCredential_DeniedWithoutIdentity(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	// Tenant present, no identity.
	tid, err := auth.NewTenantID("acme")
	require.NoError(t, err)
	ctx := auth.ContextWithTenant(context.Background(), tid)

	_, err = s.GetCredential(ctx, &harnesspb.GetCredentialRequest{Name: "cred:openai-prod"})
	require.Error(t, err, "a caller with no identity must be denied, not served")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Equal(t, 0, store.served)
	assert.Equal(t, 0, fga.calls, "FGA must not be asked a question with no subject")
}

func TestGetCredential_DeniedWithoutTenant(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	_, err := s.GetCredential(context.Background(), &harnesspb.GetCredentialRequest{Name: "cred:openai-prod"})
	require.Error(t, err, "a request with no tenant scope must be denied — there is no secret namespace "+
		"to authorize against")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 0, store.served)
}

func TestGetCredential_DeniedWhenAuthorizerMissing(t *testing.T) {
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, nil, store)

	ctx := callerCtx(t, "plugin_principal:plugin-github-1", "acme")
	_, err := s.GetCredential(ctx, &harnesspb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "an undecidable authorization question is a DENY: with no authorizer wired "+
		"the handler must refuse rather than fall back to serving the secret")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 0, store.served)
}

func TestGetCredential_DeniedWhenFGAUnavailable(t *testing.T) {
	fga := &recordingAuthorizer{err: errors.New("fga unreachable")}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	ctx := callerCtx(t, "plugin_principal:plugin-github-1", "acme")
	_, err := s.GetCredential(ctx, &harnesspb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "an FGA error must fail CLOSED — never fall through to the store")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 0, store.served)
}

// --- callbackFGAUser: must mirror the gateway's transformation exactly ---

func TestCallbackFGAUser_MirrorsGatewayShape(t *testing.T) {
	for _, tc := range []struct{ subject, want string }{
		{"agent_principal:agent-abc", "agent_principal:agent-abc"},
		{"tool_principal:tool-abc", "tool_principal:tool-abc"},
		{"plugin_principal:plugin-abc", "plugin_principal:plugin-abc"},
		{"user:11111111-2222-3333-4444-555555555555", "user:11111111-2222-3333-4444-555555555555"},
		{"11111111-2222-3333-4444-555555555555", "user:11111111-2222-3333-4444-555555555555"},
		{"spiffe://zeroroot.ai/platform/dashboard", "user:zeroroot.ai/platform/dashboard"},
	} {
		assert.Equal(t, tc.want, callbackFGAUser(tc.subject),
			"callbackFGAUser must produce the same user string as "+
				"internal/server/extauthz/fga/check.go; a divergent shape would never match the "+
				"tuples the gateway path matches")
	}
}

// memberCredentialCtx is a caller that is a bank member: an identity, and the
// verified claims of the task grant it presented, naming its run and its job.
func memberCredentialCtx(t *testing.T, runID, jobID string) context.Context {
	t.Helper()
	ctx := callerCtx(t, "agent_principal:claude-member-1", "acme")
	return withTaskGrantClaims(ctx, sdkcg.Claims{MissionID: runID, TaskID: jobID})
}

// TestGetCredential_AMemberIsBoundedByItsJob asserts the second layer that
// holds if the minter ever puts secret resolution on a member grant: a name
// the job declared is served, and a name it did not declare is refused with
// a deny record, before FGA is even asked.
func TestGetCredential_AMemberIsBoundedByItsJob(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1") // declares gitlab-token
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)
	WithJobSurface(jobs)(s)
	WithMemberLookup(liveMembers())(s)

	_, err := s.GetCredential(memberCredentialCtx(t, "run-1", "job-1"),
		&harnesspb.GetCredentialRequest{Name: "gitlab-token"})
	require.NoError(t, err, "a name the job declared must be served")
	assert.Equal(t, 1, store.served)

	_, err = s.GetCredential(memberCredentialCtx(t, "run-1", "job-1"),
		&harnesspb.GetCredentialRequest{Name: "openai-prod"})
	require.Error(t, err, "a name the job did not declare must be refused")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 1, store.served, "the refused read must not reach the store")
}

// TestGetCredential_AMemberWithNoJobIsRefused asserts that a member whose
// grant names no open job cannot read any credential: there is no job to have
// declared one.
func TestGetCredential_AMemberWithNoJobIsRefused(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)
	WithJobSurface(newFakeJobs())(s)
	WithMemberLookup(liveMembers())(s)

	_, err := s.GetCredential(memberCredentialCtx(t, "run-1", "job-gone"),
		&harnesspb.GetCredentialRequest{Name: "gitlab-token"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 0, store.served)
}

// TestGetCredential_ANonMemberWithAGrantFallsToFGA asserts that a dispatched
// one-shot agent, which also presents a task grant, is not bounded by a job it
// does not have: its boundary is the FGA check, as before ADR-0019.
func TestGetCredential_ANonMemberWithAGrantFallsToFGA(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)
	WithJobSurface(newFakeJobs())(s)
	WithMemberLookup(liveMembers())(s) // knows run-1 only

	_, err := s.GetCredential(memberCredentialCtx(t, "run-oneshot", "task-9"),
		&harnesspb.GetCredentialRequest{Name: "openai-prod"})
	require.NoError(t, err)
	assert.Equal(t, 1, store.served)
	assert.Equal(t, "agent_principal:claude-member-1", fga.gotUser, "FGA must have been asked")
}

// TestGetCredential_AMemberLookupOutageIsRefused asserts that a bank store
// outage is not read as "not a member": the read is refused as Unavailable.
func TestGetCredential_AMemberLookupOutageIsRefused(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)
	WithJobSurface(newFakeJobs())(s)
	WithMemberLookup(&fakeMembers{err: errors.New("postgres is down")})(s)

	_, err := s.GetCredential(memberCredentialCtx(t, "run-1", "job-1"),
		&harnesspb.GetCredentialRequest{Name: "gitlab-token"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 0, store.served)
}

// TestGetCredential_ADaemonWithNoBanksReadsEveryCallerAsNotAMember asserts the
// default seams: with no bank surface wired, a grant-bearing caller is bounded
// by FGA alone, exactly as on a daemon before banks existed.
func TestGetCredential_ADaemonWithNoBanksReadsEveryCallerAsNotAMember(t *testing.T) {
	fga := &recordingAuthorizer{allow: true}
	store := &stubCredentialStore{}
	s := newCredentialTestService(t, fga, store)

	_, err := s.GetCredential(memberCredentialCtx(t, "run-1", "job-1"),
		&harnesspb.GetCredentialRequest{Name: "openai-prod"})
	require.NoError(t, err)
	assert.Equal(t, 1, store.served)
}
