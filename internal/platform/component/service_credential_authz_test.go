// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Regression tests for gibson#1245: ComponentService/GetCredential had NO
// per-secret authorization decision.
//
//   - The handler did a bare credentialStore read after a tenant-presence check
//     only — no Check against the requested secret.
//   - The gateway could not supply one either: its field deriver has no request
//     field to derive the secret object from, so the registry rule cannot form
//     the per-secret question, and this listener is reachable without it.
//
// Any caller that reached the RPC therefore got any secret in its
// header-asserted tenant. These tests pin the restored decision: user = the
// caller's typed FGA principal, relation = can_resolve, object =
// authz.SecretObject(tenant, name) — the same triple the sibling
// HarnessCallbackService/GetCredential asks (PR #1278) and the same one the
// tenant-operator and the daemon's secret writers seed tuples against.

package component

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// credRecordingAuthorizer captures the (user, relation, object) triple the
// handler asks FGA about, so the tests can assert the SHAPE of the question — a
// check whose object is shaped differently from what the tuple writers produce
// would pass an "it denied" assertion while never matching a real grant.
type credRecordingAuthorizer struct {
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

func (r *credRecordingAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	r.calls++
	r.gotUser, r.gotRelation, r.gotObject = user, relation, object
	if r.err != nil {
		return false, r.err
	}
	return r.allow, nil
}

// credPerObjectAuthorizer allows can_resolve on exactly one (user, object)
// pair, so TestComponentGetCredential_DeniedForDifferentSecret exercises the
// real decision triple instead of ignoring who is asking.
type credPerObjectAuthorizer struct {
	authz.Authorizer
	allowedUser   string
	allowedObject string
}

func (p *credPerObjectAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	return user == p.allowedUser && relation == relationCanResolve && object == p.allowedObject, nil
}

// credStoreSpy returns a fixed payload for any name and counts reads. Reaching
// it at all is the failure this suite guards against for unauthorized callers.
type credStoreSpy struct{ served int }

func (s *credStoreSpy) GetCredential(context.Context, string, string) ([]byte, error) {
	s.served++
	return []byte(`{"username":"admin","password":"s3cr3t"}`), nil
}

// credCallerCtx builds a request context carrying the identity the SDK auth
// interceptor would have placed there from the x-gibson-identity-* headers.
func credCallerCtx(t *testing.T, subject, tenant string) context.Context {
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

func newCredentialAuthzServer(a authz.Authorizer, store CredentialStore) *ComponentServiceServer {
	svc := newParityServer().WithCredentialStore(store)
	if a != nil {
		svc = svc.WithAuthorizer(a)
	}
	return svc
}

// TestComponentGetCredential_DeniedWithoutCanResolve is the core regression
// test: a caller with no can_resolve tuple on the requested secret must get
// PERMISSION_DENIED, and the credential store must never be touched.
//
// Per internal/platform/authz/model.fga the `secret` type declares
// `can_resolve: [plugin_principal]` and nothing else — agent_principal and
// tool_principal have NO relation to secret at all, so FGA answers false for
// them structurally, not by policy default (spec non-plugin-secret-isolation).
func TestComponentGetCredential_DeniedWithoutCanResolve(t *testing.T) {
	fga := &credRecordingAuthorizer{allow: false}
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(fga, store)

	ctx := credCallerCtx(t, "agent_principal:agent-abc-123", "acme")
	_, err := svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "REGRESSION (gibson#1245): GetCredential must deny a caller with no "+
		"can_resolve on the requested secret. It previously did a bare store read after a "+
		"tenant-presence check only, and the gateway cannot form the per-secret question")
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

// TestComponentGetCredential_AllowedWithCanResolve is the paired control: a
// plugin principal that DOES hold can_resolve on this secret is served. Without
// this, the deny test above could pass on a guard that denies everything.
func TestComponentGetCredential_AllowedWithCanResolve(t *testing.T) {
	fga := &credRecordingAuthorizer{allow: true}
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(fga, store)

	ctx := credCallerCtx(t, "plugin_principal:plugin-github-1", "acme")
	resp, err := svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.NoError(t, err, "a caller holding can_resolve must still be served — breaking secret "+
		"resolution for legitimate plugin principals is a shipping blocker")
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CredentialJson)
	assert.Equal(t, 1, store.served, "an authorized caller must reach the credential store")
	assert.Equal(t, "plugin_principal:plugin-github-1", fga.gotUser)
}

// TestComponentGetCredential_DeniedForDifferentSecret proves the decision is
// PER-SECRET, not per-caller: the same principal is allowed one secret and
// denied another.
func TestComponentGetCredential_DeniedForDifferentSecret(t *testing.T) {
	granted := authz.SecretObject("acme", "cred:openai-prod")

	const caller = "plugin_principal:plugin-github-1"
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(&credPerObjectAuthorizer{allowedUser: caller, allowedObject: granted}, store)
	ctx := credCallerCtx(t, caller, "acme")

	_, err := svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:openai-prod"})
	require.NoError(t, err, "the granted secret must be served")

	_, err = svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:stripe-live"})
	require.Error(t, err, "REGRESSION (gibson#1245): the decision must be per-SECRET. A caller granted "+
		"one secret must not thereby read every secret in its tenant")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 1, store.served, "only the granted secret may reach the store")
}

// --- fail-closed axes ---

// TestComponentGetCredential_DeniedWithoutRequestContext pins the ordering: a
// caller carrying no request context at all is refused by the authorization
// gate, not by a downstream argument or capability check. The gate runs before
// request validation and before the nil-store branch, so an unauthorized caller
// cannot even learn whether a credential store is configured.
func TestComponentGetCredential_DeniedWithoutRequestContext(t *testing.T) {
	fga := &credRecordingAuthorizer{allow: true}
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(fga, store)

	_, err := svc.GetCredential(context.Background(),
		&componentpb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "a request with no tenant scope must be denied — there is no secret "+
		"namespace to authorize against")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"a caller with no context must get PERMISSION_DENIED, not an argument or capability error")
	assert.Equal(t, 0, store.served)
	assert.Equal(t, 0, fga.calls, "FGA must not be asked a question with no tenant")
}

// TestComponentGetCredential_DeniedWithoutRequestContextEvenWithNoStore proves
// the gate runs AHEAD of the nil-credentialStore branch: the same contextless
// caller is denied rather than told the store is unimplemented.
func TestComponentGetCredential_DeniedWithoutRequestContextEvenWithNoStore(t *testing.T) {
	svc := newCredentialAuthzServer(&credRecordingAuthorizer{allow: true}, nil)

	_, err := svc.GetCredential(context.Background(),
		&componentpb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"authorization must be decided before the handler reveals whether a credential store "+
			"is configured")
}

func TestComponentGetCredential_DeniedWithoutIdentity(t *testing.T) {
	fga := &credRecordingAuthorizer{allow: true}
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(fga, store)

	// Tenant present, no subject.
	tid, err := auth.NewTenantID("acme")
	require.NoError(t, err)
	ctx := auth.ContextWithTenant(context.Background(), tid)

	_, err = svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:openai-prod"})
	require.Error(t, err, "a caller with no identity must be denied, not served")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Equal(t, 0, store.served)
	assert.Equal(t, 0, fga.calls, "FGA must not be asked a question with no subject")
}

func TestComponentGetCredential_DeniedWhenAuthorizerMissing(t *testing.T) {
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(nil, store)

	ctx := credCallerCtx(t, "plugin_principal:plugin-github-1", "acme")
	_, err := svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "an undecidable authorization question is a DENY: with no authorizer wired "+
		"the handler must refuse rather than fall back to serving the secret")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 0, store.served)
}

func TestComponentGetCredential_DeniedWhenFGAUnavailable(t *testing.T) {
	fga := &credRecordingAuthorizer{err: errors.New("fga unreachable")}
	store := &credStoreSpy{}
	svc := newCredentialAuthzServer(fga, store)

	ctx := credCallerCtx(t, "plugin_principal:plugin-github-1", "acme")
	_, err := svc.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: "cred:openai-prod"})

	require.Error(t, err, "an FGA error must fail CLOSED — never fall through to the store")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 0, store.served)
}

// --- componentFGAUser: must mirror the gateway and the sibling endpoint ---

// TestComponentFGAUser_MirrorsGatewayShape pins the same table as
// TestCallbackFGAUser_MirrorsGatewayShape in internal/engine/harness (PR #1278).
// The two GetCredential endpoints resolve the same secrets against the same
// tuples; if one endpoint's user derivation drifts, this table diverges from its
// sibling and the divergence is visible in review rather than silent at runtime.
func TestComponentFGAUser_MirrorsGatewayShape(t *testing.T) {
	for _, tc := range []struct{ subject, want string }{
		{"agent_principal:agent-abc", "agent_principal:agent-abc"},
		{"tool_principal:tool-abc", "tool_principal:tool-abc"},
		{"plugin_principal:plugin-abc", "plugin_principal:plugin-abc"},
		{"user:11111111-2222-3333-4444-555555555555", "user:11111111-2222-3333-4444-555555555555"},
		{"11111111-2222-3333-4444-555555555555", "user:11111111-2222-3333-4444-555555555555"},
		{"spiffe://zeroroot.ai/platform/dashboard", "user:zeroroot.ai/platform/dashboard"},
	} {
		assert.Equal(t, tc.want, componentFGAUser(tc.subject),
			"componentFGAUser must produce the same user string as "+
				"internal/server/extauthz/fga/check.go and harness.callbackFGAUser; a divergent "+
				"shape would never match the tuples the gateway path matches")
	}
}
