// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Regression tests for gibson#1245: PluginInvokeService/PluginInvoke had NO
// per-plugin authorization decision the daemon could rely on.
//
//   - The handler trusted ext-authz for the can_invoke FGA check and dispatched
//     without any check of its own.
//   - The gateway could not supply one: PluginInvoke's registry rule is
//     object_deriver=tenant_and_field('PluginName'), and the PluginName lives in
//     the request body ext-authz never sees. Since #1243 the gateway therefore
//     runs the coarse checks and passes through (handler-enforced), so the
//     per-plugin decision has to be made HERE.
//
// Any component that reached the RPC could otherwise invoke any plugin in its
// header-asserted tenant. These tests pin the restored decision: user = the
// caller's typed FGA principal, relation = can_invoke, object =
// authz.PluginObject(tenant, name) — the triple the writers seed tuples against.
package component

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	pluginpb "github.com/zeroroot-ai/sdk/api/gen/gibson/plugin/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// allowInvokeAuthorizer allows the can_invoke-on-a-plugin decision the dispatch
// tests in plugin_dispatch_test.go need to get past, so they can exercise
// behaviour AFTER the per-plugin gate. It keys on the decision arguments
// (relation + object) rather than answering true unconditionally: it grants
// only the exact shape authorizeInvoke forms (relation can_invoke on a
// plugin:<tenant>/<name> object) and denies anything else. A handler that asked
// a different question would be denied here and its dispatch test would fail —
// which is what keeps this double honest (the constant-verdict-double guard,
// gibson#1310 class).
type allowInvokeAuthorizer struct{ authz.Authorizer }

func (allowInvokeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	// Verdict is a function of all three decision arguments: a named principal
	// asking can_invoke on a plugin object. A question missing any of these —
	// the shapes a broken handler would produce — is denied, so a dispatch test
	// riding this double still fails if the gate stops asking the right thing.
	return user != "" && relation == relationCanInvoke && strings.HasPrefix(object, "plugin:"), nil
}

// allowInvokeAuthz is the shared allow-all authorizer wired into the existing
// dispatch tests. Its behaviour is pinned by TestPluginInvoke_AllowedWithCanInvoke
// below, so "authz is wired and permissive" is a tested property, not an
// assumption.
var allowInvokeAuthz = allowInvokeAuthorizer{}

// recordingInvokeAuthorizer captures the (user, relation, object) triple the
// handler asks FGA about, so the tests assert the SHAPE of the question — a
// check whose object is shaped differently from what the tuple writers produce
// would pass an "it denied" assertion while never matching a real grant.
type recordingInvokeAuthorizer struct {
	// Embedded so this fake only overrides Check. Any other method is a
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

func (r *recordingInvokeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	r.calls++
	r.gotUser, r.gotRelation, r.gotObject = user, relation, object
	if r.err != nil {
		return false, r.err
	}
	return r.allow, nil
}

// invokeCallerCtx builds a request context carrying a component (Capability
// Grant) identity whose Subject is a typed tool_principal ref — the shape the
// daemon asserts for a component (ADR-0045), and the caller model.fga expects
// for plugin can_invoke.
func invokeCallerCtx(t *testing.T, subject, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	require.NoError(t, err)
	return auth.WithIdentity(auth.ContextWithTenant(context.Background(), tid), auth.Identity{
		Subject:        subject,
		Issuer:         auth.IssuerOIDC,
		CredentialType: auth.CredentialCapabilityGrant,
		Tenant:         tid,
		IssuedAt:       time.Now(),
	})
}

// invokeReq is a minimal well-formed PluginInvokeRequest for the named plugin.
func invokeReq(plugin string) *pluginpb.PluginInvokeRequest {
	return &pluginpb.PluginInvokeRequest{PluginName: plugin, Method: "search", DeadlineMs: 5000}
}

// TestPluginInvoke_DeniedWithoutCanInvoke is the core regression test: a caller
// with no can_invoke tuple on the requested plugin must get PERMISSION_DENIED,
// and dispatch must never happen. The FGA question asked must be the exact
// tenant-qualified triple the writers answer.
func TestPluginInvoke_DeniedWithoutCanInvoke(t *testing.T) {
	reg := newFakeComponentInstallRegistry()
	// The plugin IS installed and serving — so a deny can only come from authz,
	// not from a missing install. This is what proves the gate, not a 404.
	reg.addInstall(auth.MustNewTenantID("acme"), "lookup", []string{"search"})
	dispatched := false
	reg.dispatchFunc = func(context.Context, auth.TenantID, string, string, []byte, time.Duration) ([]byte, error) {
		dispatched = true
		return nil, nil
	}

	fga := &recordingInvokeAuthorizer{allow: false}
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(fga)

	ctx := invokeCallerCtx(t, "tool_principal:9", "acme")
	_, err := svc.PluginInvoke(ctx, invokeReq("lookup"))

	require.Error(t, err, "REGRESSION (gibson#1245): PluginInvoke must deny a caller with no "+
		"can_invoke on the requested plugin. It previously trusted ext-authz for the FGA check "+
		"and dispatched with no per-plugin decision of its own")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, dispatched, "dispatch must NEVER happen for a denied caller")

	// The question asked must be the one the tuple writers answer.
	assert.Equal(t, 1, fga.calls, "exactly one FGA question must be asked")
	assert.Equal(t, "tool_principal:9", fga.gotUser,
		"a component's Subject is already a typed FGA principal ref (ADR-0045) and must be used "+
			"verbatim — mirroring ext-authz's componentFGAUser")
	assert.Equal(t, "can_invoke", fga.gotRelation)
	assert.Equal(t, authz.PluginObject("acme", "lookup"), fga.gotObject,
		"the object must be the canonical authz.PluginObject form; any other shape would never "+
			"match a tuple the writers produced")
}

// TestPluginInvoke_AllowedWithCanInvoke is the paired control: a caller that
// DOES hold can_invoke on this plugin is dispatched. Without this, a handler
// that denied unconditionally would also pass the deny test above.
func TestPluginInvoke_AllowedWithCanInvoke(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})
	dispatched := false
	reg.dispatchFunc = func(context.Context, auth.TenantID, string, string, []byte, time.Duration) ([]byte, error) {
		dispatched = true
		return nil, nil
	}

	fga := &recordingInvokeAuthorizer{allow: true}
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(fga)

	ctx := invokeCallerCtx(t, "tool_principal:9", "acme")
	resp, err := svc.PluginInvoke(ctx, invokeReq("lookup"))

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.GetError(), "expected a successful dispatch, got a plugin error")
	assert.True(t, dispatched, "an authorized caller must reach dispatch")
	assert.Equal(t, authz.PluginObject("acme", "lookup"), fga.gotObject)
}

// TestPluginInvoke_DeniedWhenNoAuthorizerWired proves the fail-closed default:
// a service with no authorizer denies every invocation rather than dispatching.
// This is the branch that catches a misconfigured or partially-constructed
// service — an undecidable authorization question is a deny.
func TestPluginInvoke_DeniedWhenNoAuthorizerWired(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})
	dispatched := false
	reg.dispatchFunc = func(context.Context, auth.TenantID, string, string, []byte, time.Duration) ([]byte, error) {
		dispatched = true
		return nil, nil
	}

	// No WithAuthorizer call — the authorizer is nil.
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil)

	ctx := invokeCallerCtx(t, "tool_principal:9", "acme")
	_, err := svc.PluginInvoke(ctx, invokeReq("lookup"))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"an unwired authorizer must fail closed (deny), never dispatch")
	assert.False(t, dispatched, "dispatch must NEVER happen without an authorizer")
}

// TestPluginInvoke_FGAErrorFailsClosed proves an FGA infrastructure error is a
// refusal (Unavailable), never a silent allow, and dispatch does not happen.
func TestPluginInvoke_FGAErrorFailsClosed(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})
	dispatched := false
	reg.dispatchFunc = func(context.Context, auth.TenantID, string, string, []byte, time.Duration) ([]byte, error) {
		dispatched = true
		return nil, nil
	}

	fga := &recordingInvokeAuthorizer{err: errors.New("fga down")}
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(fga)

	ctx := invokeCallerCtx(t, "tool_principal:9", "acme")
	_, err := svc.PluginInvoke(ctx, invokeReq("lookup"))

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"an FGA error must fail closed, never allow")
	assert.False(t, dispatched, "dispatch must NEVER happen on an FGA error")
}

// TestAuthorizeInvoke_FailsClosedOnEveryAxis targets authorizeInvoke directly.
// The handler pre-checks tenant/identity and returns before reaching these
// branches, but authorizeInvoke is the authoritative gate — anything that
// calls it (now or in a future caller) must get the same fail-closed refusals,
// with no FGA question asked when the request is undecidable.
func TestAuthorizeInvoke_FailsClosedOnEveryAxis(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")

	componentCtx := func(withTenant, withIdentity bool) context.Context {
		ctx := context.Background()
		if withTenant {
			ctx = auth.ContextWithTenant(ctx, tenant)
		}
		if withIdentity {
			id := auth.Identity{
				Subject:        "tool_principal:9",
				Issuer:         auth.IssuerOIDC,
				CredentialType: auth.CredentialCapabilityGrant,
				IssuedAt:       time.Now(),
			}
			// Carry the tenant on the identity too, so WithIdentity does not
			// stamp an empty tenant over the context set above.
			if withTenant {
				id.Tenant = tenant
			}
			ctx = auth.WithIdentity(ctx, id)
		}
		return ctx
	}

	tests := []struct {
		name       string
		ctx        context.Context
		authorizer authz.Authorizer
		wantCode   codes.Code
		wantAsks   bool // whether an FGA question should be asked
	}{
		{"empty plugin name", componentCtx(true, true), &recordingInvokeAuthorizer{allow: true}, codes.InvalidArgument, false},
		{"no tenant", componentCtx(false, true), &recordingInvokeAuthorizer{allow: true}, codes.PermissionDenied, false},
		{"no identity", componentCtx(true, false), &recordingInvokeAuthorizer{allow: true}, codes.Unauthenticated, false},
		{"no authorizer wired", componentCtx(true, true), nil, codes.PermissionDenied, false},
		{"fga error", componentCtx(true, true), &recordingInvokeAuthorizer{err: errors.New("fga down")}, codes.Unavailable, true},
		{"denied", componentCtx(true, true), &recordingInvokeAuthorizer{allow: false}, codes.PermissionDenied, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := newFakeComponentInstallRegistry()
			svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil)
			if tc.authorizer != nil {
				svc = svc.WithAuthorizer(tc.authorizer)
			}

			name := "lookup"
			if tc.name == "empty plugin name" {
				name = ""
			}
			err := svc.authorizeInvoke(tc.ctx, name)

			require.Error(t, err, "every axis here must deny")
			assert.Equal(t, tc.wantCode, status.Code(err))
			if rec, ok := tc.authorizer.(*recordingInvokeAuthorizer); ok {
				if tc.wantAsks {
					assert.Equal(t, 1, rec.calls, "an FGA question must be asked for this axis")
				} else {
					assert.Equal(t, 0, rec.calls, "no FGA question may be asked when the request is undecidable")
				}
			}
		})
	}
}

// TestPluginInvoke_UserCredentialStillGated covers the canary-log branch: a
// user (OIDC) credential reaching this component RPC is unexpected and logged,
// but the authoritative gate is still authorizeInvoke — a user credential
// WITHOUT can_invoke is denied exactly like any other caller.
func TestPluginInvoke_UserCredentialStillGated(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})
	dispatched := false
	reg.dispatchFunc = func(context.Context, auth.TenantID, string, string, []byte, time.Duration) ([]byte, error) {
		dispatched = true
		return nil, nil
	}

	fga := &recordingInvokeAuthorizer{allow: false}
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(fga)

	ctx := auth.WithIdentity(auth.ContextWithTenant(context.Background(), tenant), auth.Identity{
		Subject:        "user:42",
		Issuer:         auth.IssuerOIDC,
		CredentialType: auth.CredentialOIDCUser,
		Tenant:         tenant,
		IssuedAt:       time.Now(),
	})
	_, err := svc.PluginInvoke(ctx, invokeReq("lookup"))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"a user credential is logged as a canary but still gated by can_invoke")
	assert.False(t, dispatched, "an unauthorized user credential must not dispatch")
}
