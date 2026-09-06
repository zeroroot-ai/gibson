// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// secretBindRecorder records the tuples passed to Write. It embeds
// authz.Authorizer so any un-overridden method panics — the binding must call
// exactly Write and nothing else.
type secretBindRecorder struct {
	authz.Authorizer
	written []authz.Tuple
	err     error
	calls   int
}

func (r *secretBindRecorder) Write(_ context.Context, tuples []authz.Tuple) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.written = append(r.written, tuples...)
	return nil
}

// TestBindDeclaredSecrets_PluginGrantsCanResolve: a plugin_principal caller with
// declared secrets gets a can_resolve tuple per secret, on its own principal, in
// its tenant (ADR-0066).
func TestBindDeclaredSecrets_PluginGrantsCanResolve(t *testing.T) {
	rec := &secretBindRecorder{}
	svc := newParityServer().WithAuthorizer(rec)
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", map[string]string{
		metadataDeclaredSecrets: "cred:github_token, cred:other , cred:github_token",
	})

	// Deduped to two, one Write batch.
	if rec.calls != 1 {
		t.Fatalf("Write calls = %d, want 1 batch", rec.calls)
	}
	if len(rec.written) != 2 {
		t.Fatalf("wrote %d tuples, want 2 (deduped): %+v", len(rec.written), rec.written)
	}
	want := map[string]bool{
		authz.SecretObject("primary", "cred:github_token"): true,
		authz.SecretObject("primary", "cred:other"):        true,
	}
	for _, tp := range rec.written {
		if tp.User != "plugin_principal:github" {
			t.Errorf("tuple user = %q, want plugin_principal:github", tp.User)
		}
		if tp.Relation != relationCanResolve {
			t.Errorf("tuple relation = %q, want %q", tp.Relation, relationCanResolve)
		}
		delete(want, tp.Object)
	}
	if len(want) != 0 {
		t.Errorf("missing can_resolve objects: %v", want)
	}
}

// TestBindDeclaredSecrets_NonPluginSkipped: a non-plugin_principal caller writes
// nothing — only plugin_principal may hold can_resolve (model.fga).
func TestBindDeclaredSecrets_NonPluginSkipped(t *testing.T) {
	rec := &secretBindRecorder{}
	svc := newParityServer().WithAuthorizer(rec)
	ctx := credCallerCtx(t, "agent_principal:x", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", map[string]string{
		metadataDeclaredSecrets: "cred:github_token",
	})
	if rec.calls != 0 {
		t.Errorf("wrote for a non-plugin caller (%d calls) — must skip", rec.calls)
	}
}

// TestBindDeclaredSecrets_NoDeclaredSecretsNoOp: absent/empty metadata is a no-op.
func TestBindDeclaredSecrets_NoDeclaredSecretsNoOp(t *testing.T) {
	rec := &secretBindRecorder{}
	svc := newParityServer().WithAuthorizer(rec)
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", map[string]string{})
	svc.bindDeclaredSecrets(ctx, "primary", map[string]string{metadataDeclaredSecrets: "  "})
	if rec.calls != 0 {
		t.Errorf("wrote with no declared secrets (%d calls) — must no-op", rec.calls)
	}
}

// TestBindDeclaredSecrets_WriteErrorIsNonFatal: a Write failure is logged, not
// returned (best-effort; the plugin re-binds idempotently on its next start).
func TestBindDeclaredSecrets_WriteErrorIsNonFatal(t *testing.T) {
	rec := &secretBindRecorder{err: errors.New("fga down")}
	svc := newParityServer().WithAuthorizer(rec)
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")
	// Must not panic and must return normally (void).
	svc.bindDeclaredSecrets(ctx, "primary", map[string]string{
		metadataDeclaredSecrets: "cred:github_token",
	})
}
