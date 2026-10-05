// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"fmt"
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
	// offered is the set of component objects carrying platform_enabled from
	// the system tenant, the way the startup seeder leaves FGA.
	offered map[string]bool
	// checkErr makes Check fail, modelling an unreachable FGA.
	checkErr error
}

func (r *secretBindRecorder) Check(_ context.Context, user, relation, object string) (bool, error) {
	if r.checkErr != nil {
		return false, r.checkErr
	}
	if user != "system_tenant:_system" || relation != "platform_enabled" {
		return false, fmt.Errorf("unexpected gate question: Check(%s, %s, %s)", user, relation, object)
	}
	return r.offered[object], nil
}

func (r *secretBindRecorder) Write(_ context.Context, tuples []authz.Tuple) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.written = append(r.written, tuples...)
	return nil
}

// declaring builds the RegisterComponent metadata that names the given
// secret refs. The values are names, never secret material.
func declaring(refs string) map[string]string {
	return map[string]string{metadataDeclaredSecrets: refs}
}

// offering returns a recorder whose platform catalog offers exactly one
// (kind, id).
func offering(kind, id string) *secretBindRecorder {
	return &secretBindRecorder{offered: map[string]bool{authz.ComponentObject(kind, id): true}}
}

// TestBindDeclaredSecrets_OutsideCatalogWritesNothing: a check-in from a
// component the signed catalog does not list writes zero can_resolve tuples,
// whatever secret names it declares (gibson#554, ADR-0097). Before the gate
// this wrote two tuples for the caller's own principal.
func TestBindDeclaredSecrets_OutsideCatalogWritesNothing(t *testing.T) {
	rec := offering("plugin", "github")
	svc := newParityServer().WithAuthorizer(rec).WithEnrollmentReader(attestedCaller{})
	ctx := credCallerCtx(t, "plugin_principal:7f3c1b2e-dev", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "my-own-plugin", declaring("cred:github_token, cred:tenant_master_key"))
	if rec.calls != 0 || len(rec.written) != 0 {
		t.Fatalf("a non-catalog check-in wrote %d tuple(s) in %d call(s); want none: %+v",
			len(rec.written), rec.calls, rec.written)
	}
}

// TestBindDeclaredSecrets_GateErrorWritesNothing: when FGA cannot answer the
// catalog question, nothing is written. An undecidable gate is a closed gate.
func TestBindDeclaredSecrets_GateErrorWritesNothing(t *testing.T) {
	rec := offering("plugin", "github")
	rec.checkErr = errors.New("fga unreachable")
	svc := newParityServer().WithAuthorizer(rec).WithEnrollmentReader(attestedCaller{})
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("cred:github_token"))
	if rec.calls != 0 {
		t.Fatalf("a failed gate check wrote %d call(s); want none", rec.calls)
	}
}

// TestBindDeclaredSecrets_NoAuthorizerWritesNothing: with no authorizer wired
// the gate cannot be asked, so the binding is skipped rather than assumed.
func TestBindDeclaredSecrets_NoAuthorizerWritesNothing(t *testing.T) {
	svc := newParityServer()
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")
	// Must return normally with nothing to write to.
	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("cred:github_token"))
}

// TestBindDeclaredSecrets_PluginGrantsCanResolve: a plugin_principal caller with
// declared secrets gets a can_resolve tuple per secret, on its own principal, in
// its tenant (ADR-0066).
func TestBindDeclaredSecrets_PluginGrantsCanResolve(t *testing.T) {
	rec := offering("plugin", "github")
	svc := newParityServer().WithAuthorizer(rec).WithEnrollmentReader(attestedCaller{})
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("cred:github_token, cred:other , cred:github_token"))

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
	rec := offering("plugin", "github")
	svc := newParityServer().WithAuthorizer(rec).WithEnrollmentReader(attestedCaller{})
	ctx := credCallerCtx(t, "agent_principal:x", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("cred:github_token"))
	if rec.calls != 0 {
		t.Errorf("wrote for a non-plugin caller (%d calls) — must skip", rec.calls)
	}
}

// TestBindDeclaredSecrets_NoDeclaredSecretsNoOp: absent/empty metadata is a no-op.
func TestBindDeclaredSecrets_NoDeclaredSecretsNoOp(t *testing.T) {
	rec := offering("plugin", "github")
	svc := newParityServer().WithAuthorizer(rec).WithEnrollmentReader(attestedCaller{})
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")

	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", map[string]string{})
	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("  "))
	if rec.calls != 0 {
		t.Errorf("wrote with no declared secrets (%d calls) — must no-op", rec.calls)
	}
}

// TestBindDeclaredSecrets_WriteErrorIsNonFatal: a Write failure is logged, not
// returned (best-effort; the plugin re-binds idempotently on its next start).
func TestBindDeclaredSecrets_WriteErrorIsNonFatal(t *testing.T) {
	rec := offering("plugin", "github")
	rec.err = errors.New("fga down")
	svc := newParityServer().WithAuthorizer(rec).WithEnrollmentReader(attestedCaller{})
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")
	// Must not panic and must return normally (void).
	svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("cred:github_token"))
}

// attestedCaller answers that every principal enrolled with an attested
// workload identity, the state of a catalog plugin on the platform.
type attestedCaller struct{}

func (attestedCaller) PrincipalIsAttested(context.Context, string, string) (bool, error) {
	return true, nil
}

// enrollmentAnswer is a reader with one fixed answer.
type enrollmentAnswer struct {
	attested bool
	err      error
}

func (e enrollmentAnswer) PrincipalIsAttested(context.Context, string, string) (bool, error) {
	return e.attested, e.err
}

// TestBindDeclaredSecrets_TokenEnrolledCallerWritesNothing is the failing
// fixture for the rule that a catalog name is not a catalog identity
// (ADR-0066). The caller checks in as the catalog plugin, with a
// plugin_principal, but it enrolled with a bootstrap token. No reader, a
// failed read and a token enrollment all write zero tuples.
func TestBindDeclaredSecrets_TokenEnrolledCallerWritesNothing(t *testing.T) {
	ctx := credCallerCtx(t, "plugin_principal:310000000000000001", "primary")
	cases := map[string]func(*ComponentServiceServer) *ComponentServiceServer{
		"no reader": func(s *ComponentServiceServer) *ComponentServiceServer { return s },
		"read failed": func(s *ComponentServiceServer) *ComponentServiceServer {
			return s.WithEnrollmentReader(enrollmentAnswer{attested: true, err: errors.New("db down")})
		},
		"token enrollment": func(s *ComponentServiceServer) *ComponentServiceServer {
			return s.WithEnrollmentReader(enrollmentAnswer{attested: false})
		},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			rec := offering("plugin", "github")
			svc := wire(newParityServer().WithAuthorizer(rec))
			svc.bindDeclaredSecrets(ctx, "primary", "plugin", "github", declaring("cred:github_token"))
			if rec.calls != 0 || len(rec.written) != 0 {
				t.Fatalf("wrote %d tuples in %d calls, want none", len(rec.written), rec.calls)
			}
		})
	}
}
