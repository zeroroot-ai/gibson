// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// secretValue is the plaintext every case below resolves. It is a distinctive
// string so a leak assertion can search for it without matching anything else.
const secretValue = "kubeconfig-plaintext-SHOULD-NEVER-PERSIST"

type fakeCredentialStore struct {
	value string
	err   error
	calls []string
}

func (f *fakeCredentialStore) GetCredential(_ context.Context, name string) (*types.Credential, string, error) {
	f.calls = append(f.calls, name)
	if f.err != nil {
		return nil, "", f.err
	}
	return &types.Credential{Name: name}, f.value, nil
}

// harnessWithTarget builds the smallest harness that injectTargetSecret needs.
// The dispatch path around it wants a live executor and a registered manifest
// tool, which is why gibson#485's env injection is tested here on its own.
func harnessWithTarget(target TargetInfo, store CredentialStore) *DefaultAgentHarness {
	h := &DefaultAgentHarness{targetInfo: target}
	if store != nil {
		h.credentials = func() (CredentialStore, error) { return store, nil }
	}
	return h
}

// A target that names a secret gets its value, and the shape alongside it.
func TestInjectTargetSecret_ResolvesByName(t *testing.T) {
	store := &fakeCredentialStore{value: secretValue}
	h := harnessWithTarget(TargetInfo{
		Name:       "kubernetes-goat",
		SecretName: "goat-kubeconfig",
		AuthType:   "bearer",
	}, store)

	env := map[string]string{"GIBSON_TOOL_NAME": "kube-bench"}
	if err := h.injectTargetSecret(context.Background(), env); err != nil {
		t.Fatalf("injectTargetSecret: %v", err)
	}

	if got := env[envToolSecret]; got != secretValue {
		t.Errorf("%s = %q, want the resolved value", envToolSecret, got)
	}
	if got := env[envToolSecretAuthType]; got != "bearer" {
		t.Errorf("%s = %q, want bearer", envToolSecretAuthType, got)
	}
	if len(store.calls) != 1 || store.calls[0] != "goat-kubeconfig" {
		t.Errorf("store calls = %v, want exactly [goat-kubeconfig]", store.calls)
	}
}

// A target that names no secret dispatches exactly as today: the env it gets is
// the env it had. This is every target that exists right now.
func TestInjectTargetSecret_NoNameLeavesEnvAlone(t *testing.T) {
	store := &fakeCredentialStore{value: secretValue}
	h := harnessWithTarget(TargetInfo{Name: "example.com"}, store)

	env := map[string]string{"GIBSON_TOOL_NAME": "nmap"}
	if err := h.injectTargetSecret(context.Background(), env); err != nil {
		t.Fatalf("injectTargetSecret: %v", err)
	}

	if len(env) != 1 || env["GIBSON_TOOL_NAME"] != "nmap" {
		t.Errorf("env = %v, want it untouched", env)
	}
	if len(store.calls) != 0 {
		t.Errorf("store was called %v; a target naming no secret must not reach it", store.calls)
	}
}

// Every failure is loud. Target.credential_id, which this replaced, accepted a
// value only when it parsed as a UUID and dropped it in silence otherwise, so a
// mission could scan an authenticated endpoint, find nothing, and report success.
func TestInjectTargetSecret_FailsLoudly(t *testing.T) {
	cases := []struct {
		name  string
		store CredentialStore
		want  types.ErrorCode
	}{
		{
			name:  "secret does not resolve",
			store: &fakeCredentialStore{err: errors.New(`credential "goat-kubeconfig" not found`)},
			want:  types.CREDENTIAL_NOT_FOUND,
		},
		{
			name:  "secret resolves empty",
			store: &fakeCredentialStore{value: ""},
			want:  types.CREDENTIAL_INVALID,
		},
		{
			name:  "no credential store wired",
			store: nil,
			want:  types.CREDENTIAL_INVALID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := harnessWithTarget(TargetInfo{
				Name:       "kubernetes-goat",
				SecretName: "goat-kubeconfig",
			}, tc.store)

			env := map[string]string{"GIBSON_TOOL_NAME": "kube-bench"}
			err := h.injectTargetSecret(context.Background(), env)
			if err == nil {
				t.Fatal("want an error, got nil: a tool must not launch unauthenticated")
			}
			var gErr *types.GibsonError
			if !errors.As(err, &gErr) {
				t.Fatalf("error is not a *types.GibsonError: %v", err)
			}
			if gErr.Code != tc.want {
				t.Errorf("error code = %q, want %q (err: %v)", gErr.Code, tc.want, err)
			}
			if _, present := env[envToolSecret]; present {
				t.Errorf("%s was set on a failed resolution", envToolSecret)
			}
		})
	}
}

// A store that cannot be built yet is a refused dispatch, never a silent
// degrade. The resolver is lazy because the harness factory is constructed
// before the broker stack exists.
func TestInjectTargetSecret_ResolverError(t *testing.T) {
	h := &DefaultAgentHarness{
		targetInfo:  TargetInfo{Name: "kubernetes-goat", SecretName: "goat-kubeconfig"},
		credentials: func() (CredentialStore, error) { return nil, errors.New("broker stack not wired") },
	}

	err := h.injectTargetSecret(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("want an error when the credential store cannot be built")
	}
	if !strings.Contains(err.Error(), "not usable") {
		t.Errorf("error = %v, want it to say the store is not usable", err)
	}
}

// A resolver that returns a nil store with no error must not be read as "no
// secret needed".
func TestInjectTargetSecret_ResolverReturnsNil(t *testing.T) {
	h := &DefaultAgentHarness{
		targetInfo:  TargetInfo{Name: "kubernetes-goat", SecretName: "goat-kubeconfig"},
		credentials: func() (CredentialStore, error) { return nil, nil },
	}

	if err := h.injectTargetSecret(context.Background(), map[string]string{}); err == nil {
		t.Fatal("want an error when the resolver yields a nil store")
	}
}

// The name is a primary key and the AAD of its own envelope, so " x " and "x"
// are different keys. Validation refuses a padded name at the write boundary;
// here the read side trims rather than resolving a key nobody wrote.
func TestInjectTargetSecret_TrimsTheName(t *testing.T) {
	store := &fakeCredentialStore{value: secretValue}
	h := harnessWithTarget(TargetInfo{Name: "t", SecretName: "  goat-kubeconfig  "}, store)

	if err := h.injectTargetSecret(context.Background(), map[string]string{}); err != nil {
		t.Fatalf("injectTargetSecret: %v", err)
	}
	if len(store.calls) != 1 || store.calls[0] != "goat-kubeconfig" {
		t.Errorf("store calls = %v, want the trimmed name", store.calls)
	}
}

// Whitespace alone is not a secret name. It must dispatch as a target naming
// nothing, not resolve the empty key.
func TestInjectTargetSecret_WhitespaceNameIsNoName(t *testing.T) {
	store := &fakeCredentialStore{value: secretValue}
	h := harnessWithTarget(TargetInfo{Name: "t", SecretName: "   "}, store)

	if err := h.injectTargetSecret(context.Background(), map[string]string{}); err != nil {
		t.Fatalf("injectTargetSecret: %v", err)
	}
	if len(store.calls) != 0 {
		t.Errorf("store was called %v for a whitespace-only name", store.calls)
	}
}

// The structural half of acceptance criterion 5: the two structs that travel
// with a mission both serialize, so neither may carry the plaintext. TargetInfo
// carries the NAME, which is already stored and listed on the target record.
func TestMissionCarriersNeverSerializeTheSecret(t *testing.T) {
	target := TargetInfo{
		Name:       "kubernetes-goat",
		SecretName: "goat-kubeconfig",
		AuthType:   "bearer",
		Connection: map[string]any{"url": "https://10.60.0.11:6443"},
		Metadata:   map[string]any{"note": "staging VPC"},
	}
	missionCtx := NewMissionContext(types.NewID(), "hack-k8s-goat", "recon")
	missionCtx.Metadata = map[string]any{"target": target.Name}

	for _, v := range []any{target, missionCtx} {
		blob, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %T: %v", v, err)
		}
		if strings.Contains(string(blob), secretValue) {
			t.Errorf("%T serialized the secret plaintext: %s", v, blob)
		}
	}

	// And the name does survive, or dispatch could never find the secret.
	blob, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("marshal TargetInfo: %v", err)
	}
	if !strings.Contains(string(blob), "goat-kubeconfig") {
		t.Errorf("TargetInfo dropped the secret NAME, which dispatch needs: %s", blob)
	}
}

// WithSecret is the builder that keeps NewTargetInfoFull's signature and its
// existing callers unchanged.
func TestWithSecret(t *testing.T) {
	got := NewTargetInfoFull(types.NewID(), "goat", "https://10.60.0.11:6443", "kubernetes", nil).
		WithSecret("goat-kubeconfig", "bearer")

	if got.SecretName != "goat-kubeconfig" || got.AuthType != "bearer" {
		t.Errorf("WithSecret = {%q, %q}, want {goat-kubeconfig, bearer}", got.SecretName, got.AuthType)
	}
	if got.Name != "goat" {
		t.Errorf("WithSecret clobbered Name: %q", got.Name)
	}
}
