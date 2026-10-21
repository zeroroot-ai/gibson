// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestCheckCredentials_StoresOnlyACheckedWorkspaceHeader(t *testing.T) {
	in := &ProviderConfigInput{Type: llm.ProviderAnthropic, Credentials: map[string]string{
		"api_key": "k", llm.CustomHeadersKey: " ANTHROPIC-WORKSPACE-ID:wrkspc_1 \n",
	}}
	out, err := checkCredentials(in)
	if err != nil {
		t.Fatalf("checkCredentials: %v", err)
	}
	if got := out.Credentials[llm.CustomHeadersKey]; got != "anthropic-workspace-id: wrkspc_1" {
		t.Errorf("stored value = %q, want the canonical form", got)
	}
	if in.Credentials[llm.CustomHeadersKey] == out.Credentials[llm.CustomHeadersKey] {
		t.Error("the caller map must not change")
	}
	if out.Credentials["api_key"] != "k" {
		t.Error("the other fields must stay")
	}
}

func TestCheckCredentials_RefusesWhatTheAllowlistRefuses(t *testing.T) {
	for name, in := range map[string]*ProviderConfigInput{
		"another header": {Type: llm.ProviderAnthropic, Credentials: map[string]string{llm.CustomHeadersKey: "X-Other: v"}},
		"a bad value":    {Type: llm.ProviderAnthropic, Credentials: map[string]string{llm.CustomHeadersKey: "anthropic-workspace-id: x y"}},
		"another type":   {Type: llm.ProviderOpenAI, Credentials: map[string]string{llm.CustomHeadersKey: "anthropic-workspace-id: wrkspc_1"}},
	} {
		if _, err := checkCredentials(in); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want ErrInvalidCredentials", name, err)
		}
	}
	plain := &ProviderConfigInput{Type: llm.ProviderOpenAI, Credentials: map[string]string{"api_key": "k"}}
	if out, err := checkCredentials(plain); err != nil || out != plain {
		t.Errorf("an input with no header field must pass unchanged: %v", err)
	}
}

// Create and Update run the check before they reach the database. The store
// here cannot reach Postgres, so a bad value that is refused with
// ErrInvalidCredentials was refused by the check and by nothing else, and a
// good value passes the check and fails later for another cause.
func TestBrokerStore_CreateAndUpdateRunTheCredentialCheck(t *testing.T) {
	store := newUnreachableStore(t)
	ctx := context.Background()
	input := func(headers string) *ProviderConfigInput {
		return &ProviderConfigInput{
			Name: "exit-anthropic", Type: llm.ProviderAnthropic,
			Credentials: map[string]string{"api_key": "k", llm.CustomHeadersKey: headers},
		}
	}
	for op, run := range map[string]func(*ProviderConfigInput) error{
		"Create": func(in *ProviderConfigInput) error { _, err := store.Create(ctx, "tenant-a", in); return err },
		"Update": func(in *ProviderConfigInput) error { _, err := store.Update(ctx, "tenant-a", in.Name, in); return err },
	} {
		if err := run(input("x-api-key: other")); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s with a bad header: err = %v, want ErrInvalidCredentials", op, err)
		}
		err := run(input("anthropic-workspace-id: wrkspc_1"))
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s with a good header: err = %v, want a database error", op, err)
		}
	}
}
