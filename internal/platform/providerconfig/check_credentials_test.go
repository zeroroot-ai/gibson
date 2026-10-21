// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
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
