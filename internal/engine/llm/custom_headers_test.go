// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

import (
	"errors"
	"strings"
	"testing"
)

func TestParseCustomHeaders_AcceptsOnlyTheWorkspaceHeader(t *testing.T) {
	h, err := ParseCustomHeaders("\n Anthropic-Workspace-Id :  wrkspc_01Abc \n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := h.Get(WorkspaceHeader); got != "wrkspc_01Abc" {
		t.Errorf("workspace header = %q", got)
	}
	for name, bad := range map[string]string{
		"no colon":         "anthropic-workspace-id wrkspc_1",
		"empty name":       ": wrkspc_1",
		"another header":   "X-Other: v",
		"the api key":      "x-api-key: sk-ant-secret",
		"a base redirect":  "Host: evil.example",
		"value shape":      "anthropic-workspace-id: not-an-id",
		"value with space": "anthropic-workspace-id: wrkspc_1 extra",
		"value with colon": "anthropic-workspace-id: wrkspc_1:x",
		"repeated":         "anthropic-workspace-id: wrkspc_1\nanthropic-workspace-id: wrkspc_2",
		"second header":    "anthropic-workspace-id: wrkspc_1\nX-Other: v",
	} {
		_, err := ParseCustomHeaders(bad)
		if !errors.Is(err, ErrInvalidCustomHeaders) {
			t.Errorf("%s: err = %v, want ErrInvalidCustomHeaders", name, err)
			continue
		}
		if strings.Contains(err.Error(), "sk-ant-secret") {
			t.Errorf("%s: the error holds the value", name)
		}
	}
}

func TestCanonicalCustomHeaders(t *testing.T) {
	got, err := CanonicalCustomHeaders("  ANTHROPIC-WORKSPACE-ID:wrkspc_1\n")
	if err != nil || got != "anthropic-workspace-id: wrkspc_1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := CanonicalCustomHeaders("  "); err != nil || got != "" {
		t.Fatalf("empty value: got %q, %v", got, err)
	}
	if _, err := CanonicalCustomHeaders("x-api-key: k"); err == nil {
		t.Fatal("want an error")
	}
}
