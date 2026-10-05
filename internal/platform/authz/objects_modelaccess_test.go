// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"testing"
)

func TestModelAccessObjects_AreTenantQualified(t *testing.T) {
	p, err := ProviderObject("acme", "anthropic")
	if err != nil || p != "provider:acme/anthropic" {
		t.Errorf("ProviderObject = %q, %v", p, err)
	}
	m, err := ModelObject("acme", "meta/llama3:8b")
	if err != nil || m != "model:acme/meta/llama3:8b" {
		t.Errorf("ModelObject = %q, %v", m, err)
	}
	for name, tc := range map[string][2]string{
		"no tenant":             {"", "anthropic"},
		"tenant with separator": {"victim-co/acme", "anthropic"},
		"tenant with colon":     {"a:b", "anthropic"},
		"no name":               {"acme", ""},
		"userset marker":        {"acme", "opus#member"},
		"whitespace":            {"acme", "opus 4"},
	} {
		if got, err := ProviderObject(tc[0], tc[1]); !errors.Is(err, ErrInvalidModelAccessObject) {
			t.Errorf("%s: ProviderObject = %q, %v; want ErrInvalidModelAccessObject", name, got, err)
		}
	}
}

func TestModelAccessNameFromObject_OnlyTheTenantsOwn(t *testing.T) {
	typ, name, ok := ModelAccessNameFromObject("acme", "provider:acme/anthropic")
	if !ok || typ != "provider" || name != "anthropic" {
		t.Errorf("provider = %q, %q, %v", typ, name, ok)
	}
	typ, name, ok = ModelAccessNameFromObject("acme", "model:acme/meta/llama3:8b")
	if !ok || typ != "model" || name != "meta/llama3:8b" {
		t.Errorf("model = %q, %q, %v", typ, name, ok)
	}
	for _, tc := range [][2]string{
		{"acme", "provider:victim-co/anthropic"},
		{"acme", "provider:anthropic"},
		{"acme", "model:acme/"},
		{"acme", "team:acme/eng"},
		{"", "provider:acme/anthropic"},
	} {
		if _, _, ok := ModelAccessNameFromObject(tc[0], tc[1]); ok {
			t.Errorf("ModelAccessNameFromObject(%q, %q) reported the object as the tenant's", tc[0], tc[1])
		}
	}
}
