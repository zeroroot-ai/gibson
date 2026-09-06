// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package harness

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// kindStubRegistry is a minimal component.ComponentRegistry whose Discover
// reports a component present under the kinds recorded in present["<kind>/<name>"].
// Only Discover is exercised by deriveFGAObject/resolveComponentKind; the rest
// satisfy the interface.
type kindStubRegistry struct {
	present map[string]bool
}

func (s kindStubRegistry) Discover(_ context.Context, _, kind, name string) ([]component.ComponentInfo, error) {
	if s.present[kind+"/"+name] {
		return []component.ComponentInfo{{Kind: kind, Name: name}}, nil
	}
	return nil, nil
}

func (kindStubRegistry) Register(context.Context, string, string, string, component.ComponentInfo) (string, error) {
	return "", nil
}
func (kindStubRegistry) Deregister(context.Context, string, string, string, string) error { return nil }
func (kindStubRegistry) RefreshTTL(context.Context, string, string, string, string) error { return nil }
func (kindStubRegistry) DiscoverAll(context.Context, string, string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (kindStubRegistry) ListTenantComponents(context.Context, string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (kindStubRegistry) DiscoverTenantOnly(context.Context, string, string, string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (kindStubRegistry) DiscoverSystemOnly(context.Context, string, string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func TestDeriveFGAObject_KindResolution(t *testing.T) {
	reg := kindStubRegistry{present: map[string]bool{
		"tool/nmap":  true,
		"agent/scan": true,
		"tool/scan":  true, // "scan" is ambiguous: agent AND tool
	}}
	s := &HarnessCallbackService{componentRegistry: reg}
	ctx := context.Background()

	cases := []struct {
		name     string
		resource string
		want     string
		wantErr  bool
	}{
		{"kind-qualified passes through canonical", "tool:nmap", "component:tool/nmap", false},
		{"already canonical passes through", "component:agent/scan", "component:agent/scan", false},
		{"bare name resolves to its single kind", "nmap", "component:tool/nmap", false},
		{"bare ambiguous across kinds fails closed", "scan", "", true},
		{"bare unregistered fails closed", "ghost", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.deriveFGAObject(ctx, "acme", tc.resource)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("deriveFGAObject(%q) = %q, want error", tc.resource, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("deriveFGAObject(%q) unexpected error: %v", tc.resource, err)
			}
			if got != tc.want {
				t.Errorf("deriveFGAObject(%q) = %q, want %q", tc.resource, got, tc.want)
			}
		})
	}
}

// TestDeriveFGAObject_NilRegistryBareFailsClosed: with no registry, a bare
// kind-less resource keeps the fail-closed error from CanonicalComponentResource.
func TestDeriveFGAObject_NilRegistryBareFailsClosed(t *testing.T) {
	s := &HarnessCallbackService{} // componentRegistry nil
	if _, err := s.deriveFGAObject(context.Background(), "acme", "nmap"); err == nil {
		t.Fatal("bare resource with nil registry: want fail-closed error, got nil")
	}
}

// TestResolveComponentKind covers the single/ambiguous/unregistered branches.
func TestResolveComponentKind(t *testing.T) {
	reg := kindStubRegistry{present: map[string]bool{
		"plugin/gitlab": true,
		"agent/dup":     true,
		"plugin/dup":    true,
	}}
	s := &HarnessCallbackService{componentRegistry: reg}
	ctx := context.Background()

	if kind, err := s.resolveComponentKind(ctx, "acme", "gitlab"); err != nil || kind != "plugin" {
		t.Fatalf("resolveComponentKind(gitlab) = (%q,%v), want (plugin,nil)", kind, err)
	}
	if _, err := s.resolveComponentKind(ctx, "acme", "dup"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("resolveComponentKind(dup): want ambiguous error, got %v", err)
	}
	if _, err := s.resolveComponentKind(ctx, "acme", "missing"); err == nil {
		t.Fatal("resolveComponentKind(missing): want not-registered error, got nil")
	}
}
