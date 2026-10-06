// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"testing"

	"github.com/zeroroot-ai/sdk/plugin/manifest"
)

// The declaration passes the validation of the SDK, runs as a pod, declares
// each method that main registers, and declares the one broker secret.
func TestDeclaration(t *testing.T) {
	m := declaration()
	manifest.ApplyDefaults(m)
	if err := manifest.Validate(m); err != nil {
		t.Fatalf("the declaration does not validate: %v", err)
	}
	if m.Spec.Runtime != "pod" {
		t.Errorf("runtime = %q, want pod (the chart refuses process)", m.Spec.Runtime)
	}
	want := map[string]bool{"GetRepository": true, "ListIssues": true, "CreateIssue": true}
	for _, d := range m.Spec.Methods {
		if !want[d.Name] || d.Description == "" {
			t.Errorf("method %q (description %q) is not one that main registers with a description", d.Name, d.Description)
		}
		delete(want, d.Name)
	}
	for name := range want {
		t.Errorf("method %s is not declared", name)
	}
	if len(m.Spec.Secrets) != 1 || m.Spec.Secrets[0].Name != credName || !m.Spec.Secrets[0].Required {
		t.Errorf("secrets = %+v, want the one required %s", m.Spec.Secrets, credName)
	}
}
