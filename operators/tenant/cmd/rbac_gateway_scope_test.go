// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// The tenant operator writes the gateway objects and the credential Secrets in
// the dedicated namespace of the gateway only. The chart gives that access with
// a namespaced Role (gibson-tenant-operator-gateway). The generated ClusterRole
// must hold none of these kinds, so the operator has no cluster-wide grant on
// them. The namespace is a runtime value, so a kubebuilder marker cannot name it.

type roleRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
}

type roleFile struct {
	Rules []roleRule `json:"rules"`
}

// gatewayScopeViolations returns each rule that grants a gateway kind or Secrets
// at cluster scope.
func gatewayScopeViolations(raw []byte) ([]string, error) {
	var role roleFile
	if err := yaml.Unmarshal(raw, &role); err != nil {
		return nil, err //nolint:wrapcheck // a test helper
	}
	forbidden := map[string]bool{
		"agentgatewaybackends": true, "agentgatewaypolicies": true, "httproutes": true, "secrets": true,
	}
	var out []string
	for _, r := range role.Rules {
		for _, res := range r.Resources {
			if forbidden[res] {
				out = append(out, res)
			}
		}
	}
	return out, nil
}

func TestGeneratedRoleHasNoClusterWideGatewayKindOrSecret(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "config", "rbac", "role.yaml"))
	if err != nil {
		t.Fatalf("read the generated role: %v", err)
	}
	got, err := gatewayScopeViolations(raw)
	if err != nil {
		t.Fatalf("parse the generated role: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("the ClusterRole grants %v at cluster scope: move them to the namespaced Role of the gateway", got)
	}
}

// The failing fixture: a role that lists a forbidden kind is reported.
func TestGatewayScopeGuardFailsOnAViolation(t *testing.T) {
	bad := []byte("rules:\n- apiGroups: [agentgateway.dev]\n  resources: [agentgatewaybackends]\n  verbs: [get]\n" +
		"- apiGroups: [\"\"]\n  resources: [secrets]\n  verbs: [get]\n")
	got, err := gatewayScopeViolations(bad)
	if err != nil || len(got) != 2 {
		t.Fatalf("violations = %v, %v, want two", got, err)
	}
}
