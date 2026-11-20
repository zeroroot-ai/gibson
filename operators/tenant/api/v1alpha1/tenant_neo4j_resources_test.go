// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

func neo4jQty(s string) *resource.Quantity {
	q := resource.MustParse(s)
	return &q
}

func TestTenantNeo4jResourcesValidateAcceptsAUsableSize(t *testing.T) {
	for name, r := range map[string]*TenantNeo4jResources{
		"nil":            nil,
		"empty":          {},
		"all fields":     {Storage: neo4jQty("50Gi"), CPU: neo4jQty("500m"), Memory: neo4jQty("4Gi")},
		"memory only":    {Memory: neo4jQty("1Gi")},
		"minimum memory": {Memory: neo4jQty(MinNeo4jMemory)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.Validate(); err != nil {
				t.Fatalf("Validate refused a usable size: %v", err)
			}
		})
	}
}

// FAILING FIXTURE. Each size here is one the operator cannot apply.
func TestTenantNeo4jResourcesValidateRefusesAnUnusableSize(t *testing.T) {
	for name, tc := range map[string]struct {
		r    *TenantNeo4jResources
		want string
	}{
		"zero storage":     {&TenantNeo4jResources{Storage: neo4jQty("0")}, "storage"},
		"negative storage": {&TenantNeo4jResources{Storage: neo4jQty("-1Gi")}, "storage"},
		"zero cpu":         {&TenantNeo4jResources{CPU: neo4jQty("0")}, "cpu"},
		"zero memory":      {&TenantNeo4jResources{Memory: neo4jQty("0")}, "memory"},
		"memory too small": {&TenantNeo4jResources{Memory: neo4jQty("4Mi")}, "at least " + MinNeo4jMemory},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.r.Validate()
			if err == nil {
				t.Fatal("Validate accepted a size the operator cannot apply")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}
