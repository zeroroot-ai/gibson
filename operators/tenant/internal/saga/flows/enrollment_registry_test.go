/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package flows

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// TestEnrollmentIssuanceSteps_RegistryContract mirrors
// TestProvisionSteps_RegistryContract for the enrollment issuance saga
// (WriteComponentGrantsFGA, WriteSecretResolveGrantFGA,
// WritePluginCanInvokeGrantFGA). See provision_registry_test.go for the
// rationale.
func TestEnrollmentIssuanceSteps_RegistryContract(t *testing.T) {
	assertEnrollmentContract(t, "EnrollmentIssuanceSteps",
		EnrollmentIssuanceSteps(EnrollmentDeps{}))
}

// TestEnrollmentRevocationSteps_RegistryContract is the revocation-side
// counterpart (DeleteAgentFGATuples).
func TestEnrollmentRevocationSteps_RegistryContract(t *testing.T) {
	assertEnrollmentContract(t, "EnrollmentRevocationSteps",
		EnrollmentRevocationSteps(EnrollmentDeps{}))
}

// assertEnrollmentContract factors the per-flow invariants into one
// helper since both enrollment flows share the same contract.
func assertEnrollmentContract(t *testing.T, flowName string, steps []saga.Step) {
	t.Helper()

	// 1. Every step has a non-empty Owner.
	for _, s := range steps {
		op, ok := s.(ownerProvider)
		if !ok {
			t.Errorf("step %q must embed saga.StepBase or implement ownerProvider", s.Name())
			continue
		}
		if op.GetOwner() == "" {
			t.Errorf("step %q has empty Owner — set StepBase.Owner at the factory site", s.Name())
		}
	}

	// 2. Names unique.
	seen := map[string]bool{}
	for _, s := range steps {
		if seen[s.Name()] {
			t.Errorf("duplicate step name %q in %s", s.Name(), flowName)
		}
		seen[s.Name()] = true
	}

	// 3. Requires() references only known names.
	for _, s := range steps {
		for _, dep := range s.Requires() {
			if !seen[dep] {
				t.Errorf("step %q declares Requires=%q but no such step is registered in %s "+
					"(typo, rename, or missing step).", s.Name(), dep, flowName)
			}
		}
	}

	// 4. Graph is acyclic and the literal slice order is a valid topo sort.
	indexByName := map[string]int{}
	for i, s := range steps {
		indexByName[s.Name()] = i
	}
	for i, s := range steps {
		for _, dep := range s.Requires() {
			j, ok := indexByName[dep]
			if !ok {
				continue
			}
			if j >= i {
				t.Errorf("step %q (index %d) declares Requires=%q (index %d) — "+
					"the dependency must come BEFORE the step in the literal "+
					"slice (the hand-written %s order is the readable "+
					"documentation surface).", s.Name(), i, dep, j, flowName)
			}
		}
	}
}

// TestEnrollmentIssuanceSteps_NamesStableContract captures the current
// set of issuance step names. Rename → migrate consumers → update test.
func TestEnrollmentIssuanceSteps_NamesStableContract(t *testing.T) {
	steps := EnrollmentIssuanceSteps(EnrollmentDeps{})
	got := make([]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, s.Name())
	}
	want := []string{
		"WriteComponentGrantsFGA",
		"WriteSecretResolveGrantFGA",
		"WritePluginCanInvokeGrantFGA",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(
			"EnrollmentIssuanceSteps registered name list drifted from the contract.\n"+
				"  got:  %v\n  want: %v\n"+
				"If a rename is intentional, update both this test AND the "+
				"PR body migration note (see tenant-operator#91).",
			got, want,
		)
	}
}

// TestEnrollmentRevocationSteps_NamesStableContract is the revocation
// counterpart.
func TestEnrollmentRevocationSteps_NamesStableContract(t *testing.T) {
	steps := EnrollmentRevocationSteps(EnrollmentDeps{})
	got := make([]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, s.Name())
	}
	want := []string{
		"DeleteAgentFGATuples",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(
			"EnrollmentRevocationSteps registered name list drifted from the contract.\n"+
				"  got:  %v\n  want: %v\n"+
				"If a rename is intentional, update both this test AND the "+
				"PR body migration note (see tenant-operator#91).",
			got, want,
		)
	}
}
