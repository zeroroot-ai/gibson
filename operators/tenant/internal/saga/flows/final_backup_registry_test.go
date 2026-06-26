// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

import (
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// TestFinalBackupSteps_RegistryContract mirrors
// TestProvisionSteps_RegistryContract for the FinalNeo4jBackup step.
//
// final_backup.go exposes ExportedFinalBackupStep(FinalBackupDeps) for
// tests; the step is also embedded as the first entry of TeardownSteps.
// This contract test reads the metadata directly from the exported
// constructor so the assertion does not depend on TeardownSteps' shape.
func TestFinalBackupSteps_RegistryContract(t *testing.T) {
	step := ExportedFinalBackupStep(FinalBackupDeps{}) // zero deps — only metadata is read
	steps := []saga.Step{step}

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

	// 2. Names unique (trivially true for a single step; kept for
	// uniformity with the other registry tests).
	seen := map[string]bool{}
	for _, s := range steps {
		if seen[s.Name()] {
			t.Errorf("duplicate step name %q in FinalBackup flow", s.Name())
		}
		seen[s.Name()] = true
	}

	// 3. Requires() references only known names. The final-backup step
	// has no upstream deps (it's the head of the teardown saga); any
	// Requires() entry here would be a bug.
	for _, s := range steps {
		for _, dep := range s.Requires() {
			if !seen[dep] {
				t.Errorf("step %q declares Requires=%q but no such step is registered in the FinalBackup flow", s.Name(), dep)
			}
		}
	}

	// 4. Slice order is a valid topo sort (trivially true for one step).
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
					"the dependency must come BEFORE the step in the literal slice.",
					s.Name(), i, dep, j)
			}
		}
	}
}

// TestFinalBackupSteps_NamesStableContract captures the FinalNeo4jBackup
// step name so a rename without an accompanying migration causes a loud
// test failure. The step name is also referenced from teardown.go as the
// Req for DeleteTenantName; renaming requires updating both sites.
func TestFinalBackupSteps_NamesStableContract(t *testing.T) {
	step := ExportedFinalBackupStep(FinalBackupDeps{})
	if got, want := step.Name(), "FinalNeo4jBackup"; got != want {
		t.Errorf("FinalBackup step name drifted: got %q, want %q. "+
			"If a rename is intentional, update both this test AND any "+
			"teardown.go Req declarations that reference it.", got, want)
	}
}
