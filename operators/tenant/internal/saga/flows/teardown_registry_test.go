// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

import (
	"reflect"
	"testing"
)

// TestTeardownSteps_RegistryContract mirrors TestProvisionSteps_RegistryContract
// for the teardown saga. See provision_registry_test.go for the rationale:
// every step must declare Owner (operator-private metadata surfaced via
// ownerProvider) and the literal slice order must be a valid topological
// sort of the Requires() graph so the slice itself documents the runtime
// order.
//
// When this test fails, the fix is to update the Step's StepBase fields
// (Owner / Req) at the factory site — not to add an exception here.
func TestTeardownSteps_RegistryContract(t *testing.T) {
	steps := TeardownSteps(ProvisionDeps{}) // zero deps — only metadata is read

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
			t.Errorf("duplicate step name %q in TeardownSteps", s.Name())
		}
		seen[s.Name()] = true
	}

	// 3. Requires() references only known names.
	for _, s := range steps {
		for _, dep := range s.Requires() {
			if !seen[dep] {
				t.Errorf("step %q declares Requires=%q but no such step is registered in TeardownSteps "+
					"(typo, rename, or missing step). The psaga runner would fail at saga construction.",
					s.Name(), dep)
			}
		}
	}

	// 4. Graph is acyclic and the literal slice order is a valid topo
	// sort. Equivalent assertion: when walking the slice in order, every
	// dependency of step[i] must appear in steps[0..i).
	indexByName := map[string]int{}
	for i, s := range steps {
		indexByName[s.Name()] = i
	}
	for i, s := range steps {
		for _, dep := range s.Requires() {
			j, ok := indexByName[dep]
			if !ok {
				continue // already reported above
			}
			if j >= i {
				t.Errorf("step %q (index %d) declares Requires=%q (index %d) — "+
					"the dependency must come BEFORE the step in the literal slice "+
					"(or the runner's topo sort would reorder and break the "+
					"hand-written TeardownSteps order, which is the readable "+
					"documentation surface).", s.Name(), i, dep, j)
			}
		}
	}
}

// TestTeardownSteps_NamesStableContract captures the current set of
// teardown step names so a rename without an accompanying migration
// causes a loud test failure rather than silent breakage of dashboard /
// alerting surfaces that key by step name.
//
// To rename a step intentionally:
//  1. update the registered name in flows/teardown*.go;
//  2. update this list;
//  3. ship a one-line PR note describing what consumers need to update.
func TestTeardownSteps_NamesStableContract(t *testing.T) {
	steps := TeardownSteps(ProvisionDeps{})
	got := make([]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, s.Name())
	}
	// E8/gibson#805 cutover: the imperative compensation steps that tore
	// down the identity / secrets-backend / grants / data-plane domains
	// (DeprovisionDataPlane, DeleteTenantFGATuples, RemoveZitadelOrg,
	// DeprovisionSecretsBackend) were removed. Those domains are now owned
	// by the four sub-CRDs, whose own finalizers tear them down. The
	// retained teardown saga owns only the foundation cleanup with no
	// owning sub-CRD.
	want := []string{
		"FinalNeo4jBackup",
		"DeleteTenantName",
		"DeleteRedisKeyspace",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(
			"TeardownSteps registered name list drifted from the contract.\n"+
				"  got:  %v\n  want: %v\n"+
				"If a rename is intentional, update both this test AND the "+
				"PR body migration note (see tenant-operator#91).",
			got, want,
		)
	}
}
