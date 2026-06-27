// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// ownerProvider is the operator-private interface that surfaces the
// StepBase.Owner field. Steps that don't embed StepBase MUST implement
// this themselves; the contract test refuses anything that doesn't.
type ownerProvider interface {
	GetOwner() string
}

// TestProvisionSteps_RegistryContract locks the invariants from
// tenant-operator#83 against the provisioning saga:
//
//   - every step declares a non-empty Owner (operator-private metadata
//     surfaced via OwnerProvider; future alerting routes by this);
//   - step names are unique (Requires() reference and Status condition
//     bookkeeping both key by name);
//   - the dependency graph is acyclic and references only known step
//     names (this is what the psaga runner needs to topo-sort without
//     error);
//   - the literal slice order in ProvisionSteps is a valid topological
//     sort of the Requires() graph — so a reader can use the slice as
//     plain-language documentation of the runtime order without
//     simulating the sort.
//
// When this test fails, the fix is to update the Step's StepBase fields
// (Owner / Req) at the factory site — not to add an exception here.
// Drift in the graph is the bug class this lock is designed to catch
// (root cause behind tenant-operator#57 and the PRD #76 module 1 fix).
func TestProvisionSteps_RegistryContract(t *testing.T) {
	steps := ProvisionSteps(ProvisionDeps{}) // zero deps — only metadata is read

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
			t.Errorf("duplicate step name %q in ProvisionSteps", s.Name())
		}
		seen[s.Name()] = true
	}

	// 3. Requires() references only known names.
	for _, s := range steps {
		for _, dep := range s.Requires() {
			if !seen[dep] {
				t.Errorf("step %q declares Requires=%q but no such step is registered in ProvisionSteps "+
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
					"hand-written ProvisionSteps order, which is the readable "+
					"documentation surface).", s.Name(), i, dep, j)
			}
		}
	}
}

// TestProvisionSteps_NamesStableContract acts as a stable-id break
// detector: it captures the current set of step names so a rename
// without an accompanying migration causes a loud test failure rather
// than silent breakage of every reconcile-history dashboard / alert
// that keys by step name.
//
// To rename a step intentionally:
//  1. update the registered name in flows/<file>.go;
//  2. update this list;
//  3. ship a one-line PR note describing what consumers (dashboard
//     ProvisioningPanel, SDK panel renderer, alerting) need to update.
//
// Renaming without doing (3) is the contract-break class this guards.
func TestProvisionSteps_NamesStableContract(t *testing.T) {
	steps := ProvisionSteps(ProvisionDeps{})
	got := make([]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, s.Name())
	}
	// E8/gibson#805 cutover: the identity / secrets-backend / grants /
	// data-plane domains are now provisioned by the four owned sub-CRDs
	// (TenantIdentity #803, TenantSecretsBackend #802, TenantGrants #804,
	// TenantDataPlane #801). The corresponding inline saga steps
	// (EnsureZitadelOrg, ProvisionSecretsBackend, ConfigureSecretsJWTAuth,
	// RegisterTenantWithPlatform, DataPlaneProvisioned, TenantBrokerConfigWritten)
	// were removed. The retained provision saga owns only the foundation
	// steps with no owning sub-CRD.
	want := []string{
		"InitRedisKeyspace",
		"PublishTenantName",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(
			"ProvisionSteps registered name list drifted from the contract.\n"+
				"  got:  %v\n  want: %v\n"+
				"If a rename is intentional, update both this test AND the "+
				"PR body migration note (see tenant-operator#83).",
			got, want,
		)
	}
}

// compile-time check: saga.StepBase satisfies ownerProvider.
var _ ownerProvider = saga.StepBase{}
