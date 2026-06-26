// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Regression test pinning the property "non-plugin provisioning never writes
// can_resolve tuples" per non-plugin-secret-isolation Phase 4 Task 11
// (Requirement 3 of that spec, derived from secrets-broker Spec 1 R8).
//
// This test fixtures the tenant-operator's full provisioning code path
// (EnrollmentIssuanceSteps) for kind=AGENT, kind=TOOL, kind=PLUGIN, captures
// every FGA tuple write performed end-to-end, and asserts:
//
//   - kind=AGENT  → zero tuples with relation can_resolve
//   - kind=TOOL   → zero tuples with relation can_resolve
//   - kind=PLUGIN → exactly one tuple matching
//                   (plugin_principal:enrollment-<UID>, can_resolve,
//                    secret:tenant-<tenant_id>:*)
//
// Unlike enrollment_secrets_test.go (which runs only the
// WriteSecretResolveGrantFGA step in isolation), this test runs the full
// EnrollmentIssuanceSteps saga so that any future refactor that moves the
// can_resolve tuple write to a different step, or adds a new step that
// emits a credential-related tuple for a non-plugin kind, will fail this
// test. The test is intentionally end-to-end at the saga level.
//
// Per the task spec: production tuple-write code is NOT modified by this
// task. The test pins the existing property.

package flows

import (
	"context"
	"fmt"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// recordingFGA is a fake FGA client used by the regression test. It records
// every tuple passed to Write() and never persists anything to a real OpenFGA
// store. Concurrency-safe so it can be reused across sub-tests if needed.
type recordingFGA struct {
	mu      sync.Mutex
	written []fga.Tuple
}

func (r *recordingFGA) Write(_ context.Context, tuples []fga.Tuple) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, tuples...)
	return nil
}

func (r *recordingFGA) Delete(_ context.Context, _ []fga.Tuple) error { return nil }
func (r *recordingFGA) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) {
	return nil, nil
}
func (r *recordingFGA) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
func (r *recordingFGA) Ping(_ context.Context) error { return nil }

func (r *recordingFGA) snapshot() []fga.Tuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]fga.Tuple, len(r.written))
	copy(out, r.written)
	return out
}

// canResolveTuples returns the subset of recorded tuples whose relation is
// can_resolve. Used to assert the credential-grant property by kind.
func canResolveTuples(tuples []fga.Tuple) []fga.Tuple {
	var out []fga.Tuple
	for _, t := range tuples {
		if t.Relation == "can_resolve" {
			out = append(out, t)
		}
	}
	return out
}

// runIssuanceSteps runs every step in EnrollmentIssuanceSteps for the given
// enrollment, honouring each step's Skip predicate. This mirrors the saga
// runner's behaviour but stays in-package so the test does not depend on the
// production saga.Run loop.
func runIssuanceSteps(t *testing.T, ae *gibsonv1alpha1.AgentEnrollment, fgaClient fga.Client) {
	t.Helper()
	deps := EnrollmentDeps{FGA: fgaClient}
	steps := EnrollmentIssuanceSteps(deps)
	ctx := context.Background()
	for _, step := range steps {
		if step.Skip(ae) {
			continue
		}
		if _, err := step.Provision(ctx, ae, nil); err != nil {
			t.Fatalf("step %q returned unexpected error: %v", step.Name(), err)
		}
	}
}

// makeEnrollmentForKind builds an AgentEnrollment with a single component ref
// in Spec.ComponentGrants (so writeAgentGrants has something to do — keeps the
// fixture realistic) and a stable AgentName (required for the plugin can_invoke step).
func makeEnrollmentForKind(uid types.UID, tenantID string, kind gibsonv1alpha1.PrincipalKind) *gibsonv1alpha1.AgentEnrollment {
	return &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "regression-enrollment",
			Namespace: tenantID,
			UID:       uid,
		},
		Spec: gibsonv1alpha1.AgentEnrollmentSpec{
			AgentName:     "regression-agent",
			Mode:          gibsonv1alpha1.AgentModeAutonomous,
			PrincipalKind: kind,
			ComponentGrants: []gibsonv1alpha1.ComponentRef{
				{Kind: "tool", Name: "noop"},
			},
		},
	}
}

// TestProvisioning_NonPluginNeverWritesCanResolveTuple is the single
// regression test required by spec non-plugin-secret-isolation Task 11.
// It runs EnrollmentIssuanceSteps end-to-end for AGENT, TOOL, and PLUGIN
// principal kinds and asserts the can_resolve relation appears exactly
// where Spec 1 R8 says it should: only for plugin_principal.
func TestProvisioning_NonPluginNeverWritesCanResolveTuple(t *testing.T) {
	cases := []struct {
		name            string
		kind            gibsonv1alpha1.PrincipalKind
		uid             types.UID
		tenantID        string
		wantCanResolve  int
		wantPluginTuple bool // expect the canonical plugin_principal can_resolve tuple
	}{
		{
			name:            "agent_writes_zero_can_resolve",
			kind:            gibsonv1alpha1.PrincipalKindAgent,
			uid:             "uid-regression-agent",
			tenantID:        "tenant-regression-a",
			wantCanResolve:  0,
			wantPluginTuple: false,
		},
		{
			name:            "agent_default_empty_kind_writes_zero_can_resolve",
			kind:            "", // legacy default — must behave like agent
			uid:             "uid-regression-agent-default",
			tenantID:        "tenant-regression-default",
			wantCanResolve:  0,
			wantPluginTuple: false,
		},
		{
			name:            "tool_writes_zero_can_resolve",
			kind:            gibsonv1alpha1.PrincipalKindTool,
			uid:             "uid-regression-tool",
			tenantID:        "tenant-regression-t",
			wantCanResolve:  0,
			wantPluginTuple: false,
		},
		{
			name:            "plugin_writes_exactly_one_can_resolve",
			kind:            gibsonv1alpha1.PrincipalKindPlugin,
			uid:             "uid-regression-plugin",
			tenantID:        "tenant-regression-p",
			wantCanResolve:  1,
			wantPluginTuple: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeFGA := &recordingFGA{}
			ae := makeEnrollmentForKind(tc.uid, tc.tenantID, tc.kind)

			runIssuanceSteps(t, ae, fakeFGA)

			tuples := fakeFGA.snapshot()
			got := canResolveTuples(tuples)
			if len(got) != tc.wantCanResolve {
				t.Fatalf("kind=%q produced %d can_resolve tuples, want %d; all tuples: %+v",
					tc.kind, len(got), tc.wantCanResolve, tuples)
			}

			if tc.wantPluginTuple {
				wantUser := fmt.Sprintf("plugin_principal:enrollment-%s", tc.uid)
				wantObject := fmt.Sprintf("secret:tenant-%s:*", tc.tenantID)
				match := got[0]
				if match.User != wantUser {
					t.Errorf("can_resolve tuple User = %q, want %q", match.User, wantUser)
				}
				if match.Relation != "can_resolve" {
					t.Errorf("can_resolve tuple Relation = %q, want %q", match.Relation, "can_resolve")
				}
				if match.Object != wantObject {
					t.Errorf("can_resolve tuple Object = %q, want %q", match.Object, wantObject)
				}
			} else {
				// Defense-in-depth: even if some future refactor introduces a
				// can_resolve tuple under a different relation alias, this
				// loop catches any tuple whose object matches the secret
				// resource type for the wrong principal kind.
				for _, tup := range tuples {
					if hasSecretObjectPrefix(tup.Object) && hasNonPluginPrincipal(tup.User) {
						t.Errorf("kind=%q wrote a tuple targeting a secret object from a non-plugin principal: %+v",
							tc.kind, tup)
					}
				}
			}
		})
	}
}

// TestProvisioning_BackfillSecretGrantsRemainsPluginOnly pins the property
// for the existing BackfillSecretResolveGrants helper: the function is
// typed to PluginEnrollment and produces only plugin_principal can_resolve
// tuples. If a future refactor ever loosens the input type to include
// agent or tool enrollments, this test will fail. Per Task 12 (Backfill
// safety check, Requirement 3.4).
func TestProvisioning_BackfillSecretGrantsRemainsPluginOnly(t *testing.T) {
	fakeFGA := &recordingFGA{}
	ctx := context.Background()

	plugins := []fga.PluginEnrollment{
		{EnrollmentUID: "enrollment-backfill-1", TenantID: "tenant-backfill-a"},
		{EnrollmentUID: "enrollment-backfill-2", TenantID: "tenant-backfill-b"},
	}
	results := fga.BackfillSecretResolveGrants(ctx, fakeFGA, plugins)
	if len(results) != len(plugins) {
		t.Fatalf("expected %d backfill results, got %d", len(plugins), len(results))
	}

	tuples := fakeFGA.snapshot()
	if len(tuples) != len(plugins) {
		t.Fatalf("expected %d tuples written, got %d: %+v", len(plugins), len(tuples), tuples)
	}
	for _, tup := range tuples {
		if tup.Relation != "can_resolve" {
			t.Errorf("backfill produced unexpected relation %q on tuple %+v", tup.Relation, tup)
		}
		if !hasPluginPrincipal(tup.User) {
			t.Errorf("backfill produced can_resolve tuple for non-plugin principal: %+v", tup)
		}
	}
}

// hasSecretObjectPrefix returns true if the given FGA object identifier names
// a secret resource (any object whose type prefix is "secret:").
func hasSecretObjectPrefix(object string) bool {
	const prefix = "secret:"
	return len(object) >= len(prefix) && object[:len(prefix)] == prefix
}

// hasNonPluginPrincipal returns true if the given FGA user identifier is an
// agent_principal or tool_principal (the two non-plugin classes that must
// never receive can_resolve on secrets).
func hasNonPluginPrincipal(user string) bool {
	return hasPrefix(user, "agent_principal:") || hasPrefix(user, "tool_principal:")
}

// hasPluginPrincipal returns true if the given FGA user identifier is a
// plugin_principal.
func hasPluginPrincipal(user string) bool {
	return hasPrefix(user, "plugin_principal:")
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// Compile-time check: ensure recordingFGA satisfies the fga.Client interface.
var _ fga.Client = (*recordingFGA)(nil)

// Compile-time check: ensure runIssuanceSteps stays in scope and is referenced
// (the linter would otherwise complain in a hypothetical refactor that
// inlines the helper).
var _ = func(t *testing.T, ae *gibsonv1alpha1.AgentEnrollment, c fga.Client) {
	runIssuanceSteps(t, ae, c)
}

// Compile-time guard: ensure the saga.Step type is referenced so that any
// future renaming of saga.Step surfaces a build error here too.
var _ saga.Step
