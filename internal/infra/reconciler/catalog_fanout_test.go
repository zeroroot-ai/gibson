package reconciler

// catalog_fanout_test.go — first behavior test for the reconciler package.
//
// First tracer-bullet of issue #57 (epic Epic: tdd-coverage-gibson-sdk).
// internal/infra/reconciler/ had zero test files prior to this; the goal here is
// one vertical slice through CatalogFanout.tick's observable behaviour,
// establishing the pattern. Follow-up branches will cover the remaining
// cases enumerated on the issue (idempotency, multi-tenant fan-out,
// empty-catalog / empty-tenant short-circuits, Write-error tolerance).

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// TestCatalogFanoutTick_WritesMissingTuplesForOneTenantOneItem asserts the
// observable outcome of a single tick when one platform-enabled component
// exists, one tenant exists under the system tenant, and that tenant has no
// existing tenant_enabled tuple for the component: the reconciler must call
// Write exactly once with the single missing tuple.
//
// This is a behaviour test through the reconciler's only collaborator
// (authz.Authorizer). It does not assert on the sequence of internal calls;
// it asserts on the resulting state-change request.
func TestCatalogFanoutTick_WritesMissingTuplesForOneTenantOneItem(t *testing.T) {
	az := &recordingAuthorizer{
		listObjects: map[listObjectsKey][]string{
			// Platform catalog: one component is platform_enabled by the system tenant.
			{User: "system_tenant:_system", Relation: "platform_enabled", ObjectType: "component"}: {"component:plugin/a"},
			// Tenant t1 has no existing tenant_enabled tuples.
			{User: "tenant:t1", Relation: "tenant_enabled", ObjectType: "component"}: {},
		},
		listUsers: map[listUsersKey][]string{
			// Tenants under the system tenant: one tenant. Keyed by the
			// system_tenant object the fan-out enumerates parents of.
			{ObjectType: "system_tenant", Object: "system_tenant:_system", Relation: "parent"}: {"tenant:t1"},
		},
	}

	r := NewCatalogFanout(CatalogFanoutConfig{Authorizer: az})
	r.tick(context.Background())

	want := []authz.Tuple{
		// ADR-0046 option-B baseline: every tenant gets the system backplane.
		{User: "tenant:t1", Relation: "tenant_enabled", Object: "component:_system"},
		{User: "tenant:t1", Relation: "tenant_enabled", Object: "component:plugin/a"},
	}
	if !reflect.DeepEqual(sortTuples(az.writes), sortTuples(want)) {
		t.Errorf("Write tuples mismatch\n  got:  %v\n  want: %v", az.writes, want)
	}
}

// ----- recordingAuthorizer -----

type listObjectsKey struct {
	User       string
	Relation   string
	ObjectType string
}

type listUsersKey struct {
	ObjectType string
	Object     string
	Relation   string
}

// recordingAuthorizer is a hand-rolled stub for the authz.Authorizer
// interface. It serves canned answers for List* and records Write calls so
// tests can assert on the resulting state-change request. The other methods
// are present to satisfy the interface but return zero values; tests that
// need them should grow the stub.
type recordingAuthorizer struct {
	listObjects map[listObjectsKey][]string
	listUsers   map[listUsersKey][]string
	writes      []authz.Tuple
}

func (a *recordingAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	return a.listObjects[listObjectsKey{User: user, Relation: relation, ObjectType: objectType}], nil
}

func (a *recordingAuthorizer) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	return a.listUsers[listUsersKey{ObjectType: objectType, Object: object, Relation: relation}], nil
}

// ListUsersOfType is the typed enumeration the CatalogFanout type-asserts for.
// The canned map is keyed by (objectType, object, relation); userType only
// narrows the FGA user-filter and does not change the fixture lookup.
func (a *recordingAuthorizer) ListUsersOfType(_ context.Context, objectType, object, relation, _ string) ([]string, error) {
	return a.listUsers[listUsersKey{ObjectType: objectType, Object: object, Relation: relation}], nil
}

func (a *recordingAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.writes = append(a.writes, tuples...)
	return nil
}

// Interface-completeness stubs — return zero values; tests that exercise
// these paths should grow recordingAuthorizer rather than hand-rolling
// another stub.
func (a *recordingAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (a *recordingAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (a *recordingAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (a *recordingAuthorizer) StoreID() string                             { return "" }
func (a *recordingAuthorizer) ModelID() string                             { return "" }
func (a *recordingAuthorizer) Close() error                                { return nil }

// sortTuples returns a deterministic copy so reflect.DeepEqual doesn't care
// about insertion order.
func sortTuples(ts []authz.Tuple) []authz.Tuple {
	out := make([]authz.Tuple, len(ts))
	copy(out, ts)
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		if out[i].Relation != out[j].Relation {
			return out[i].Relation < out[j].Relation
		}
		return out[i].Object < out[j].Object
	})
	return out
}
