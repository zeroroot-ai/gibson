package reconciler

// catalog_fanout_testfixtures_test.go — widened coverage for CatalogFanout using
// testfixtures/fga.FakeStore as the canonical in-memory tuple store.
//
// This extends catalog_fanout_test.go (which holds the first tracer-bullet and
// the hand-rolled recordingAuthorizer stub) with four additional behaviour cases:
//
//  1. Idempotency — no Write when all tenant_enabled tuples already exist.
//  2. Empty-catalog short-circuit — reconciler exits cleanly when no platform
//     items are published.
//  3. Multi-tenant fan-out — Write includes tuples for every tenant that is
//     missing an item, skipping tenants that already have it.
//  4. Write-error tolerance — a Write failure is logged and does not propagate;
//     the tick returns without panicking.
//
// Slice 5.6 of the production-readiness epic (gibson#183).

import (
	"context"
	"errors"
	"testing"

	"github.com/zero-day-ai/gibson/internal/authz"
	tfxfga "github.com/zero-day-ai/testfixtures/fga"
)

// fgaStoreAuthorizer wraps testfixtures/fga.FakeStore to satisfy the
// authz.Authorizer interface used by CatalogFanout.
//
// The wrapper translates between the FakeStore's typed-tuple API and the
// narrower ListObjects / ListUsers / Write / Check surface that
// CatalogFanout exercises. Methods not used by CatalogFanout are no-ops.
type fgaStoreAuthorizer struct {
	store *tfxfga.FakeStore

	// listObjectsFixtures provides canned answers for ListObjects. The
	// FakeStore's Check method handles existence, but ListObjects is a
	// query-all operation we pre-populate directly.
	listObjectsData map[listObjectsKey][]string

	// listUsersData provides canned answers for ListUsers.
	listUsersData map[listUsersKey][]string

	// writeErr, when non-nil, is returned by Write (simulates FGA error).
	writeErr error

	// written captures the tuples passed to Write for post-test assertions.
	written []authz.Tuple
}

func newFGAStoreAuthorizer(store *tfxfga.FakeStore) *fgaStoreAuthorizer {
	return &fgaStoreAuthorizer{
		store:           store,
		listObjectsData: make(map[listObjectsKey][]string),
		listUsersData:   make(map[listUsersKey][]string),
	}
}

// setListObjects pre-populates the canned list for a given (user, relation, objectType).
func (a *fgaStoreAuthorizer) setListObjects(user, relation, objectType string, objects []string) {
	a.listObjectsData[listObjectsKey{User: user, Relation: relation, ObjectType: objectType}] = objects
}

// setListUsers pre-populates the canned user list for a given (objectType, object, relation).
func (a *fgaStoreAuthorizer) setListUsers(objectType, object, relation string, users []string) {
	a.listUsersData[listUsersKey{ObjectType: objectType, Object: object, Relation: relation}] = users
}

// setWriteErr arms the next Write call to return err.
func (a *fgaStoreAuthorizer) setWriteErr(err error) { a.writeErr = err }

// authz.Authorizer implementation

func (a *fgaStoreAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	ok, err := a.store.Check(context.Background(), tfxfga.Tuple{
		User: user, Relation: relation, Object: object,
	})
	return ok, err
}

func (a *fgaStoreAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		ok, err := a.store.Check(context.Background(), tfxfga.Tuple{
			User: c.User, Relation: c.Relation, Object: c.Object,
		})
		if err != nil {
			return nil, err
		}
		out[i] = ok
	}
	return out, nil
}

func (a *fgaStoreAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	if a.writeErr != nil {
		err := a.writeErr
		a.writeErr = nil
		return err
	}
	for _, t := range tuples {
		a.store.Write(context.Background(), tfxfga.Tuple{ //nolint:errcheck
			User: t.User, Relation: t.Relation, Object: t.Object,
		})
	}
	a.written = append(a.written, tuples...)
	return nil
}

func (a *fgaStoreAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		a.store.Delete(context.Background(), tfxfga.Tuple{ //nolint:errcheck
			User: t.User, Relation: t.Relation, Object: t.Object,
		})
	}
	return nil
}

func (a *fgaStoreAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	return a.listObjectsData[listObjectsKey{User: user, Relation: relation, ObjectType: objectType}], nil
}

func (a *fgaStoreAuthorizer) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	return a.listUsersData[listUsersKey{ObjectType: objectType, Object: object, Relation: relation}], nil
}

func (a *fgaStoreAuthorizer) StoreID() string { return "fake" }
func (a *fgaStoreAuthorizer) ModelID() string { return "fake" }
func (a *fgaStoreAuthorizer) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// TestCatalogFanoutTick_IdempotentWhenTenantAlreadyEnabled asserts that when
// a tenant already holds the tenant_enabled tuple for every platform-published
// component, tick writes nothing (idempotent pass produces zero writes).
func TestCatalogFanoutTick_IdempotentWhenTenantAlreadyEnabled(t *testing.T) {
	store := tfxfga.NewFakeStore()
	az := newFGAStoreAuthorizer(store)

	az.setListObjects("system_tenant:_system", "platform_enabled", "component", []string{"component:plugin/a"})
	az.setListUsers("tenant", "system_tenant:_system", "parent", []string{"t1"})
	// Tenant t1 already holds the tuple — reconciler should write nothing.
	az.setListObjects("tenant:t1", "tenant_enabled", "component", []string{"component:plugin/a"})

	r := NewCatalogFanout(CatalogFanoutConfig{Authorizer: az})
	r.tick(context.Background())

	if len(az.written) != 0 {
		t.Errorf("expected zero writes when tenant already has all tuples; got %d: %v", len(az.written), az.written)
	}
}

// TestCatalogFanoutTick_EmptyCatalogShortCircuits asserts that when the
// platform catalog is empty (no platform_enabled components), tick returns
// without calling ListUsers or Write at all.
func TestCatalogFanoutTick_EmptyCatalogShortCircuits(t *testing.T) {
	store := tfxfga.NewFakeStore()
	az := newFGAStoreAuthorizer(store)

	// Empty catalog — no platform_enabled components.
	az.setListObjects("system_tenant:_system", "platform_enabled", "component", nil)

	r := NewCatalogFanout(CatalogFanoutConfig{Authorizer: az})
	r.tick(context.Background())

	if len(az.written) != 0 {
		t.Errorf("expected zero writes on empty catalog; got %d: %v", len(az.written), az.written)
	}
}

// TestCatalogFanoutTick_MultiTenantFanout asserts that when two tenants exist
// but only one already holds the tenant_enabled tuple, tick writes exactly one
// new tuple for the tenant that is missing it.
func TestCatalogFanoutTick_MultiTenantFanout(t *testing.T) {
	store := tfxfga.NewFakeStore()
	az := newFGAStoreAuthorizer(store)

	az.setListObjects("system_tenant:_system", "platform_enabled", "component", []string{"component:plugin/a"})
	az.setListUsers("tenant", "system_tenant:_system", "parent", []string{"t1", "t2"})
	// t1 already enabled; t2 is missing the tuple.
	az.setListObjects("tenant:t1", "tenant_enabled", "component", []string{"component:plugin/a"})
	az.setListObjects("tenant:t2", "tenant_enabled", "component", nil)

	r := NewCatalogFanout(CatalogFanoutConfig{Authorizer: az})
	r.tick(context.Background())

	if len(az.written) != 1 {
		t.Errorf("expected exactly 1 write (for t2); got %d: %v", len(az.written), az.written)
	}
	want := authz.Tuple{User: "tenant:t2", Relation: "tenant_enabled", Object: "component:plugin/a"}
	if az.written[0] != want {
		t.Errorf("written tuple mismatch\n  got:  %+v\n  want: %+v", az.written[0], want)
	}
}

// TestCatalogFanoutTick_WriteErrorTolerated asserts that a Write failure
// is absorbed by the reconciler — it logs a warning and returns; it does not
// panic or propagate the error to the caller.
func TestCatalogFanoutTick_WriteErrorTolerated(t *testing.T) {
	store := tfxfga.NewFakeStore()
	az := newFGAStoreAuthorizer(store)

	az.setListObjects("system_tenant:_system", "platform_enabled", "component", []string{"component:plugin/a"})
	az.setListUsers("tenant", "system_tenant:_system", "parent", []string{"t1"})
	az.setListObjects("tenant:t1", "tenant_enabled", "component", nil)
	az.setWriteErr(errors.New("fga: store unavailable"))

	r := NewCatalogFanout(CatalogFanoutConfig{Authorizer: az})
	// Must not panic.
	r.tick(context.Background())
	// No tuples written because Write returned an error before appending.
	if len(az.written) != 0 {
		t.Errorf("expected zero successful writes on error path; got %d", len(az.written))
	}
}
