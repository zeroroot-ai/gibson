/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package flows

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// ---------------------------------------------------------------------------
// fakeZitadel — in-memory Zitadel client for unit tests
// ---------------------------------------------------------------------------

// fakeZitadel implements zitadel.Client without speaking HTTP.
type fakeZitadel struct {
	mu sync.Mutex

	// orgs maps orgID -> Organization
	orgs map[string]*zitadel.Organization
	// orgsByName maps name -> orgID for conflict resolution
	orgsByName map[string]string
	// nextID is the auto-increment source for generated org IDs
	nextID int

	// CreateOrganizationErr overrides CreateOrganization with a fixed error.
	CreateOrganizationErr error
	// GetOrganizationErr overrides GetOrganization with a fixed error.
	GetOrganizationErr error
	// DeleteOrganizationErr overrides DeleteOrganization with a fixed error.
	DeleteOrganizationErr error

	// CreateCalled counts CreateOrganization invocations.
	CreateCalled int
	// GetCalled counts GetOrganization invocations.
	GetCalled int
	// DeleteCalled counts DeleteOrganization invocations.
	DeleteCalled int
}

func newFakeZitadel() *fakeZitadel {
	return &fakeZitadel{
		orgs:       make(map[string]*zitadel.Organization),
		orgsByName: make(map[string]string),
	}
}

func (f *fakeZitadel) CreateOrganization(_ context.Context, name, slug string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CreateCalled++
	if f.CreateOrganizationErr != nil {
		return "", f.CreateOrganizationErr
	}
	// Idempotent: if org with same name exists, return existing ID.
	if id, ok := f.orgsByName[name]; ok {
		return id, nil
	}
	f.nextID++
	id := fmt.Sprintf("org_%d", f.nextID)
	f.orgs[id] = &zitadel.Organization{ID: id, Name: name, Slug: slug}
	f.orgsByName[name] = id
	return id, nil
}

func (f *fakeZitadel) GetOrganization(_ context.Context, orgID string) (*zitadel.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.GetCalled++
	if f.GetOrganizationErr != nil {
		return nil, f.GetOrganizationErr
	}
	org, ok := f.orgs[orgID]
	if !ok {
		return nil, fmt.Errorf("fake zitadel: org %q: %w", orgID, clients.ErrNotFound)
	}
	return org, nil
}

func (f *fakeZitadel) DeleteOrganization(_ context.Context, orgID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DeleteCalled++
	if f.DeleteOrganizationErr != nil {
		return f.DeleteOrganizationErr
	}
	if _, ok := f.orgs[orgID]; !ok {
		return fmt.Errorf("fake zitadel: org %q: %w", orgID, clients.ErrNotFound)
	}
	delete(f.orgs, orgID)
	return nil
}

func (f *fakeZitadel) AddMember(_ context.Context, _, _ string, _ []string) (string, error) {
	return "", nil
}
func (f *fakeZitadel) RemoveMember(_ context.Context, _, _ string) error { return nil }
func (f *fakeZitadel) SendInvitation(_ context.Context, _, _ string, _ []string) (string, error) {
	return "", nil
}
func (f *fakeZitadel) CreateServiceAccount(_ context.Context, _, name string) (string, string, string, error) {
	return "svc-" + name, "client-" + name, "secret-" + name, nil
}
func (f *fakeZitadel) DeleteServiceAccount(_ context.Context, _, _ string) error { return nil }

// compile-time check
var _ zitadel.Client = (*fakeZitadel)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTenant returns the canonical fixture Tenant ("acme" / "Acme Corp").
// Every existing caller passed those exact strings; if a new test needs
// a different name/display, construct a literal Tenant inline.
func newTenant() *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme",
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme Corp",
			Owner:       "owner@example.com",
			Tier:        gibsonv1alpha1.TenantPlanEnterprise,
		},
	}
}

// newFakeK8sClient builds a controller-runtime fake client pre-seeded with the
// given objects and a scheme that includes Gibson CRDs.
func newFakeK8sClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	builder := fake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	return builder.Build()
}

// ---------------------------------------------------------------------------
// EnsureZitadelOrg tests
// ---------------------------------------------------------------------------

// TestEnsureZitadelOrg_CreateFresh verifies that when ZitadelOrgID is empty
// the step calls CreateOrganization and writes the result to Status.
func TestEnsureZitadelOrg_CreateFresh(t *testing.T) {
	fz := newFakeZitadel()
	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()

	step := newEnsureZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true after successful org creation")
	}
	if tenant.Status.ZitadelOrgID == "" {
		t.Fatal("expected ZitadelOrgID to be populated after creation")
	}
	if tenant.Status.ZitadelOrgSlug != "acme" {
		t.Errorf("ZitadelOrgSlug: want %q, got %q", "acme", tenant.Status.ZitadelOrgSlug)
	}
	if fz.CreateCalled != 1 {
		t.Errorf("CreateOrganization call count: want 1, got %d", fz.CreateCalled)
	}
	if fz.GetCalled != 0 {
		t.Errorf("GetOrganization should not be called on fresh create, got %d calls", fz.GetCalled)
	}
}

// TestEnsureZitadelOrg_FindExisting verifies that when ZitadelOrgID is already
// set the step calls GetOrganization to verify and returns done=true without
// calling CreateOrganization.
func TestEnsureZitadelOrg_FindExisting(t *testing.T) {
	fz := newFakeZitadel()
	// Pre-seed the org so GetOrganization succeeds.
	fz.orgs["org_99"] = &zitadel.Organization{ID: "org_99", Name: "Acme Corp", Slug: "acme"}

	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()
	tenant.Status.ZitadelOrgID = "org_99"
	tenant.Status.ZitadelOrgSlug = "acme"

	step := newEnsureZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when org already exists")
	}
	if fz.GetCalled != 1 {
		t.Errorf("GetOrganization call count: want 1, got %d", fz.GetCalled)
	}
	if fz.CreateCalled != 0 {
		t.Errorf("CreateOrganization should not be called when org already confirmed, got %d calls", fz.CreateCalled)
	}
	// Status fields must remain unchanged.
	if tenant.Status.ZitadelOrgID != "org_99" {
		t.Errorf("ZitadelOrgID should remain %q, got %q", "org_99", tenant.Status.ZitadelOrgID)
	}
}

// TestEnsureZitadelOrg_GetNotFound_Recreates verifies that when the status
// carries an org ID that no longer exists in Zitadel (404 from GetOrganization),
// the step clears the stale ID and calls CreateOrganization to re-provision.
func TestEnsureZitadelOrg_GetNotFound_Recreates(t *testing.T) {
	fz := newFakeZitadel()
	// Do NOT seed org_stale — GetOrganization returns 404.

	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()
	tenant.Status.ZitadelOrgID = "org_stale"

	step := newEnsureZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true after re-creation")
	}
	if tenant.Status.ZitadelOrgID == "org_stale" {
		t.Error("stale org ID should have been replaced after 404")
	}
	if tenant.Status.ZitadelOrgID == "" {
		t.Error("ZitadelOrgID should be populated after re-creation")
	}
	if fz.GetCalled != 1 {
		t.Errorf("GetOrganization call count: want 1, got %d", fz.GetCalled)
	}
	if fz.CreateCalled != 1 {
		t.Errorf("CreateOrganization call count after stale-ID path: want 1, got %d", fz.CreateCalled)
	}
}

// TestEnsureZitadelOrg_ConflictIdempotent verifies that a 409 conflict from
// CreateOrganization (org already exists with same name) is resolved inside the
// client and the step receives a valid org ID — returning done=true.
//
// The fakeZitadel models this: CreateOrganization on a name that already exists
// returns the existing ID rather than an error, matching the real httpClient's
// 409→lookup behavior.
func TestEnsureZitadelOrg_ConflictIdempotent(t *testing.T) {
	fz := newFakeZitadel()
	// Seed an existing org so the second CreateOrganization call simulates a conflict.
	fz.orgs["org_1"] = &zitadel.Organization{ID: "org_1", Name: "Acme Corp", Slug: "acme"}
	fz.orgsByName["Acme Corp"] = "org_1"
	fz.nextID = 1 // keep counter consistent

	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()
	// Status is empty — step will call CreateOrganization.

	step := newEnsureZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error on conflict (client handles 409 internally), got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true after conflict-resolved create")
	}
	if tenant.Status.ZitadelOrgID != "org_1" {
		t.Errorf("ZitadelOrgID: want %q, got %q", "org_1", tenant.Status.ZitadelOrgID)
	}
}

// TestEnsureZitadelOrg_PermanentFailure verifies that a permanent error from
// Zitadel (e.g., 401 Unauthorized) propagates as-is and done=false so the
// saga runner sets a Blocked condition and stops retrying.
func TestEnsureZitadelOrg_PermanentFailure(t *testing.T) {
	fz := newFakeZitadel()
	fz.CreateOrganizationErr = clients.WrapPermanent(
		fmt.Errorf("zitadel 401: %w: bad PAT", clients.ErrUnauthorized),
	)

	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()

	step := newEnsureZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if done {
		t.Fatal("expected done=false on permanent failure")
	}
	if err == nil {
		t.Fatal("expected non-nil error on permanent failure")
	}
	if !saga.IsPermanent(err) {
		t.Errorf("expected saga.IsPermanent(err)=true; got false: %v", err)
	}
	if !errors.Is(err, saga.ErrPermanent) {
		t.Errorf("expected errors.Is(err, saga.ErrPermanent)=true; got false")
	}
	// Status must not be polluted on failure.
	if tenant.Status.ZitadelOrgID != "" {
		t.Errorf("ZitadelOrgID should remain empty on failure, got %q", tenant.Status.ZitadelOrgID)
	}
}

// TestEnsureZitadelOrg_TransientFailure verifies that a transient error from
// Zitadel (e.g., network timeout) returns done=false without wrapping as
// permanent — the saga runner should retry with backoff.
func TestEnsureZitadelOrg_TransientFailure(t *testing.T) {
	fz := newFakeZitadel()
	fz.CreateOrganizationErr = fmt.Errorf("zitadel: %w: connection refused", clients.ErrUnreachable)

	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()

	step := newEnsureZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if done {
		t.Fatal("expected done=false on transient failure")
	}
	if err == nil {
		t.Fatal("expected non-nil error on transient failure")
	}
	if saga.IsPermanent(err) {
		t.Errorf("expected transient error (not permanent), got permanent: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RemoveZitadelOrg tests
// ---------------------------------------------------------------------------

// TestRemoveZitadelOrg_EmptyStatus verifies that when ZitadelOrgID is empty
// the step returns done=true immediately without calling Zitadel.
func TestRemoveZitadelOrg_EmptyStatus(t *testing.T) {
	fz := newFakeZitadel()
	deps := ProvisionDeps{Zitadel: fz}
	tenant := newTenant()
	// Status.ZitadelOrgID is empty.

	step := newRemoveZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when org was never provisioned")
	}
	if fz.DeleteCalled != 0 {
		t.Errorf("DeleteOrganization should not be called when status is empty, got %d calls", fz.DeleteCalled)
	}
}

// TestRemoveZitadelOrg_BlockedByMembers verifies that when TenantMember CRDs
// remain in the tenant namespace the step returns done=false with reason
// WaitingForMembersRemoved and does not call Zitadel.
func TestRemoveZitadelOrg_BlockedByMembers(t *testing.T) {
	fz := newFakeZitadel()
	fz.orgs["org_1"] = &zitadel.Organization{ID: "org_1", Name: "Acme Corp", Slug: "acme"}

	// Create a TenantMember in the tenant's namespace.
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alice",
			Namespace: "tenant-acme",
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email: "alice@example.com",
			Role:  gibsonv1alpha1.MemberRoleMember,
		},
	}
	k8s := newFakeK8sClient(member)

	deps := ProvisionDeps{
		Zitadel:   fz,
		K8sClient: k8s,
	}
	tenant := newTenant()
	tenant.Status.ZitadelOrgID = "org_1"
	tenant.Status.Namespace = "tenant-acme"

	step := newRemoveZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error (requeue signal), got: %v", err)
	}
	if done {
		t.Fatal("expected done=false while TenantMember CRDs remain")
	}
	if fz.DeleteCalled != 0 {
		t.Errorf("DeleteOrganization must not be called while members remain, got %d calls", fz.DeleteCalled)
	}
	// Verify the WaitingForMembersRemoved condition is set.
	cond := findConditionByType(tenant, "ZitadelOrgDeleted")
	if cond == nil {
		t.Fatal("expected ZitadelOrgDeleted condition to be set")
	}
	if cond.Reason != "WaitingForMembersRemoved" {
		t.Errorf("condition reason: want WaitingForMembersRemoved, got %q", cond.Reason)
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("condition status: want False, got %v", cond.Status)
	}
}

// TestRemoveZitadelOrg_HappyPath verifies that when no TenantMember CRDs
// remain the step calls DeleteOrganization, clears the status, and sets
// ZitadelOrgReady=False with Reason=Deleted.
func TestRemoveZitadelOrg_HappyPath(t *testing.T) {
	fz := newFakeZitadel()
	fz.orgs["org_1"] = &zitadel.Organization{ID: "org_1", Name: "Acme Corp", Slug: "acme"}

	k8s := newFakeK8sClient() // no members

	deps := ProvisionDeps{
		Zitadel:   fz,
		K8sClient: k8s,
	}
	tenant := newTenant()
	tenant.Status.ZitadelOrgID = "org_1"
	tenant.Status.ZitadelOrgSlug = "acme"
	tenant.Status.Namespace = "tenant-acme"

	step := newRemoveZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true on successful deletion")
	}
	if fz.DeleteCalled != 1 {
		t.Errorf("DeleteOrganization call count: want 1, got %d", fz.DeleteCalled)
	}
	if tenant.Status.ZitadelOrgID != "" {
		t.Errorf("ZitadelOrgID should be cleared after deletion, got %q", tenant.Status.ZitadelOrgID)
	}
	if tenant.Status.ZitadelOrgSlug != "" {
		t.Errorf("ZitadelOrgSlug should be cleared after deletion, got %q", tenant.Status.ZitadelOrgSlug)
	}
	// ZitadelOrgReady must be set False with Reason=Deleted.
	cond := findConditionByType(tenant, gibsonv1alpha1.ConditionZitadelOrgReady)
	if cond == nil {
		t.Fatal("expected ZitadelOrgReady condition to be set after teardown")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("ZitadelOrgReady status: want False, got %v", cond.Status)
	}
	if cond.Reason != "Deleted" {
		t.Errorf("ZitadelOrgReady reason: want Deleted, got %q", cond.Reason)
	}
}

// TestRemoveZitadelOrg_NotFound_Idempotent verifies that a 404 from Zitadel on
// DeleteOrganization is treated as success — the org was already gone.
func TestRemoveZitadelOrg_NotFound_Idempotent(t *testing.T) {
	fz := newFakeZitadel()
	// Do NOT seed the org — DeleteOrganization will return ErrNotFound.

	k8s := newFakeK8sClient()

	deps := ProvisionDeps{
		Zitadel:   fz,
		K8sClient: k8s,
	}
	tenant := newTenant()
	tenant.Status.ZitadelOrgID = "org_gone"
	tenant.Status.Namespace = "tenant-acme"

	step := newRemoveZitadelOrgStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error on 404 (idempotent delete), got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when org was already gone (404)")
	}
	if tenant.Status.ZitadelOrgID != "" {
		t.Errorf("ZitadelOrgID should be cleared even on 404 path, got %q", tenant.Status.ZitadelOrgID)
	}
}

// TestRemoveZitadelOrg_Idempotent verifies that calling the step twice (e.g.,
// controller crash between status write and condition update) succeeds on the
// second call: ZitadelOrgID empty → returns done=true immediately.
func TestRemoveZitadelOrg_Idempotent(t *testing.T) {
	fz := newFakeZitadel()
	k8s := newFakeK8sClient()
	fz.orgs["org_1"] = &zitadel.Organization{ID: "org_1"}

	deps := ProvisionDeps{Zitadel: fz, K8sClient: k8s}
	tenant := newTenant()
	tenant.Status.ZitadelOrgID = "org_1"
	tenant.Status.Namespace = "tenant-acme"

	step := newRemoveZitadelOrgStep(deps)

	// First call: deletes org.
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("first call: expected (true, nil), got (%v, %v)", done, err)
	}

	// Second call: ZitadelOrgID is now empty → should return immediately.
	done, err = step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("second call (idempotent): expected (true, nil), got (%v, %v)", done, err)
	}
	// DeleteOrganization should only have been called once.
	if fz.DeleteCalled != 1 {
		t.Errorf("DeleteOrganization call count: want 1, got %d (called twice would indicate non-idempotent behavior)", fz.DeleteCalled)
	}
}

// findConditionByType returns the Tenant status condition of the given type, or
// nil if absent.
func findConditionByType(t *gibsonv1alpha1.Tenant, condType string) *metav1.Condition {
	for i := range t.Status.Conditions {
		if t.Status.Conditions[i].Type == condType {
			return &t.Status.Conditions[i]
		}
	}
	return nil
}
