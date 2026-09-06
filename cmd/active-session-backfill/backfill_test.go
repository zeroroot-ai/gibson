// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for runBackfill — the core enumeration+write loop that is extracted
// from main/run so it can be exercised without live Kubernetes or FGA.
//
// Test fakes:
//   - fakeTenantLister: returns a static list of Tenant objects.
//   - fakeMemberListerFactory: maps namespace → static TenantMember list.
//   - fakeConditionalWriter: captures WriteConditional calls, optionally errors.
package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// ---- fakes ------------------------------------------------------------------

type fakeTenantLister struct {
	items []unstructured.Unstructured
	err   error
}

func (f *fakeTenantLister) List(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &unstructured.UnstructuredList{Items: f.items}, nil
}

type fakeMemberLister struct {
	items []unstructured.Unstructured
	err   error
}

func (f *fakeMemberLister) List(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &unstructured.UnstructuredList{Items: f.items}, nil
}

type fakeConditionalWriter struct {
	calls []authz.ConditionalTuple
	errFn func(t authz.ConditionalTuple) error // nil = always succeed
}

func (f *fakeConditionalWriter) WriteConditional(_ context.Context, t authz.ConditionalTuple) error {
	f.calls = append(f.calls, t)
	if f.errFn != nil {
		return f.errFn(t)
	}
	return nil
}

func (f *fakeConditionalWriter) UpdateConditionalTuple(_ context.Context, t authz.ConditionalTuple) error {
	f.calls = append(f.calls, t)
	if f.errFn != nil {
		return f.errFn(t)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// makeTenant builds an unstructured Tenant CR with the given name and
// status.namespace.
func makeTenant(name, ns string) unstructured.Unstructured {
	obj := unstructured.Unstructured{}
	obj.SetName(name)
	if ns != "" {
		_ = unstructured.SetNestedField(obj.Object, ns, "status", "namespace")
	}
	return obj
}

// makeMember builds an unstructured TenantMember CR with the given fields.
func makeMember(name, phase, userID string, createdAt time.Time) unstructured.Unstructured {
	obj := unstructured.Unstructured{}
	obj.SetName(name)
	obj.SetCreationTimestamp(metav1.NewTime(createdAt))
	if phase != "" {
		_ = unstructured.SetNestedField(obj.Object, phase, "status", "phase")
	}
	if userID != "" {
		_ = unstructured.SetNestedField(obj.Object, userID, "status", "userId")
	}
	return obj
}

// ---- runBackfill tests ------------------------------------------------------

func TestRunBackfill_EmptyTenantList(t *testing.T) {
	tenants := &fakeTenantLister{}
	factory := func(_ string) MemberLister { return &fakeMemberLister{} }
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Backfilled != 0 || stats.AlreadySeeded != 0 || stats.Failed != 0 {
		t.Errorf("expected zero stats for empty tenant list, got %+v", stats)
	}
	if len(writer.calls) != 0 {
		t.Errorf("expected no FGA writes for empty tenant list, got %d", len(writer.calls))
	}
}

func TestRunBackfill_TenantListError_ReturnsFatalError(t *testing.T) {
	tenants := &fakeTenantLister{err: errors.New("k8s unavailable")}
	factory := func(_ string) MemberLister { return &fakeMemberLister{} }
	writer := &fakeConditionalWriter{}

	_, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err == nil {
		t.Fatal("expected fatal error when Tenant list fails, got nil")
	}
}

func TestRunBackfill_TenantWithNoNamespace_Skipped(t *testing.T) {
	// A Tenant CR whose status.namespace is empty should be skipped.
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{
			makeTenant("acme", ""), // no namespace
		},
	}
	factory := func(_ string) MemberLister { return &fakeMemberLister{} }
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Backfilled != 0 || stats.Failed != 0 {
		t.Errorf("expected zero backfill for namespace-less tenant, got %+v", stats)
	}
}

func TestRunBackfill_MemberListError_TenantSkipped(t *testing.T) {
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{
			makeTenant("acme", "acme-ns"),
		},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{err: errors.New("apiserver timeout")}
	}
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("expected nil fatal error (member list error is non-fatal), got %v", err)
	}
	if stats.Backfilled != 0 || stats.Failed != 0 {
		t.Errorf("expected zero stats when member list fails per-tenant, got %+v", stats)
	}
}

func TestRunBackfill_ActiveMember_WritesEpochTuple(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{
			makeTenant("acme", "acme-ns"),
		},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("alice-member", "Active", "user-alice", now),
			},
		}
	}
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Backfilled != 1 {
		t.Errorf("Backfilled = %d, want 1", stats.Backfilled)
	}
	// gibson#1244: each member now gets TWO tuples — the per-tenant tuple and
	// the user-scoped tuple (user:<id>, active_session, user:<id>).
	if len(writer.calls) != 2 {
		t.Fatalf("expected 2 FGA writes (per-tenant + user-scoped), got %d", len(writer.calls))
	}
	byObject := map[string]authz.ConditionalTuple{}
	for _, c := range writer.calls {
		byObject[c.Object] = c
	}

	call, ok := byObject["tenant:acme"]
	if !ok {
		t.Fatalf("missing per-tenant write on tenant:acme; objects=%v", writer.calls)
	}
	if call.User != "user:user-alice" {
		t.Errorf("User = %q, want %q", call.User, "user:user-alice")
	}
	if call.Relation != "active_session" {
		t.Errorf("Relation = %q, want active_session", call.Relation)
	}
	if call.ConditionName != authz.ConditionTokenNotRevoked {
		t.Errorf("ConditionName = %q, want %q", call.ConditionName, authz.ConditionTokenNotRevoked)
	}
	if call.ConditionContext[authz.ConditionParamRevokedAt] != authz.EpochRevokedAt {
		t.Errorf("ConditionContext[revoked_at] = %v, want %v",
			call.ConditionContext[authz.ConditionParamRevokedAt], authz.EpochRevokedAt)
	}

	userCall, ok := byObject["user:user-alice"]
	if !ok {
		t.Fatalf("missing user-scoped write on user:user-alice; objects=%v", writer.calls)
	}
	if userCall.User != "user:user-alice" {
		t.Errorf("user-scoped User = %q, want %q", userCall.User, "user:user-alice")
	}
	if userCall.Relation != "active_session" {
		t.Errorf("user-scoped Relation = %q, want active_session", userCall.Relation)
	}
	if userCall.ConditionContext[authz.ConditionParamRevokedAt] != authz.EpochRevokedAt {
		t.Errorf("user-scoped ConditionContext[revoked_at] = %v, want %v",
			userCall.ConditionContext[authz.ConditionParamRevokedAt], authz.EpochRevokedAt)
	}
}

func TestRunBackfill_InactiveMember_Skipped(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("pending-member", "Pending", "user-bob", now),
			},
		}
	}
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Backfilled != 0 {
		t.Errorf("expected 0 backfills for inactive member, got %d", stats.Backfilled)
	}
	if len(writer.calls) != 0 {
		t.Errorf("expected no FGA writes for inactive member, got %d", len(writer.calls))
	}
}

func TestRunBackfill_MemberWithoutUserID_Skipped(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("no-user-member", "Active", "", now), // no userId
			},
		}
	}
	writer := &fakeConditionalWriter{}

	stats, _ := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if stats.Backfilled != 0 {
		t.Errorf("expected 0 backfills for member without userId, got %d", stats.Backfilled)
	}
}

func TestRunBackfill_WriteError_CountedAsFailed(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("alice-member", "Active", "user-alice", now),
			},
		}
	}
	writer := &fakeConditionalWriter{
		errFn: func(_ authz.ConditionalTuple) error {
			return errors.New("FGA unreachable")
		},
	}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("expected nil fatal error (write failure is non-fatal), got %v", err)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
	if stats.Backfilled != 0 {
		t.Errorf("Backfilled = %d, want 0 when write fails", stats.Backfilled)
	}
}

func TestRunBackfill_MultipleTenants_AllProcessed(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{
			makeTenant("acme", "acme-ns"),
			makeTenant("beta", "beta-ns"),
		},
	}
	membersByNS := map[string][]unstructured.Unstructured{
		"acme-ns": {makeMember("alice", "Active", "user-alice", now)},
		"beta-ns": {makeMember("bob", "Active", "user-bob", now)},
	}
	factory := func(ns string) MemberLister {
		return &fakeMemberLister{items: membersByNS[ns]}
	}
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Backfilled != 2 {
		t.Errorf("Backfilled = %d, want 2", stats.Backfilled)
	}
	// gibson#1244: each member gets a per-tenant AND a user-scoped tuple, so two
	// members produce four writes.
	if len(writer.calls) != 4 {
		t.Errorf("expected 4 FGA writes (2 members × [per-tenant + user-scoped]), got %d: %+v", len(writer.calls), writer.calls)
	}
	// Verify both tenants were stamped with their respective slugs, and each
	// member got its user-scoped object.
	objects := map[string]bool{}
	for _, c := range writer.calls {
		objects[c.Object] = true
	}
	for _, want := range []string{"tenant:acme", "tenant:beta", "user:user-alice", "user:user-bob"} {
		if !objects[want] {
			t.Errorf("missing active_session write for %s", want)
		}
	}
}

func TestRunBackfill_MembersProcessedInCreationTimestampOrder(t *testing.T) {
	// Verify members are sorted by creationTimestamp so backfill is deterministic.
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				// Intentionally out of order.
				makeMember("charlie", "Active", "user-charlie", t3),
				makeMember("alice", "Active", "user-alice", t1),
				makeMember("bob", "Active", "user-bob", t2),
			},
		}
	}
	writer := &fakeConditionalWriter{}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Backfilled != 3 {
		t.Errorf("Backfilled = %d, want 3", stats.Backfilled)
	}
	// Verify sorted order by checking user IDs in call sequence. gibson#1244:
	// each member emits two consecutive writes (per-tenant then user-scoped),
	// both carrying the same User, so each member appears twice in order.
	want := []string{
		"user:user-alice", "user:user-alice",
		"user:user-bob", "user:user-bob",
		"user:user-charlie", "user:user-charlie",
	}
	if len(writer.calls) != len(want) {
		t.Fatalf("expected %d writes, got %d", len(want), len(writer.calls))
	}
	for i, call := range writer.calls {
		if call.User != want[i] {
			t.Errorf("call[%d].User = %q, want %q", i, call.User, want[i])
		}
	}
}

// ---- backfillMember tests --------------------------------------------------

func TestBackfillMember_Success(t *testing.T) {
	writer := &fakeConditionalWriter{}
	outcome, err := backfillMember(context.Background(), writer, "acme", "user-alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != outcomeBackfilled {
		t.Errorf("outcome = %q, want %q", outcome, outcomeBackfilled)
	}
}

func TestBackfillMember_WriteFailure_ReturnsWriteFailedOutcome(t *testing.T) {
	writer := &fakeConditionalWriter{
		errFn: func(_ authz.ConditionalTuple) error {
			return errors.New("connection refused")
		},
	}
	outcome, err := backfillMember(context.Background(), writer, "acme", "user-alice")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if outcome != outcomeWriteFailed {
		t.Errorf("outcome = %q, want %q", outcome, outcomeWriteFailed)
	}
}

func TestBackfillMember_TupleContentsMatchAuthzConstants(t *testing.T) {
	writer := &fakeConditionalWriter{}
	_, err := backfillMember(context.Background(), writer, "tenant-slug", "user-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// gibson#1244: backfillMember writes the per-tenant tuple then the
	// user-scoped tuple.
	if len(writer.calls) != 2 {
		t.Fatalf("expected 2 calls (per-tenant + user-scoped), got %d", len(writer.calls))
	}
	tuple := writer.calls[0]

	// authz.ActiveSessionTuple should produce these exact values.
	expected := authz.ActiveSessionTuple("user-xyz", "tenant-slug")
	if tuple.User != expected.User {
		t.Errorf("User = %q, want %q", tuple.User, expected.User)
	}
	if tuple.Relation != expected.Relation {
		t.Errorf("Relation = %q, want %q", tuple.Relation, expected.Relation)
	}
	if tuple.Object != expected.Object {
		t.Errorf("Object = %q, want %q", tuple.Object, expected.Object)
	}
	if tuple.ConditionName != expected.ConditionName {
		t.Errorf("ConditionName = %q, want %q", tuple.ConditionName, expected.ConditionName)
	}

	// The second write must equal authz.ActiveSessionUserTuple exactly.
	userTuple := writer.calls[1]
	expectedUser := authz.ActiveSessionUserTuple("user-xyz")
	if userTuple.User != expectedUser.User {
		t.Errorf("user-scoped User = %q, want %q", userTuple.User, expectedUser.User)
	}
	if userTuple.Object != expectedUser.Object {
		t.Errorf("user-scoped Object = %q, want %q", userTuple.Object, expectedUser.Object)
	}
	if userTuple.Relation != expectedUser.Relation {
		t.Errorf("user-scoped Relation = %q, want %q", userTuple.Relation, expectedUser.Relation)
	}
	if userTuple.ConditionContext[authz.ConditionParamRevokedAt] != authz.EpochRevokedAt {
		t.Errorf("user-scoped revoked_at = %v, want %v",
			userTuple.ConditionContext[authz.ConditionParamRevokedAt], authz.EpochRevokedAt)
	}
}

// ---- nestedString tests ----------------------------------------------------

func TestNestedString_Found(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{
			"namespace": "acme-ns",
		},
	}
	v, found, err := nestedString(obj, "status", "namespace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Error("expected found=true")
	}
	if v != "acme-ns" {
		t.Errorf("value = %q, want acme-ns", v)
	}
}

func TestNestedString_MissingIntermediateKey(t *testing.T) {
	obj := map[string]any{}
	v, found, err := nestedString(obj, "status", "namespace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false for missing key")
	}
	if v != "" {
		t.Errorf("value = %q, want empty string", v)
	}
}

func TestNestedString_NonStringLeaf(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{
			"count": 42, // not a string
		},
	}
	v, found, err := nestedString(obj, "status", "count")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false for non-string leaf")
	}
	if v != "" {
		t.Errorf("value = %q, want empty string", v)
	}
}

func TestNestedString_IntermediateNotMap(t *testing.T) {
	obj := map[string]any{
		"status": "scalar-not-map",
	}
	v, found, err := nestedString(obj, "status", "namespace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false when intermediate field is not a map")
	}
	if v != "" {
		t.Errorf("value = %q, want empty string", v)
	}
}

// ---- backfillOutcome constant coverage -------------------------------------

func TestBackfillOutcomeConstants(t *testing.T) {
	// Exercise all four outcome constants (for coverage and to confirm no
	// string-formatting regressions).
	cases := []struct {
		outcome backfillOutcome
		want    string
	}{
		{outcomeBackfilled, "backfilled"},
		{outcomeAlreadySeeded, "already_seeded"},
		{outcomeWriteFailed, "write_failed"},
		{outcomeCheckFailed, "check_failed"},
	}
	for _, tc := range cases {
		if string(tc.outcome) != tc.want {
			t.Errorf("outcome %q = %q, want %q", tc.outcome, string(tc.outcome), tc.want)
		}
	}
}

// ---- requireEnv tests -------------------------------------------------------

func TestRequireEnv_Present(t *testing.T) {
	t.Setenv("TEST_REQ_ENV", "hello")
	logger := discardLogger()
	v := requireEnv(logger, "TEST_REQ_ENV")
	if v != "hello" {
		t.Errorf("requireEnv = %q, want hello", v)
	}
}

func TestRequireEnv_Absent(t *testing.T) {
	t.Setenv("TEST_ABSENT_ENV", "")
	logger := discardLogger()
	v := requireEnv(logger, "TEST_ABSENT_ENV")
	if v != "" {
		t.Errorf("requireEnv for absent var = %q, want empty string", v)
	}
}

// ---- fakeConditionalWriter interface check ---------------------------------

// Ensure fakeConditionalWriter satisfies authz.ConditionalWriter.
var _ authz.ConditionalWriter = (*fakeConditionalWriter)(nil)

// ---- listerProvider fakes for runWithDeps ----------------------------------

// staticListerProvider returns a listerProvider that uses the given fake listers.
// This avoids needing to implement the full dynamic.Interface in tests.
func staticListerProvider(
	tenants *fakeTenantLister,
	membersByNS map[string][]unstructured.Unstructured,
) listerProvider {
	return func(_ *rest.Config) (TenantLister, MemberListerFactory, error) {
		factory := func(ns string) MemberLister {
			return &fakeMemberLister{items: membersByNS[ns]}
		}
		return tenants, factory, nil
	}
}

// errListerProvider returns a listerProvider that always fails.
func errListerProvider(err error) listerProvider {
	return func(_ *rest.Config) (TenantLister, MemberListerFactory, error) {
		return nil, nil, err
	}
}

// ---- fakeAuthorizer for runWithDeps ----------------------------------------

// fakeAuthorizer is used to supply a ConditionalWriter to runWithDeps tests.
// It satisfies authz.Authorizer (and also authz.ConditionalWriter).
type fakeAuthorizer struct {
	// fakeConditionalWriter is embedded to satisfy ConditionalWriter.
	*fakeConditionalWriter
}

func (f *fakeAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
func (f *fakeAuthorizer) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (f *fakeAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (f *fakeAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (f *fakeAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) StoreID() string { return "test-store" }
func (f *fakeAuthorizer) ModelID() string { return "test-model" }
func (f *fakeAuthorizer) Close() error    { return nil }

// Compile-time check.
var _ authz.Authorizer = (*fakeAuthorizer)(nil)

// ---- integration-style smoke: multiple members, one write failure ----------

func TestRunBackfill_PartialWriteFailure(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("alice", "Active", "user-alice", now.Add(-2*time.Second)),
				makeMember("bob", "Active", "user-bob", now.Add(-1*time.Second)),
				makeMember("charlie", "Active", "user-charlie", now),
			},
		}
	}
	// bob's write always fails; alice and charlie succeed.
	writer := &fakeConditionalWriter{
		errFn: func(t authz.ConditionalTuple) error {
			if t.User == "user:user-bob" {
				return errors.New("FGA write error for bob")
			}
			return nil
		},
	}

	stats, err := runBackfill(context.Background(), tenants, factory, writer, discardLogger())
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if stats.Backfilled != 2 {
		t.Errorf("Backfilled = %d, want 2", stats.Backfilled)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
}

// ---- resolveFgaEnvConfig tests ---------------------------------------------

func TestResolveFgaEnvConfig_AllPresent(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-123")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-456")

	cfg, err := resolveFgaEnvConfig(discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != "http://fga:8080" {
		t.Errorf("Addr = %q, want http://fga:8080", cfg.Addr)
	}
	if cfg.StoreID != "store-123" {
		t.Errorf("StoreID = %q, want store-123", cfg.StoreID)
	}
	if cfg.ModelID != "model-456" {
		t.Errorf("ModelID = %q, want model-456", cfg.ModelID)
	}
}

func TestResolveFgaEnvConfig_AllMissing(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "")

	_, err := resolveFgaEnvConfig(discardLogger())
	if err == nil {
		t.Fatal("expected error when all env vars missing, got nil")
	}
}

func TestResolveFgaEnvConfig_PartialMissing(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-456")

	_, err := resolveFgaEnvConfig(discardLogger())
	if err == nil {
		t.Fatal("expected error when one env var missing, got nil")
	}
}

// ---- runWithWriter tests ---------------------------------------------------

func TestRunWithWriter_SuccessReturnsZero(t *testing.T) {
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("alice", "Active", "user-alice", now),
			},
		}
	}
	writer := &fakeConditionalWriter{}

	code := runWithWriter(context.Background(), tenants, factory, writer, discardLogger())
	if code != 0 {
		t.Errorf("runWithWriter exit code = %d, want 0", code)
	}
	// gibson#1244: one member → per-tenant tuple + user-scoped tuple.
	if len(writer.calls) != 2 {
		t.Errorf("expected 2 FGA writes (per-tenant + user-scoped), got %d", len(writer.calls))
	}
}

func TestRunWithWriter_FatalTenantListError_ReturnsNonZero(t *testing.T) {
	tenants := &fakeTenantLister{err: errors.New("apiserver down")}
	factory := func(_ string) MemberLister { return &fakeMemberLister{} }
	writer := &fakeConditionalWriter{}

	code := runWithWriter(context.Background(), tenants, factory, writer, discardLogger())
	if code == 0 {
		t.Error("expected non-zero exit code when tenant list fails, got 0")
	}
}

func TestRunWithWriter_NonFatalWriteError_ReturnsZero(t *testing.T) {
	// Per-member write failures are non-fatal; runWithWriter still returns 0.
	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	factory := func(_ string) MemberLister {
		return &fakeMemberLister{
			items: []unstructured.Unstructured{
				makeMember("alice", "Active", "user-alice", now),
			},
		}
	}
	writer := &fakeConditionalWriter{
		errFn: func(_ authz.ConditionalTuple) error {
			return errors.New("FGA unavailable")
		},
	}

	code := runWithWriter(context.Background(), tenants, factory, writer, discardLogger())
	if code != 0 {
		t.Errorf("runWithWriter exit code = %d (want 0 — per-member failures are non-fatal)", code)
	}
}

func TestRunWithWriter_EmptyTenants_ReturnsZero(t *testing.T) {
	tenants := &fakeTenantLister{}
	factory := func(_ string) MemberLister { return &fakeMemberLister{} }
	writer := &fakeConditionalWriter{}

	code := runWithWriter(context.Background(), tenants, factory, writer, discardLogger())
	if code != 0 {
		t.Errorf("runWithWriter exit code = %d, want 0 for empty tenant list", code)
	}
}

// ---- runWithDeps tests -----------------------------------------------------

// happyKubeLoader returns a no-op *rest.Config (the pointer is just passed
// through to the listerProvider in tests; no real k8s connection is made).
func happyKubeLoader() (*rest.Config, error) {
	return &rest.Config{Host: "http://fake-k8s:6443"}, nil
}

// noOpAuthzBuilder returns a fakeAuthorizer (which implements ConditionalWriter)
// via the authzBuilder signature.
func noOpAuthzBuilder(tenants *fakeTenantLister, members map[string][]unstructured.Unstructured) (
	listerProvider, fgaAuthorizerBuilder,
) {
	lp := staticListerProvider(tenants, members)
	ab := func(_ context.Context, _ authz.FgaConfig) (authz.Authorizer, error) {
		return &fakeAuthorizer{fakeConditionalWriter: &fakeConditionalWriter{}}, nil
	}
	return lp, ab
}

func TestRunWithDeps_MissingEnv_ReturnsOne(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "")

	code := runWithDeps(
		discardLogger(),
		happyKubeLoader,
		errListerProvider(errors.New("should not be called")),
		func(_ context.Context, _ authz.FgaConfig) (authz.Authorizer, error) {
			return nil, errors.New("should not be called")
		},
	)
	if code != 1 {
		t.Errorf("expected exit code 1 for missing env, got %d", code)
	}
}

func TestRunWithDeps_KubeLoaderError_ReturnsOne(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-1")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-1")

	code := runWithDeps(
		discardLogger(),
		func() (*rest.Config, error) { return nil, errors.New("no kubeconfig") },
		errListerProvider(errors.New("should not be called")),
		func(_ context.Context, _ authz.FgaConfig) (authz.Authorizer, error) {
			return nil, errors.New("should not be called")
		},
	)
	if code != 1 {
		t.Errorf("expected exit code 1 for kubeloader error, got %d", code)
	}
}

func TestRunWithDeps_ListerProviderError_ReturnsOne(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-1")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-1")

	code := runWithDeps(
		discardLogger(),
		happyKubeLoader,
		errListerProvider(errors.New("dynamic client failed")),
		func(_ context.Context, _ authz.FgaConfig) (authz.Authorizer, error) {
			return nil, errors.New("should not be called")
		},
	)
	if code != 1 {
		t.Errorf("expected exit code 1 for lister provider error, got %d", code)
	}
}

func TestRunWithDeps_AuthzBuilderError_ReturnsOne(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-1")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-1")

	tenants := &fakeTenantLister{}
	lp := staticListerProvider(tenants, nil)

	code := runWithDeps(
		discardLogger(),
		happyKubeLoader,
		lp,
		func(_ context.Context, _ authz.FgaConfig) (authz.Authorizer, error) {
			return nil, errors.New("FGA dial failed")
		},
	)
	if code != 1 {
		t.Errorf("expected exit code 1 for authz builder error, got %d", code)
	}
}

func TestRunWithDeps_NonConditionalWriter_ReturnsOne(t *testing.T) {
	// authzBuilder returns an Authorizer that does NOT implement ConditionalWriter.
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-1")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-1")

	tenants := &fakeTenantLister{}
	lp := staticListerProvider(tenants, nil)

	code := runWithDeps(
		discardLogger(),
		happyKubeLoader,
		lp,
		func(_ context.Context, _ authz.FgaConfig) (authz.Authorizer, error) {
			// Return an Authorizer that is NOT a ConditionalWriter.
			return &noConditionalWriterAuthorizer{}, nil
		},
	)
	if code != 1 {
		t.Errorf("expected exit code 1 when authorizer lacks ConditionalWriter, got %d", code)
	}
}

// noConditionalWriterAuthorizer satisfies authz.Authorizer but NOT authz.ConditionalWriter.
type noConditionalWriterAuthorizer struct{}

func (n *noConditionalWriterAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
func (n *noConditionalWriterAuthorizer) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (n *noConditionalWriterAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (n *noConditionalWriterAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (n *noConditionalWriterAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (n *noConditionalWriterAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (n *noConditionalWriterAuthorizer) StoreID() string { return "" }
func (n *noConditionalWriterAuthorizer) ModelID() string { return "" }
func (n *noConditionalWriterAuthorizer) Close() error    { return nil }

func TestRunWithDeps_HappyPath_ReturnsZero(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-1")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-1")

	now := time.Now()
	tenants := &fakeTenantLister{
		items: []unstructured.Unstructured{makeTenant("acme", "acme-ns")},
	}
	membersByNS := map[string][]unstructured.Unstructured{
		"acme-ns": {makeMember("alice", "Active", "user-alice", now)},
	}
	lp, ab := noOpAuthzBuilder(tenants, membersByNS)

	code := runWithDeps(discardLogger(), happyKubeLoader, lp, ab)
	if code != 0 {
		t.Errorf("expected exit code 0 for happy path, got %d", code)
	}
}

// ListUsersOfType is unused by this package's tests. It exists because the
// method is on authz.Authorizer — a gate reached by type assertion was
// silently skipped by every double that did not implement it.
func (f *fakeAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}

// ListUsersOfType is unused by this package's tests. It exists because the
// method is on authz.Authorizer — a gate reached by type assertion was
// silently skipped by every double that did not implement it.
func (n *noConditionalWriterAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}
