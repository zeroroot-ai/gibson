// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// migrationStore is teamStore plus authz.TupleReader — a store that can be
// asked what it actually holds, as opposed to what it would decide.
//
// The distinction is the whole reason ReadTuples exists. ListUsers on this
// double, like the real one, answers the EFFECTIVE question and so reports a
// tenant admin as a team admin through `admin: [user] or admin from parent`;
// a migration built on it would write that derivation back as a direct tuple
// and make the grant permanent. deriveAdmins below reproduces that derivation
// so the test can prove the migration does not fall into it.
type migrationStore struct {
	teamStore
	readErr error
}

func newMigrationStore() *migrationStore {
	return &migrationStore{teamStore: teamStore{tuples: map[string]authz.Tuple{}, barrierCh: make(chan struct{})}}
}

func (s *migrationStore) ReadTuples(_ context.Context, user, relation, object string) ([]authz.Tuple, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	if object == "" && (user == "" || relation == "") {
		return nil, errors.New("ReadTuples: with no object filter, both user and relation are required")
	}
	matchesObject := func(t authz.Tuple) bool {
		switch {
		case object == "":
			return true
		case strings.HasSuffix(object, ":"): // bare type filter, e.g. "team:"
			return strings.HasPrefix(t.Object, object)
		default:
			return t.Object == object
		}
	}
	snapshot := s.snapshot()
	out := make([]authz.Tuple, 0, len(snapshot))
	for _, t := range snapshot {
		if user != "" && t.User != user {
			continue
		}
		if relation != "" && t.Relation != relation {
			continue
		}
		if !matchesObject(t) {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// ListUsers reproduces the model's derivation on top of the stored tuples:
// `admin: [user] or admin from parent` means every admin of the parent tenant
// is an admin of the team. This is what a migration must NOT read.
func (s *migrationStore) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	direct := s.listUsers(objectType, object, relation, "user")
	if relation != "admin" {
		return direct, nil
	}
	seen := map[string]struct{}{}
	out := append([]string(nil), direct...)
	for _, u := range direct {
		seen[u] = struct{}{}
	}
	for _, parent := range s.parentsOf(object) {
		for _, admin := range s.listUsers("tenant", parent, "admin", "user") {
			if _, ok := seen[admin]; !ok {
				seen[admin] = struct{}{}
				out = append(out, admin)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

var _ authz.TupleReader = (*migrationStore)(nil)

// seedLegacyTeam writes the pre-namespace shape: a global team object with a
// tenant parent, direct members and direct admins.
func seedLegacyTeam(s *migrationStore, tenant, teamID string, members, admins []string) {
	obj := "team:" + teamID
	s.put(authz.Tuple{User: "tenant:" + tenant, Relation: "parent", Object: obj})
	for _, m := range members {
		s.put(authz.Tuple{User: "user:" + m, Relation: "member", Object: obj})
	}
	for _, a := range admins {
		s.put(authz.Tuple{User: "user:" + a, Relation: "admin", Object: obj})
	}
}

func seedSystemTenants(s *migrationStore, tenants ...string) {
	for _, tn := range tenants {
		s.put(authz.Tuple{User: "tenant:" + tn, Relation: "parent", Object: "system_tenant:_system"})
	}
}

func has(t *testing.T, s *migrationStore, user, relation, object string) bool {
	t.Helper()
	ok, err := s.Check(context.Background(), user, relation, object)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return ok
}

// TestMigrateTeamObjectIDs_MovesTheWholeTeam is the happy path: a legacy team
// with a roster lands intact in its tenant's namespace, and nothing is left
// behind on the global object.
func TestMigrateTeamObjectIDs_MovesTheWholeTeam(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", []string{"alice", "bob"}, []string{"carol"})

	report, err := MigrateTeamObjectIDs(context.Background(), store, nil, false)
	if err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}
	if len(report.TeamsMigrated) != 1 || report.TeamsMigrated[0] != "acme/ops" {
		t.Errorf("TeamsMigrated = %v, want [acme/ops]", report.TeamsMigrated)
	}

	const newObj = "team:acme/ops"
	for _, want := range []authz.Tuple{
		{User: "tenant:acme", Relation: "parent", Object: newObj},
		{User: "user:alice", Relation: "member", Object: newObj},
		{User: "user:bob", Relation: "member", Object: newObj},
		{User: "user:carol", Relation: "admin", Object: newObj},
	} {
		if !has(t, store, want.User, want.Relation, want.Object) {
			t.Errorf("missing migrated tuple %+v", want)
		}
	}
	for _, t2 := range store.snapshot() {
		if t2.Object == "team:ops" {
			t.Errorf("legacy tuple survived the migration: %+v", t2)
		}
	}
}

// TestMigrateTeamObjectIDs_DoesNotMaterialiseDerivedAdmins is the reason the
// migration reads stored tuples instead of effective ones.
//
// dave is an admin of tenant:acme and therefore an *effective* admin of every
// team acme parents, through `admin: [user] or admin from parent`. He holds no
// direct tuple on the team. A migration built on ListUsers would see him and
// write `user:dave admin team:acme/ops` — turning a revocable tenant role into
// a permanent team grant that survives dave losing tenant admin.
func TestMigrateTeamObjectIDs_DoesNotMaterialiseDerivedAdmins(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", []string{"alice"}, nil)
	store.put(authz.Tuple{User: "user:dave", Relation: "admin", Object: "tenant:acme"})

	// Precondition: the effective listing really does report dave, so this
	// test is not passing because the double forgot to derive.
	effective, err := store.ListUsers(context.Background(), "team", "team:ops", "admin")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if !contains(effective, "user:dave") {
		t.Fatalf("precondition failed: the effective admin listing %v does not include the derived admin", effective)
	}

	if _, err := MigrateTeamObjectIDs(context.Background(), store, nil, false); err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}
	if has(t, store, "user:dave", "admin", "team:acme/ops") {
		t.Error("the migration wrote a DIRECT admin tuple for a user who was only ever an admin by derivation")
	}
	if !has(t, store, "user:alice", "member", "team:acme/ops") {
		t.Error("the direct member did not survive")
	}
}

// TestMigrateTeamObjectIDs_LeavesASquattedIDUntouched covers the pre-existing
// squat the old read-then-write guard was forward-only about: two tenants
// already parent the same global object.
//
// There is no correct automatic answer. Copying the shared roster into both
// namespaces would hand the squatter the victim's roster — the leak being
// fixed. Moving it into one would guess which tenant is the victim. So the
// migration reports it and touches nothing; the object is already unreachable
// because no request path addresses the global namespace any more.
func TestMigrateTeamObjectIDs_LeavesASquattedIDUntouched(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "victim-co", "evil-co")
	seedLegacyTeam(store, "victim-co", "ops", []string{"alice"}, nil)
	// The squatter's second parent tuple on the SAME object.
	store.put(authz.Tuple{User: "tenant:evil-co", Relation: "parent", Object: "team:ops"})
	before := len(store.snapshot())

	report, err := MigrateTeamObjectIDs(context.Background(), store, nil, false)
	if err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}

	if len(report.SquattedIDs) != 1 || !strings.HasPrefix(report.SquattedIDs[0], "ops (claimed by evil-co, victim-co)") {
		t.Errorf("SquattedIDs = %v, want the contested id and both claimants named", report.SquattedIDs)
	}
	if len(report.TeamsMigrated) != 0 {
		t.Errorf("TeamsMigrated = %v, want nothing moved for a contested id", report.TeamsMigrated)
	}
	if got := len(store.snapshot()); got != before {
		t.Errorf("the store changed: %d tuples, was %d — a contested id must be left exactly as it was", got, before)
	}
	// The roster must not have been copied anywhere, least of all to the
	// squatter.
	if has(t, store, "user:alice", "member", "team:evil-co/ops") {
		t.Error("the victim's member was copied onto the squatter's namespace")
	}
	if has(t, store, "user:alice", "member", "team:victim-co/ops") {
		t.Error("a contested roster was moved on a guess about who owns it")
	}
}

// TestMigrateTeamObjectIDs_MovesComponentAccessUsersets covers the tuples where
// the team is the SUBJECT rather than the object. Reading the team object does
// not find them, so a migration that only walked the object side would leave
// every component-access rule pointing at an id nothing resolves.
func TestMigrateTeamObjectIDs_MovesComponentAccessUsersets(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", nil, nil)
	store.put(authz.Tuple{
		User: "team:ops#member", Relation: "team_execute_disabled", Object: "component:agent/zerocool",
	})

	if _, err := MigrateTeamObjectIDs(context.Background(), store, nil, false); err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}
	if !has(t, store, "team:acme/ops#member", "team_execute_disabled", "component:agent/zerocool") {
		t.Error("the component-access userset was not moved into the tenant namespace")
	}
	if has(t, store, "team:ops#member", "team_execute_disabled", "component:agent/zerocool") {
		t.Error("the legacy component-access userset survived")
	}
}

// TestMigrateTeamObjectIDs_IsIdempotent asserts a second run is a no-op, so a
// partial failure can be finished by re-running rather than reasoned about.
func TestMigrateTeamObjectIDs_IsIdempotent(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", []string{"alice"}, nil)

	if _, err := MigrateTeamObjectIDs(context.Background(), store, nil, false); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := store.snapshot()

	report, err := MigrateTeamObjectIDs(context.Background(), store, nil, false)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(report.TeamsMigrated) != 0 {
		t.Errorf("second run migrated %v, want nothing", report.TeamsMigrated)
	}
	if report.TeamsAlreadyNamespaced != 1 {
		t.Errorf("TeamsAlreadyNamespaced = %d, want 1", report.TeamsAlreadyNamespaced)
	}
	if got := store.snapshot(); len(got) != len(before) {
		t.Errorf("second run changed the store: %d tuples, was %d", len(got), len(before))
	}
}

// TestMigrateTeamObjectIDs_DryRunWritesNothing pins that -dry-run is a report,
// not a rehearsal that half-applies.
func TestMigrateTeamObjectIDs_DryRunWritesNothing(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", []string{"alice"}, nil)
	before := len(store.snapshot())

	report, err := MigrateTeamObjectIDs(context.Background(), store, nil, true)
	if err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}
	if len(report.TeamsMigrated) != 1 {
		t.Errorf("dry run reported %v, want the one team it would move", report.TeamsMigrated)
	}
	if got := len(store.snapshot()); got != before {
		t.Errorf("dry run changed the store: %d tuples, was %d", got, before)
	}
	if !has(t, store, "tenant:acme", "parent", "team:ops") {
		t.Error("dry run deleted the legacy tuple")
	}
}

// TestMigrateTeamObjectIDs_RefusesAnAuthorizerThatCannotReadStoredTuples pins
// the fail-closed path. Falling back to the effective listings would be the
// over-granting bug in TestMigrateTeamObjectIDs_DoesNotMaterialiseDerivedAdmins,
// so "no TupleReader" has to be a refusal rather than a downgrade.
func TestMigrateTeamObjectIDs_RefusesAnAuthorizerThatCannotReadStoredTuples(t *testing.T) {
	plain := newTeamStore(1) // teamStore alone does not implement authz.TupleReader
	_, err := MigrateTeamObjectIDs(context.Background(), plain, nil, false)
	if err == nil {
		t.Fatal("expected a refusal when the authorizer cannot read stored tuples, got nil")
	}
	if !strings.Contains(err.Error(), "TupleReader") {
		t.Errorf("error = %v, want it to name the missing capability", err)
	}
}

// TestMigrateTeamObjectIDs_SkipsAnUnmovableLegacyID covers the one legacy shape
// that cannot be namespaced: an id containing the separator. It must be
// reported and left completely alone, not partially rewritten.
func TestMigrateTeamObjectIDs_SkipsAnUnmovableLegacyID(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "weird/id", []string{"alice"}, nil)

	report, err := MigrateTeamObjectIDs(context.Background(), store, nil, false)
	if err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}
	if len(report.Skipped) != 1 {
		t.Fatalf("Skipped = %v, want one entry", report.Skipped)
	}
	if !has(t, store, "tenant:acme", "parent", "team:weird/id") {
		t.Error("a skipped team's tuples must be left exactly as they were")
	}
	if !has(t, store, "user:alice", "member", "team:weird/id") {
		t.Error("a skipped team's roster must be left exactly as they were")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Fail-closed behaviour and the operator-facing report
// ---------------------------------------------------------------------------

// failingStore is a migrationStore whose writes and deletes can be made to
// fail, so the tests below can prove the migration stops rather than reporting
// a half-moved store as success.
type failingStore struct {
	migrationStore
	writeErr  error
	deleteErr error
}

func newFailingStore() *failingStore {
	return &failingStore{migrationStore: *newMigrationStore()}
}

func (s *failingStore) Write(ctx context.Context, tuples []authz.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return s.migrationStore.Write(ctx, tuples)
}

func (s *failingStore) Delete(ctx context.Context, tuples []authz.Tuple) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.migrationStore.Delete(ctx, tuples)
}

// TestMigrateTeamObjectIDs_RefusesANilAuthorizer is the other half of the
// fail-closed pair. A nil authorizer reaching the type assertion would panic
// inside a binary whose whole job is deleting tuples.
func TestMigrateTeamObjectIDs_RefusesANilAuthorizer(t *testing.T) {
	_, err := MigrateTeamObjectIDs(context.Background(), nil, nil, false)
	if err == nil {
		t.Fatal("MigrateTeamObjectIDs accepted a nil authorizer")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error = %v, want it to name the nil authorizer", err)
	}
}

// TestMigrateTeamObjectIDs_StopsOnAReadFailure pins that a failed read aborts
// the run. Treating it as "this tenant has no teams" would silently skip every
// team behind the error and report success.
func TestMigrateTeamObjectIDs_StopsOnAReadFailure(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", []string{"alice"}, nil)
	store.readErr = errors.New("fga unreachable")

	report, err := MigrateTeamObjectIDs(context.Background(), store, nil, false)
	if err == nil {
		t.Fatal("MigrateTeamObjectIDs reported success while reads were failing")
	}
	if len(report.TeamsMigrated) != 0 {
		t.Errorf("TeamsMigrated = %v, want none — nothing was read, so nothing moved", report.TeamsMigrated)
	}
	if !has(t, store, "user:alice", "member", "team:ops") {
		t.Error("the legacy roster was touched despite the read failure")
	}
}

// TestMigrateTeamObjectIDs_StopsOnAWriteFailure pins the ordering that makes a
// partial run recoverable: nothing is deleted unless the namespaced copy was
// written first.
func TestMigrateTeamObjectIDs_StopsOnAWriteFailure(t *testing.T) {
	store := newFailingStore()
	seedSystemTenants(&store.migrationStore, "acme")
	seedLegacyTeam(&store.migrationStore, "acme", "ops", []string{"alice"}, nil)
	store.writeErr = errors.New("fga write rejected")

	if _, err := MigrateTeamObjectIDs(context.Background(), store, nil, false); err == nil {
		t.Fatal("MigrateTeamObjectIDs reported success while writes were failing")
	}
	if !has(t, &store.migrationStore, "user:alice", "member", "team:ops") {
		t.Error("the legacy tuple was deleted even though its namespaced copy was never written")
	}
}

// TestMigrateTeamObjectIDs_ADeleteFailureLeavesTheCopyInPlace pins the
// re-runnable half: once the copy exists, a failed delete must say so rather
// than roll the copy back, because the next run finishes the job.
func TestMigrateTeamObjectIDs_ADeleteFailureLeavesTheCopyInPlace(t *testing.T) {
	store := newFailingStore()
	seedSystemTenants(&store.migrationStore, "acme")
	seedLegacyTeam(&store.migrationStore, "acme", "ops", []string{"alice"}, nil)
	store.deleteErr = errors.New("fga delete rejected")

	_, err := MigrateTeamObjectIDs(context.Background(), store, nil, false)
	if err == nil {
		t.Fatal("MigrateTeamObjectIDs reported success while deletes were failing")
	}
	if !strings.Contains(err.Error(), "re-run") {
		t.Errorf("error = %v, want it to tell the operator a re-run finishes the job", err)
	}
	if !has(t, &store.migrationStore, "user:alice", "member", "team:acme/ops") {
		t.Error("the namespaced copy was not written before the delete was attempted")
	}
}

// TestMigrateTeamObjectIDs_MovesOutboundTeamToTeamEdges covers the third read:
// `can_view_data_from` where the moved team is the SUBJECT and some other team
// is the object. Those tuples live on the other team's object, so the read of
// the moved team's own object cannot see them, and a migration that only did
// that read would delete the team out from under a live grant.
func TestMigrateTeamObjectIDs_MovesOutboundTeamToTeamEdges(t *testing.T) {
	store := newMigrationStore()
	seedSystemTenants(store, "acme")
	seedLegacyTeam(store, "acme", "ops", []string{"alice"}, nil)
	seedLegacyTeam(store, "acme", "research", nil, nil)
	// ops may view research's data: the tuple is stored ON research.
	store.put(authz.Tuple{User: "team:ops", Relation: "can_view_data_from", Object: "team:research"})

	if _, err := MigrateTeamObjectIDs(context.Background(), store, nil, false); err != nil {
		t.Fatalf("MigrateTeamObjectIDs: %v", err)
	}
	if !has(t, store, "team:acme/ops", "can_view_data_from", "team:acme/research") {
		t.Error("the outbound can_view_data_from edge did not survive the move")
	}
	if has(t, store, "team:ops", "can_view_data_from", "team:research") {
		t.Error("the legacy outbound edge was left behind")
	}
}

// TestMigrationReport_StringNamesEveryOutcome pins the operator hand-off. A
// contested id is deliberately NOT migrated, so this rendering is the only
// place a human learns it needs resolving; a report that printed counts alone
// would leave the squat invisible.
func TestMigrationReport_StringNamesEveryOutcome(t *testing.T) {
	got := MigrationReport{
		TenantsScanned:         3,
		TeamsMigrated:          []string{"team:ops -> team:acme/ops"},
		TeamsAlreadyNamespaced: 2,
		SquattedIDs:            []string{"team:contested"},
		Skipped:                []string{"team:weird/id"},
		TuplesWritten:          7,
		TuplesDeleted:          7,
	}.String()

	for _, want := range []string{
		"tenants scanned:          3",
		"teams already namespaced: 2",
		"tuples written:           7",
		"tuples deleted:           7",
		"team:ops -> team:acme/ops",
		"SQUATTED",
		"team:contested",
		"SKIPPED",
		"team:weird/id",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report does not mention %q:\n%s", want, got)
		}
	}
}
