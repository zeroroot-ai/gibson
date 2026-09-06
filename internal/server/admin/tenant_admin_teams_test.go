// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// teamStore — a shared, concurrency-safe, in-memory FGA store
// ---------------------------------------------------------------------------

// teamStore is a real (if tiny) tuple store rather than a canned-answer stub.
// The property under test is what the whole team surface does to a SHARED
// store when several tenants use it at once, and a per-call stub cannot express
// "these two tenants ended up on the same object" — which is the entire defect.
//
// readBarrier holds every caller inside the first FGA READ until all racers
// have read, or until a short timeout. That matters for the mutation runs: the
// pre-namespace CreateTeam was a read ("does anyone else parent this id?")
// followed by a write, and the barrier is what makes its interleaving happen
// every time rather than occasionally. The current code performs no read at
// all, so the barrier is simply never reached — the timeout is what keeps that
// from hanging.
type teamStore struct {
	mu     sync.Mutex
	tuples map[string]authz.Tuple

	barrier   sync.WaitGroup
	barrierCh chan struct{}
	once      sync.Once
	armed     bool
}

func newTeamStore(racers int) *teamStore {
	s := &teamStore{
		tuples:    map[string]authz.Tuple{},
		barrierCh: make(chan struct{}),
	}
	if racers > 1 {
		s.armed = true
		s.barrier.Add(racers)
	}
	return s
}

func (s *teamStore) holdAtReadBarrier() {
	if !s.armed {
		return
	}
	s.barrier.Done()
	go s.once.Do(func() { s.barrier.Wait(); close(s.barrierCh) })
	select {
	case <-s.barrierCh:
	case <-time.After(200 * time.Millisecond):
	}
}

func (s *teamStore) put(t authz.Tuple) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tuples[tupleKey(t)] = t
}

func (s *teamStore) snapshot() []authz.Tuple {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authz.Tuple, 0, len(s.tuples))
	for _, t := range s.tuples {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return tupleKey(out[i]) < tupleKey(out[j]) })
	return out
}

// parentsOf returns the tenants holding `parent` on the given team object.
func (s *teamStore) parentsOf(teamObj string) []string {
	var out []string
	for _, t := range s.snapshot() {
		if t.Relation == "parent" && t.Object == teamObj {
			out = append(out, t.User)
		}
	}
	sort.Strings(out)
	return out
}

// teamObjects returns every distinct object of type team that has a parent.
func (s *teamStore) teamObjects() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range s.snapshot() {
		if t.Relation == "parent" && strings.HasPrefix(t.Object, "team:") {
			if _, ok := seen[t.Object]; !ok {
				seen[t.Object] = struct{}{}
				out = append(out, t.Object)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *teamStore) Check(_ context.Context, user, relation, object string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tuples[tupleKey(authz.Tuple{User: user, Relation: relation, Object: object})]
	return ok, nil
}

func (s *teamStore) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		ok, err := s.Check(ctx, c.User, c.Relation, c.Object)
		if err != nil {
			return nil, err
		}
		out[i] = ok
	}
	return out, nil
}

func (s *teamStore) Write(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		s.put(t)
	}
	return nil
}

func (s *teamStore) Delete(_ context.Context, tuples []authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tuples {
		delete(s.tuples, tupleKey(t))
	}
	return nil
}

func (s *teamStore) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	var out []string
	for _, t := range s.snapshot() {
		if t.User == user && t.Relation == relation && strings.HasPrefix(t.Object, objectType+":") {
			out = append(out, t.Object)
		}
	}
	return out, nil
}

// ListUsers mirrors the real client: the subject filter is hardcoded to "user".
func (s *teamStore) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	return s.listUsers(objectType, object, relation, "user"), nil
}

func (s *teamStore) ListUsersOfType(_ context.Context, objectType, object, relation, userType string) ([]string, error) {
	s.holdAtReadBarrier()
	return s.listUsers(objectType, object, relation, userType), nil
}

func (s *teamStore) listUsers(objectType, object, relation, userType string) []string {
	if !strings.HasPrefix(object, objectType+":") {
		return nil
	}
	var out []string
	for _, t := range s.snapshot() {
		if t.Object == object && t.Relation == relation && strings.HasPrefix(t.User, userType+":") {
			out = append(out, t.User)
		}
	}
	return out
}

func (s *teamStore) StoreID() string { return "test-store" }
func (s *teamStore) ModelID() string { return "test-model" }
func (s *teamStore) Close() error    { return nil }

var _ authz.Authorizer = (*teamStore)(nil)

// teamServer wires a TenantAdminServer onto a shared store.
func teamServer(t *testing.T, store *teamStore) *TenantAdminServer {
	t.Helper()
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = store
	return srv
}

// seedTenantMember makes user a member of tenant, which AddTeamMember requires
// before it will put them on one of that tenant's teams.
func seedTenantMember(store *teamStore, tenant, user string) {
	store.put(authz.Tuple{User: "user:" + user, Relation: "member", Object: "tenant:" + tenant})
}

// ---------------------------------------------------------------------------
// The race (gibson#1231)
// ---------------------------------------------------------------------------

// TestCreateTeam_ConcurrentSameIDAcrossTenantsCannotCollide is the regression
// for gibson#1231.
//
// Team object ids used to be global. `team.parent` is a plain [tenant] relation
// with no cardinality constraint, so two tenants could hold a parent tuple on
// the SAME team object, and every other team RPC gates on exactly that edge —
// so the second parent handed the squatter the victim's roster and, through
// `admin: [user] or admin from parent`, administration of it. CreateTeam
// guarded that with a read followed by a write, which two callers can both pass.
//
// Object ids are now built from the caller's own ext-authz tenant, so the
// tenants below are not competing for anything. This test races them at the
// same team id and asserts the property that makes the guard unnecessary:
//
//   - every tenant succeeds (nobody's legitimate id is refused because someone
//     else asked for it);
//   - the store ends up with one DISTINCT object per tenant;
//   - each object has exactly one parent, and it is that tenant's own.
//
// Both of the pre-fix shapes fail it. With the global id plus the serialising
// claim lock, one racer wins and the rest get AlreadyExists — the first
// assertion goes red. With the global id and no lock, all four succeed onto one
// object with four parents — the second and third go red. Run with -race.
func TestCreateTeam_ConcurrentSameIDAcrossTenantsCannotCollide(t *testing.T) {
	const racers = 4
	store := newTeamStore(racers)

	start := make(chan struct{})
	results := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv := teamServer(t, store)
			<-start
			_, results[i] = srv.CreateTeam(
				adminCtx(t, fmt.Sprintf("tenant-%d", i)),
				&tenantv1.CreateTeamRequest{TeamId: "ops"},
			)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Errorf("racer %d (tenant-%d): CreateTeam failed with %v; every tenant owns its own namespace, so none of them may be refused",
				i, i, err)
		}
	}

	objects := store.teamObjects()
	if len(objects) != racers {
		t.Errorf("store holds %d team objects (%v), want %d — one per tenant", len(objects), objects, racers)
	}
	for i := range racers {
		tenant := fmt.Sprintf("tenant-%d", i)
		want := "team:" + tenant + "/ops"
		parents := store.parentsOf(want)
		if len(parents) != 1 || parents[0] != "tenant:"+tenant {
			t.Errorf("%s has parents %v, want exactly [tenant:%s]", want, parents, tenant)
		}
	}
	for _, obj := range objects {
		if got := store.parentsOf(obj); len(got) != 1 {
			t.Errorf("%s has %d parents (%v), want 1 — a team object with two tenant parents IS the squat",
				obj, len(got), got)
		}
	}
}

// TestCreateTeam_ConcurrentSameTenantSameIDIsIdempotent covers the other half
// of the concurrency story: one tenant retrying its own create (an install
// script, a double-clicked button) must converge on a single object with a
// single parent, not fail and not duplicate.
func TestCreateTeam_ConcurrentSameTenantSameIDIsIdempotent(t *testing.T) {
	const racers = 4
	store := newTeamStore(racers)

	start := make(chan struct{})
	results := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv := teamServer(t, store)
			<-start
			_, results[i] = srv.CreateTeam(adminCtx(t, "acme"), &tenantv1.CreateTeamRequest{TeamId: "ops"})
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Errorf("racer %d: CreateTeam failed with %v; re-creating your own team is idempotent", i, err)
		}
	}
	if objects := store.teamObjects(); len(objects) != 1 || objects[0] != "team:acme/ops" {
		t.Errorf("store holds %v, want exactly [team:acme/ops]", objects)
	}
	if parents := store.parentsOf("team:acme/ops"); len(parents) != 1 {
		t.Errorf("team:acme/ops has parents %v, want exactly one", parents)
	}
}

// TestTeamRPCs_KnowingTheIDDoesNotReachAnotherTenantsTeam is the direct
// statement of what the namespace buys, and it also covers the pre-existing
// squats the old read-then-write guard could not: victim-co's team is created
// FIRST, so a guard that only refuses new claims would have nothing to say
// here.
//
// evil-co knows the id and asks every parent-gated RPC for it. Each must deny,
// and victim-co's roster must be untouched afterwards.
func TestTeamRPCs_KnowingTheIDDoesNotReachAnotherTenantsTeam(t *testing.T) {
	store := newTeamStore(1)
	victim := teamServer(t, store)
	attacker := teamServer(t, store)

	seedTenantMember(store, "victim-co", "alice")
	if _, err := victim.CreateTeam(adminCtx(t, "victim-co"), &tenantv1.CreateTeamRequest{TeamId: "ops"}); err != nil {
		t.Fatalf("victim CreateTeam: %v", err)
	}
	if _, err := victim.AddTeamMember(adminCtx(t, "victim-co"),
		&tenantv1.AddTeamMemberRequest{TeamId: "ops", UserId: "alice"}); err != nil {
		t.Fatalf("victim AddTeamMember: %v", err)
	}

	// The squat itself: evil-co creates the same id. It must succeed (it is
	// their own namespace) and it must not touch victim-co's object.
	if _, err := attacker.CreateTeam(adminCtx(t, "evil-co"), &tenantv1.CreateTeamRequest{TeamId: "ops"}); err != nil {
		t.Fatalf("evil-co CreateTeam: %v — creating a team id in your own namespace is always allowed", err)
	}
	if parents := store.parentsOf("team:victim-co/ops"); len(parents) != 1 || parents[0] != "tenant:victim-co" {
		t.Fatalf("victim's team has parents %v, want exactly [tenant:victim-co]", parents)
	}

	// One subtest per parent-gated team RPC. The bodies are named functions so
	// this stays an index of the covered surface: an RPC missing from this list
	// is an RPC nothing here proves is namespaced. Each builds evil-co's own
	// caller context, so the RPC and the follow-up store assertion are made
	// under one identity.
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, attacker *TenantAdminServer, store *teamStore)
	}{
		{"ListTeamMembers cannot read the roster", assertListTeamMembersIsNamespaced},
		{"ListTeams does not surface the victim's team", assertListTeamsIsNamespaced},
		{"SetTeamAdmin cannot promote into the victim's team", assertSetTeamAdminIsNamespaced},
		{"DeleteTeam cannot delete the victim's team", assertDeleteTeamIsNamespaced},
		{"RemoveTeamMember cannot evict from the victim's team", assertRemoveTeamMemberIsNamespaced},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, attacker, store)
		})
	}
}

func assertListTeamMembersIsNamespaced(t *testing.T, attacker *TenantAdminServer, _ *teamStore) {
	t.Helper()
	evilCtx := adminCtx(t, "evil-co")
	resp, err := attacker.ListTeamMembers(evilCtx, &tenantv1.ListTeamMembersRequest{TeamId: "ops"})
	if err != nil {
		t.Fatalf("ListTeamMembers on evil-co's own empty team: %v", err)
	}
	for _, m := range resp.GetMembers() {
		if m.GetUserId() == "alice" {
			t.Fatalf("evil-co read victim-co's member %q", m.GetUserId())
		}
	}
	if len(resp.GetMembers()) != 0 {
		t.Errorf("evil-co's own team has %d members, want 0", len(resp.GetMembers()))
	}
}

func assertListTeamsIsNamespaced(t *testing.T, attacker *TenantAdminServer, _ *teamStore) {
	t.Helper()
	evilCtx := adminCtx(t, "evil-co")
	resp, err := attacker.ListTeams(evilCtx, &tenantv1.ListTeamsRequest{})
	if err != nil {
		t.Fatalf("ListTeams: %v", err)
	}
	if len(resp.GetTeams()) != 1 || resp.GetTeams()[0].GetId() != "ops" {
		t.Fatalf("evil-co sees %d teams, want its own single \"ops\"", len(resp.GetTeams()))
	}
	if got := resp.GetTeams()[0].GetMemberCount(); got != 0 {
		t.Errorf("evil-co's own \"ops\" reports %d members, want 0 — a non-zero count here means it is reading the victim's object", got)
	}
}

func assertSetTeamAdminIsNamespaced(t *testing.T, attacker *TenantAdminServer, store *teamStore) {
	t.Helper()
	evilCtx := adminCtx(t, "evil-co")
	// alice is not a member of evil-co, so the write must not land on
	// victim-co's object under any code path.
	_, err := attacker.SetTeamAdmin(evilCtx,
		&tenantv1.SetTeamAdminRequest{TeamId: "ops", UserId: "alice", IsAdmin: true})
	if err != nil && status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetTeamAdmin: unexpected error %v", err)
	}
	if ok, _ := store.Check(evilCtx, "user:alice", "admin", "team:victim-co/ops"); ok {
		t.Error("evil-co made alice an admin of victim-co's team")
	}
}

func assertDeleteTeamIsNamespaced(t *testing.T, attacker *TenantAdminServer, store *teamStore) {
	t.Helper()
	evilCtx := adminCtx(t, "evil-co")
	if _, err := attacker.DeleteTeam(evilCtx, &tenantv1.DeleteTeamRequest{TeamId: "ops"}); err != nil {
		t.Fatalf("DeleteTeam on evil-co's own team: %v", err)
	}
	if parents := store.parentsOf("team:victim-co/ops"); len(parents) != 1 {
		t.Errorf("victim-co's team lost its parent after evil-co deleted its own: parents=%v", parents)
	}
	if ok, _ := store.Check(evilCtx, "user:alice", "member", "team:victim-co/ops"); !ok {
		t.Error("victim-co's roster was destroyed by evil-co's delete")
	}
}

func assertRemoveTeamMemberIsNamespaced(t *testing.T, attacker *TenantAdminServer, store *teamStore) {
	t.Helper()
	evilCtx := adminCtx(t, "evil-co")
	_, err := attacker.RemoveTeamMember(evilCtx,
		&tenantv1.RemoveTeamMemberRequest{TeamId: "ops", UserId: "alice"})
	if err != nil && status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RemoveTeamMember: unexpected error %v", err)
	}
	if ok, _ := store.Check(evilCtx, "user:alice", "member", "team:victim-co/ops"); !ok {
		t.Error("evil-co removed alice from victim-co's team")
	}
}

// ---------------------------------------------------------------------------
// The object-id contract
// ---------------------------------------------------------------------------

// TestCreateTeam_RejectsUnsafeTeamIDs pins the validation that makes
// `team:<tenant>/<id>` parseable and un-forgeable.
//
// A '/' would make the split between the tenant and the team ambiguous. A '#'
// would turn the object into a userset — the component-access relations take
// `team:<id>#member` subjects, so an id ending in "#member" is not a
// theoretical confusion. A ':' would introduce a second type prefix. None of
// these was rejected before: the id went straight into the object reference.
func TestCreateTeam_RejectsUnsafeTeamIDs(t *testing.T) {
	for _, tc := range []struct{ name, teamID string }{
		{"empty", ""},
		{"namespace separator", "acme/ops"},
		{"userset suffix", "ops#member"},
		{"type prefix", "team:ops"},
		{"space", "ops team"},
		{"tab", "ops\tteam"},
		{"too long", strings.Repeat("a", authz.TeamObjectMaxIDLen+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTeamStore(1)
			srv := teamServer(t, store)
			_, err := srv.CreateTeam(adminCtx(t, "acme"), &tenantv1.CreateTeamRequest{TeamId: tc.teamID})
			if err == nil {
				t.Fatalf("CreateTeam(%q): expected rejection, got nil", tc.teamID)
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("CreateTeam(%q): code = %v, want InvalidArgument (err: %v)", tc.teamID, status.Code(err), err)
			}
			if got := store.snapshot(); len(got) != 0 {
				t.Errorf("CreateTeam(%q) wrote %v, want nothing", tc.teamID, got)
			}
		})
	}
}

// TestCreateTeam_AcceptsOrdinarySlugs is the positive side of the rule above.
// A validator that rejected everything would make every test in this file pass
// for the wrong reason.
func TestCreateTeam_AcceptsOrdinarySlugs(t *testing.T) {
	for _, id := range []string{"ops", "red-team", "team_2", "eng.platform", "ÄÖÜ-team"} {
		t.Run(id, func(t *testing.T) {
			store := newTeamStore(1)
			srv := teamServer(t, store)
			if _, err := srv.CreateTeam(adminCtx(t, "acme"), &tenantv1.CreateTeamRequest{TeamId: id}); err != nil {
				t.Fatalf("CreateTeam(%q): %v", id, err)
			}
			if parents := store.parentsOf("team:acme/" + id); len(parents) != 1 {
				t.Errorf("team:acme/%s has parents %v, want one", id, parents)
			}
		})
	}
}

func TestTeamRefAndTeamIDFromRef(t *testing.T) {
	ref, err := teamRef("acme", "ops")
	if err != nil {
		t.Fatalf("teamRef: %v", err)
	}
	if ref != "team:acme/ops" {
		t.Fatalf("teamRef = %q, want team:acme/ops", ref)
	}
	// An already-prefixed tenant is normalised, matching tenantRefFromID.
	if got, err := teamRef("tenant:acme", "ops"); err != nil || got != ref {
		t.Errorf("teamRef(\"tenant:acme\", ...) = %q, %v; want %q, nil", got, err, ref)
	}

	for _, tc := range []struct {
		name, tenant, ref, wantID string
		wantOK                    bool
	}{
		{"own team", "acme", "team:acme/ops", "ops", true},
		{"another tenant's team", "acme", "team:evil-co/ops", "", false},
		{"legacy un-namespaced", "acme", "team:ops", "", false},
		{"prefix collision", "acme", "team:acme-corp/ops", "", false},
		{"empty id", "acme", "team:acme/", "", false},
		{"nested separator", "acme", "team:acme/a/b", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := teamIDFromRef(tc.tenant, tc.ref)
			if ok != tc.wantOK || id != tc.wantID {
				t.Errorf("teamIDFromRef(%q, %q) = %q, %v; want %q, %v",
					tc.tenant, tc.ref, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

// TestListTeams_SkipsObjectsOutsideTheCallersNamespace covers the read side of
// the same rule. FGA should never return another tenant's object for this
// user, and a legacy un-namespaced object belongs to nobody in particular —
// reporting either as one of the caller's teams would re-create the ambiguity
// the namespace removes.
func TestListTeams_SkipsObjectsOutsideTheCallersNamespace(t *testing.T) {
	store := newTeamStore(1)
	srv := teamServer(t, store)

	store.put(authz.Tuple{User: "tenant:acme", Relation: "parent", Object: "team:acme/ops"})
	store.put(authz.Tuple{User: "tenant:acme", Relation: "parent", Object: "team:legacy-global"})
	store.put(authz.Tuple{User: "tenant:acme", Relation: "parent", Object: "team:other-co/theirs"})

	resp, err := srv.ListTeams(adminCtx(t, "acme"), &tenantv1.ListTeamsRequest{})
	if err != nil {
		t.Fatalf("ListTeams: %v", err)
	}
	ids := make([]string, 0, len(resp.GetTeams()))
	for _, team := range resp.GetTeams() {
		ids = append(ids, team.GetId())
	}
	if len(ids) != 1 || ids[0] != "ops" {
		t.Errorf("ListTeams returned %v, want exactly [ops]", ids)
	}
}

// TestListTeams_PaginatesTheFilteredSet pins that the cursor counts teams the
// caller can actually see. Filtering after the page window would hand back
// short pages and a cursor that skips real teams.
func TestListTeams_PaginatesTheFilteredSet(t *testing.T) {
	store := newTeamStore(1)
	srv := teamServer(t, store)

	for _, id := range []string{"a", "b", "c"} {
		store.put(authz.Tuple{User: "tenant:acme", Relation: "parent", Object: "team:acme/" + id})
	}
	store.put(authz.Tuple{User: "tenant:acme", Relation: "parent", Object: "team:legacy"})

	var seen []string
	token := ""
	for range 5 {
		resp, err := srv.ListTeams(adminCtx(t, "acme"),
			&tenantv1.ListTeamsRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("ListTeams: %v", err)
		}
		for _, team := range resp.GetTeams() {
			seen = append(seen, team.GetId())
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	sort.Strings(seen)
	if strings.Join(seen, ",") != "a,b,c" {
		t.Errorf("paged through %v, want [a b c]", seen)
	}
}

// TestAddTeamMember_StillRequiresTenantMembership guards a check the namespace
// does NOT replace: the target user must already be a member of the tenant.
// Namespacing stops another tenant reaching this team; it says nothing about
// which users may join it.
func TestAddTeamMember_StillRequiresTenantMembership(t *testing.T) {
	store := newTeamStore(1)
	srv := teamServer(t, store)
	if _, err := srv.CreateTeam(adminCtx(t, "acme"), &tenantv1.CreateTeamRequest{TeamId: "ops"}); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	_, err := srv.AddTeamMember(adminCtx(t, "acme"),
		&tenantv1.AddTeamMemberRequest{TeamId: "ops", UserId: "outsider"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddTeamMember: code = %v, want PermissionDenied (err: %v)", status.Code(err), err)
	}
	if ok, _ := store.Check(context.Background(), "user:outsider", "member", "team:acme/ops"); ok {
		t.Error("a non-member of the tenant was added to one of its teams")
	}
}
