package api

// Unit tests for ListTeams + ListTeamMembers. Hits the DaemonServer
// handlers via a fake authorizer that scripts FGA ListObjects/ListUsers
// + Check responses. Real FGA wiring is covered by the integration suite.
//
// dashboard#143/#148.

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
	platformv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/operator/v1"
)

// listTeamsFake is a programmable authorizer that scripts ListObjects/
// ListUsers/Check responses by an exact-match key. It does not extend the
// package's shared fakeAuthorizer because the team handlers need both
// ListObjects and ListUsers to return specific scripted slices, which the
// shared fake doesn't model.
type listTeamsFake struct {
	listObjects map[string][]string // key: "user|relation|objectType"
	listUsers   map[string][]string // key: "objectType|object|relation"
	checks      map[string]bool     // key: "user|relation|object"
	failOn      string              // method name to fail on (for error paths)
}

func newListTeamsFake() *listTeamsFake {
	return &listTeamsFake{
		listObjects: make(map[string][]string),
		listUsers:   make(map[string][]string),
		checks:      make(map[string]bool),
	}
}

func (f *listTeamsFake) Check(_ context.Context, user, relation, object string) (bool, error) {
	if f.failOn == "Check" {
		return false, errFake
	}
	return f.checks[user+"|"+relation+"|"+object], nil
}
func (f *listTeamsFake) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (f *listTeamsFake) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (f *listTeamsFake) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (f *listTeamsFake) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	if f.failOn == "ListObjects" {
		return nil, errFake
	}
	return f.listObjects[user+"|"+relation+"|"+objectType], nil
}
func (f *listTeamsFake) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	if f.failOn == "ListUsers" {
		return nil, errFake
	}
	return f.listUsers[objectType+"|"+object+"|"+relation], nil
}
func (f *listTeamsFake) StoreID() string { return "test-store" }
func (f *listTeamsFake) ModelID() string { return "test-model" }
func (f *listTeamsFake) Close() error    { return nil }

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }

var errFake = &fakeError{msg: "fake error"}

func newServerWithAuthz(authz authz.Authorizer) *DaemonServer {
	return &DaemonServer{authorizer: authz}
}

// -----------------------------------------------------------------------------
// ListTeams
// -----------------------------------------------------------------------------

func TestListTeams_EmptyTenantReturnsEmptyPage(t *testing.T) {
	t.Parallel()
	f := newListTeamsFake()
	s := newServerWithAuthz(f)
	resp, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{
		TenantId: "acme",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Teams) != 0 {
		t.Fatalf("expected empty teams; got %d", len(resp.Teams))
	}
	if resp.NextPageToken != "" {
		t.Fatalf("expected empty next_page_token; got %q", resp.NextPageToken)
	}
}

func TestListTeams_SingleTeamWithMixedRoster(t *testing.T) {
	t.Parallel()
	f := newListTeamsFake()
	f.listObjects["tenant:acme|parent|team"] = []string{"team:red"}
	f.listUsers["team|team:red|member"] = []string{"user:alice", "user:bob"}
	f.listUsers["team|team:red|admin"] = []string{"user:carol"}
	s := newServerWithAuthz(f)

	resp, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Teams) != 1 {
		t.Fatalf("expected 1 team; got %d", len(resp.Teams))
	}
	got := resp.Teams[0]
	if got.Id != "red" {
		t.Errorf("expected id=red; got %q", got.Id)
	}
	if got.MemberCount != 3 {
		t.Errorf("expected member_count=3 (2 members + 1 admin); got %d", got.MemberCount)
	}
}

func TestListTeams_PaginationStableAcrossCalls(t *testing.T) {
	t.Parallel()
	f := newListTeamsFake()
	f.listObjects["tenant:acme|parent|team"] = []string{
		"team:c", "team:a", "team:e", "team:b", "team:d",
	}
	// No members on any team — the request body cares about pagination, not counts.
	s := newServerWithAuthz(f)

	first, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{
		TenantId: "acme", PageSize: 2,
	})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Teams) != 2 {
		t.Fatalf("expected 2 teams on first page; got %d", len(first.Teams))
	}
	// Sorted order: a, b, c, d, e
	if first.Teams[0].Id != "a" || first.Teams[1].Id != "b" {
		t.Errorf("first page wrong order: got %v", []string{first.Teams[0].Id, first.Teams[1].Id})
	}
	if first.NextPageToken == "" {
		t.Fatalf("expected non-empty next_page_token after partial page")
	}

	second, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{
		TenantId: "acme", PageSize: 2, PageToken: first.NextPageToken,
	})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second.Teams) != 2 || second.Teams[0].Id != "c" || second.Teams[1].Id != "d" {
		t.Errorf("second page wrong: got %v", teamIDs(second.Teams))
	}
	if second.NextPageToken == "" {
		t.Fatalf("expected non-empty next_page_token after second page")
	}

	last, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{
		TenantId: "acme", PageSize: 2, PageToken: second.NextPageToken,
	})
	if err != nil {
		t.Fatalf("last page: %v", err)
	}
	if len(last.Teams) != 1 || last.Teams[0].Id != "e" {
		t.Errorf("last page wrong: got %v", teamIDs(last.Teams))
	}
	if last.NextPageToken != "" {
		t.Errorf("expected empty next_page_token on final page; got %q", last.NextPageToken)
	}
}

func TestListTeams_PageSizeClamp(t *testing.T) {
	t.Parallel()
	if got := resolvePageSize(0); got != teamsDefaultPageSize {
		t.Errorf("0 → default; got %d", got)
	}
	if got := resolvePageSize(-5); got != teamsDefaultPageSize {
		t.Errorf("negative → default; got %d", got)
	}
	if got := resolvePageSize(10); got != 10 {
		t.Errorf("10 → 10; got %d", got)
	}
	if got := resolvePageSize(500); got != teamsMaxPageSize {
		t.Errorf("500 → max; got %d", got)
	}
}

func TestListTeams_MissingTenantIDInvalidArgument(t *testing.T) {
	t.Parallel()
	s := newServerWithAuthz(newListTeamsFake())
	_, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument; got %v", err)
	}
}

func TestListTeams_InvalidPageTokenInvalidArgument(t *testing.T) {
	t.Parallel()
	s := newServerWithAuthz(newListTeamsFake())
	_, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{
		TenantId: "acme", PageToken: "not-base64-or-json",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument on bad page_token; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// ListTeamMembers
// -----------------------------------------------------------------------------

func TestListTeamMembers_AdminFlagReflectsRelation(t *testing.T) {
	t.Parallel()
	f := newListTeamsFake()
	f.checks["tenant:acme|parent|team:red"] = true
	f.listUsers["team|team:red|admin"] = []string{"user:carol"}
	f.listUsers["team|team:red|member"] = []string{"user:alice", "user:bob"}
	s := newServerWithAuthz(f)

	resp, err := s.ListTeamMembers(context.Background(), &platformv1.ListTeamMembersRequest{
		TenantId: "acme", TeamId: "red",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Members) != 3 {
		t.Fatalf("expected 3 members; got %d", len(resp.Members))
	}
	byID := map[string]bool{}
	for _, m := range resp.Members {
		byID[m.UserId] = m.IsAdmin
	}
	if !byID["carol"] {
		t.Errorf("carol should be admin; got %v", byID)
	}
	if byID["alice"] || byID["bob"] {
		t.Errorf("alice/bob should not be admin; got %v", byID)
	}
}

func TestListTeamMembers_CrossTenantPermissionDenied(t *testing.T) {
	t.Parallel()
	f := newListTeamsFake()
	// Note: NO check entry for tenant:acme|parent|team:red — Check returns false.
	f.listUsers["team|team:red|admin"] = []string{"user:should-not-leak"}
	s := newServerWithAuthz(f)

	_, err := s.ListTeamMembers(context.Background(), &platformv1.ListTeamMembersRequest{
		TenantId: "acme", TeamId: "red",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied; got %v", err)
	}
}

func TestListTeamMembers_DedupesUserHoldingBothRelations(t *testing.T) {
	t.Parallel()
	f := newListTeamsFake()
	f.checks["tenant:acme|parent|team:red"] = true
	// teams.ts writes BOTH `admin` and `member` when adding as admin; the
	// handler must surface a single row with is_admin=true.
	f.listUsers["team|team:red|admin"] = []string{"user:carol"}
	f.listUsers["team|team:red|member"] = []string{"user:carol", "user:bob"}
	s := newServerWithAuthz(f)

	resp, err := s.ListTeamMembers(context.Background(), &platformv1.ListTeamMembersRequest{
		TenantId: "acme", TeamId: "red",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Members) != 2 {
		t.Fatalf("expected 2 distinct members after dedup; got %d (%v)", len(resp.Members), memberIDs(resp.Members))
	}
	for _, m := range resp.Members {
		if m.UserId == "carol" && !m.IsAdmin {
			t.Errorf("carol should be flagged admin")
		}
		if m.UserId == "bob" && m.IsAdmin {
			t.Errorf("bob should not be flagged admin")
		}
	}
}

func TestListTeamMembers_MissingTeamIDInvalidArgument(t *testing.T) {
	t.Parallel()
	s := newServerWithAuthz(newListTeamsFake())
	_, err := s.ListTeamMembers(context.Background(), &platformv1.ListTeamMembersRequest{TenantId: "acme"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument; got %v", err)
	}
}

func TestListTeams_NilAuthorizerUnavailable(t *testing.T) {
	t.Parallel()
	s := &DaemonServer{authorizer: nil}
	_, err := s.ListTeams(context.Background(), &platformv1.ListTeamsRequest{TenantId: "acme"})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("expected Unavailable; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Cursor encode/decode round-trip
// -----------------------------------------------------------------------------

func TestPageCursor_RoundTrip(t *testing.T) {
	t.Parallel()
	cases := []int{0, 1, 50, 200, 1000}
	for _, offset := range cases {
		encoded := encodeCursor(offset)
		if offset == 0 && encoded != "" {
			t.Errorf("offset=0 should encode to empty string, got %q", encoded)
			continue
		}
		decoded, err := decodeCursor(encoded)
		if err != nil {
			t.Errorf("decode(%q): %v", encoded, err)
			continue
		}
		if decoded != offset {
			t.Errorf("round-trip failed: encoded=%d, decoded=%d", offset, decoded)
		}
	}
}

func TestPageCursor_DecodeRejectsGarbage(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"###", "not-base64!@", "YWJjZA=="} {
		if _, err := decodeCursor(bad); err == nil {
			t.Errorf("expected error decoding %q", bad)
		}
	}
}

func TestPageCursor_DecodeRejectsNegativeOffset(t *testing.T) {
	t.Parallel()
	negEncoded := "eyJvIjotMX0=" // {"o":-1}
	if _, err := decodeCursor(negEncoded); err == nil {
		t.Errorf("expected error on negative offset")
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func teamIDs(teams []*platformv1.Team) []string {
	out := make([]string, len(teams))
	for i, t := range teams {
		out[i] = t.Id
	}
	return out
}

func memberIDs(members []*platformv1.TeamMember) []string {
	out := make([]string, len(members))
	for i, m := range members {
		out[i] = m.UserId
	}
	return out
}

func TestStripTypePrefix(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, prefix, want string }{
		{"team:red", "team", "red"},
		{"user:42", "user", "42"},
		{"plain", "team", "plain"}, // no prefix → unchanged
		{"team:", "team", ""},      // empty id after prefix
	}
	for _, c := range cases {
		if got := stripTypePrefix(c.in, c.prefix); got != c.want {
			t.Errorf("stripTypePrefix(%q, %q) = %q; want %q", c.in, c.prefix, got, c.want)
		}
	}
	// strings.Contains usage in the handler — bare prefix check.
	if !strings.Contains("tenant:acme", ":") {
		t.Errorf("sanity: colon detection")
	}
}
