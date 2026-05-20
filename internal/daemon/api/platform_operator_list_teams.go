package api

// ListTeams + ListTeamMembers — read-side enumeration for the dashboard's
// Organization → Teams page. Backed by FGA `ListObjects` (teams in tenant)
// and `ListUsers` (members of a team). Pagination is opaque, server-side
// (the underlying FGA client returns the full list; we slice).
//
// dashboard#143/#148. Spec: agent-authoring-and-tenant-entitlements task 35.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/platform/v1"
)

const (
	teamsDefaultPageSize = int32(50)
	teamsMaxPageSize     = int32(200)
)

// pageCursor encodes a simple offset-based cursor. Opaque base64 JSON. We
// don't expose the offset semantics in the proto contract — clients always
// just pass the previous next_page_token verbatim.
type pageCursor struct {
	Offset int `json:"o"`
}

func encodeCursor(offset int) string {
	if offset <= 0 {
		return ""
	}
	b, _ := json.Marshal(pageCursor{Offset: offset})
	return base64.URLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid page_token: %w", err)
	}
	var c pageCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return 0, fmt.Errorf("invalid page_token: %w", err)
	}
	if c.Offset < 0 {
		return 0, fmt.Errorf("invalid page_token: negative offset")
	}
	return c.Offset, nil
}

func resolvePageSize(req int32) int32 {
	if req <= 0 {
		return teamsDefaultPageSize
	}
	if req > teamsMaxPageSize {
		return teamsMaxPageSize
	}
	return req
}

// stripTypePrefix removes the FGA "type:" prefix from an id reference.
// FGA returns objects like "team:red-team" and users like "user:42"; the
// proto contract surfaces the bare id.
func stripTypePrefix(s, typeName string) string {
	prefix := typeName + ":"
	return strings.TrimPrefix(s, prefix)
}

// ListTeams enumerates the teams under the given tenant. The dashboard
// server action gates this call on `members:invite`; the daemon-side authz
// constant is `platform_operator`, consistent with the rest of this service.
func (s *DaemonServer) ListTeams(ctx context.Context, req *platformv1.ListTeamsRequest) (*platformv1.ListTeamsResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	offset, err := decodeCursor(req.GetPageToken())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	pageSize := resolvePageSize(req.GetPageSize())

	// FGA: list all team objects whose `parent` relation is tenant:<id>.
	// teams.ts writes `(tenant:X, parent, team:Y)` on create, so the inverse
	// query is `ListObjects(user=tenant:X, relation=parent, object_type=team)`.
	tenantRef := req.GetTenantId()
	if !strings.Contains(tenantRef, ":") {
		tenantRef = "tenant:" + tenantRef
	}
	teamRefs, err := s.authorizer.ListObjects(ctx, tenantRef, "parent", "team")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListObjects: %v", err)
	}
	// Deterministic order so pagination is stable across calls. FGA does not
	// guarantee order.
	sort.Strings(teamRefs)

	out := &platformv1.ListTeamsResponse{}
	end := offset + int(pageSize)
	if end > len(teamRefs) {
		end = len(teamRefs)
	}
	for i := offset; i < end; i++ {
		teamID := stripTypePrefix(teamRefs[i], "team")
		teamObj := "team:" + teamID

		// Member count = |members| + |admins|. Two FGA round-trips per team
		// is acceptable at the realistic scale (low tens of teams per
		// tenant). If this becomes a hot path we can BatchCheck or
		// memoise — flag in the issue.
		members, err := s.authorizer.ListUsers(ctx, "team", teamObj, "member")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga ListUsers(member) for %s: %v", teamObj, err)
		}
		admins, err := s.authorizer.ListUsers(ctx, "team", teamObj, "admin")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga ListUsers(admin) for %s: %v", teamObj, err)
		}
		out.Teams = append(out.Teams, &platformv1.Team{
			Id:          teamID,
			DisplayName: "", // populated by sidecar store once dashboard#148 wires display names.
			MemberCount: int32(len(members) + len(admins)),
		})
	}
	if end < len(teamRefs) {
		out.NextPageToken = encodeCursor(end)
	}
	return out, nil
}

// ListTeamMembers enumerates the users with the `member` or `admin` relation
// on a single team. `is_admin` reflects which relation matched. The daemon
// returns bare user ids; the dashboard joins these against Zitadel for the
// `email` and `display_name` fields.
func (s *DaemonServer) ListTeamMembers(ctx context.Context, req *platformv1.ListTeamMembersRequest) (*platformv1.ListTeamMembersResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if req.GetTeamId() == "" {
		return nil, status.Error(codes.InvalidArgument, "team_id required")
	}
	offset, err := decodeCursor(req.GetPageToken())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	pageSize := resolvePageSize(req.GetPageSize())

	tenantRef := req.GetTenantId()
	if !strings.Contains(tenantRef, ":") {
		tenantRef = "tenant:" + tenantRef
	}
	teamRef := "team:" + req.GetTeamId()

	// Cross-tenant denial: verify the requested team actually belongs to the
	// caller's tenant before exposing its roster. Re-uses the parent
	// relation written at team-create time.
	owned, err := s.authorizer.Check(ctx, tenantRef, "parent", teamRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant parent: %v", err)
	}
	if !owned {
		return nil, status.Error(codes.PermissionDenied, "team not in caller's tenant")
	}

	admins, err := s.authorizer.ListUsers(ctx, "team", teamRef, "admin")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListUsers(admin): %v", err)
	}
	members, err := s.authorizer.ListUsers(ctx, "team", teamRef, "member")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListUsers(member): %v", err)
	}

	// Build a deduplicated, ordered list. A user can hold both `admin` and
	// `member` relations (the dashboard writes both on add-as-admin); the
	// admin status wins in the response.
	adminSet := make(map[string]struct{}, len(admins))
	for _, a := range admins {
		adminSet[a] = struct{}{}
	}
	combined := make([]string, 0, len(admins)+len(members))
	seen := make(map[string]struct{}, len(admins)+len(members))
	for _, u := range admins {
		if _, ok := seen[u]; !ok {
			combined = append(combined, u)
			seen[u] = struct{}{}
		}
	}
	for _, u := range members {
		if _, ok := seen[u]; !ok {
			combined = append(combined, u)
			seen[u] = struct{}{}
		}
	}
	sort.Strings(combined)

	out := &platformv1.ListTeamMembersResponse{}
	end := offset + int(pageSize)
	if end > len(combined) {
		end = len(combined)
	}
	for i := offset; i < end; i++ {
		userRef := combined[i]
		_, isAdmin := adminSet[userRef]
		out.Members = append(out.Members, &platformv1.TeamMember{
			UserId:      stripTypePrefix(userRef, "user"),
			Email:       "", // dashboard joins via Zitadel
			DisplayName: "",
			IsAdmin:     isAdmin,
		})
	}
	if end < len(combined) {
		out.NextPageToken = encodeCursor(end)
	}
	return out, nil
}
