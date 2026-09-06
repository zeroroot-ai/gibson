// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — tenant_admin_teams.go
//
// TenantAdminServer team-management and reserved-names handlers implementing
// the RPC surface added by platform-sdk issues #395 and #396.
//
// GetReservedNames (unauthenticated — ext-authz bypasses JWT check):
//
//	Returns the chart-managed reserved-names denylist for the signup form.
//	Defers to the ReservedNamesProvider wired via TenantAdminConfig.ReservedNames;
//	returns empty lists when the provider is nil (kind dev path or missing mount).
//
// ListTeams / ListTeamMembers / CreateTeam / DeleteTeam /
// AddTeamMember / RemoveTeamMember / SetTeamAdmin (all require admin on tenant):
//
//	FGA-backed team-management operations. Every one of them resolves its
//	tenant through requireCallerTenant (tenant_scope.go), so the scope is the
//	caller's own tenant from the ext-authz context and a request naming another
//	tenant is rejected.
//
//	The team object id itself is then built from that same context tenant —
//	`team:<tenant>/<team_id>`, see team_object_ref.go. The wire still carries a
//	bare team id, but no handler uses it as an object id directly, so a caller
//	cannot name a team outside their own namespace at all. The `parent` checks
//	below are what remains: with the namespace they answer "does this team
//	exist?" rather than "is it yours?", and the parent edge stays the single
//	authority on team ownership.
//
// Pagination uses an opaque base64 URL-encoded JSON cursor ({"o": offset}).
// This mirrors the DaemonServer.ListTeams pattern in
// internal/server/daemon/api/platform_operator_list_teams.go so the two surfaces
// behave identically from the dashboard's perspective.
//
// Spec: tenant-service-admin-handlers issues #395 and #396.
package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// Pagination helpers (mirrors internal/server/daemon/api/platform_operator_list_teams.go)
// ---------------------------------------------------------------------------

const (
	tenantAdminTeamsDefaultPageSize = int32(50)
	tenantAdminTeamsMaxPageSize     = int32(200)
)

type teamPageCursor struct {
	Offset int `json:"o"`
}

func encodeTeamCursor(offset int) string {
	if offset <= 0 {
		return ""
	}
	b, _ := json.Marshal(teamPageCursor{Offset: offset})
	return base64.URLEncoding.EncodeToString(b)
}

func decodeTeamCursor(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid page_token: %w", err)
	}
	var c teamPageCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return 0, fmt.Errorf("invalid page_token: %w", err)
	}
	if c.Offset < 0 {
		return 0, fmt.Errorf("invalid page_token: negative offset")
	}
	return c.Offset, nil
}

func resolveTeamPageSize(req int32) int32 {
	if req <= 0 {
		return tenantAdminTeamsDefaultPageSize
	}
	if req > tenantAdminTeamsMaxPageSize {
		return tenantAdminTeamsMaxPageSize
	}
	return req
}

// stripFGATypePrefix removes the "type:" prefix from an FGA object reference.
// FGA returns objects like "team:red-team" and users like "user:42"; the proto
// surfaces the bare ID without the prefix.
func stripFGATypePrefix(s, typeName string) string {
	return strings.TrimPrefix(s, typeName+":")
}

// tenantRefFromID builds the canonical FGA tenant reference from an inbound
// tenant id, applying the "tenant:" type prefix exactly once. The id is
// normalized defensively: a caller that already sends "tenant:<slug>" (a past
// dashboard bug, fixed in dashboard#603) cannot produce a double-prefixed,
// malformed tuple like "tenant:tenant:<slug>". The wire contract remains the
// bare slug; this only guarantees the daemon never writes a bad tuple.
func tenantRefFromID(tenantID string) string {
	return "tenant:" + stripFGATypePrefix(tenantID, "tenant")
}

// ---------------------------------------------------------------------------
// GetReservedNames (#395)
// ---------------------------------------------------------------------------

// GetReservedNames returns the chart-managed reserved-names denylist for the
// signup form. Unauthenticated (ext-authz configured with unauthenticated:true);
// the ext-authz bypass is encoded in the proto annotation, not enforced here.
//
// Returns empty lists when the ReservedNamesProvider is not wired. This is the
// same fail-open behaviour as the equivalent DaemonServer handler so callers
// can rely on the RPC being safe to call unconditionally.
func (s *TenantAdminServer) GetReservedNames(ctx context.Context, _ *tenantv1.GetReservedNamesRequest) (*tenantv1.GetReservedNamesResponse, error) {
	if s.reservedNames == nil {
		// Empty lists are a valid response — the chart may have wiped the
		// ConfigMap or the daemon may be running without K8s access (kind
		// dev path). Return empty rather than Unavailable so callers can
		// rely on the RPC being safe to call unconditionally.
		return &tenantv1.GetReservedNamesResponse{}, nil
	}
	exact, prefix, err := s.reservedNames.ReservedNames(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "reserved-names provider failed: %v", err)
	}
	return &tenantv1.GetReservedNamesResponse{
		Exact:  exact,
		Prefix: prefix,
	}, nil
}

// ---------------------------------------------------------------------------
// ListTeams (#396)
// ---------------------------------------------------------------------------

// ListTeams enumerates teams belonging to the caller's tenant. Requires the
// admin relation on the caller's tenant object (enforced by ext-authz from the
// proto annotation).
//
// FGA query: ListObjects(user="tenant:<id>", relation="parent", object_type="team")
// CreateTeam writes (tenant:X, parent, team:X/Y) at team-create time; it is the
// only writer of that edge.
//
// Team object ids are tenant-namespaced (team_object_ref.go), so every
// reference this listing can legitimately return starts with the caller's own
// namespace. One that does not is either another tenant's team — which FGA
// should never have returned for this user, and which must not be reported as
// the caller's — or a legacy un-namespaced `team:<id>` from before the
// namespace existed. Both are skipped with a WARN rather than trimmed to
// something plausible: an unattributable object id is exactly the condition the
// namespace removes, so guessing at one here would put it back.
func (s *TenantAdminServer) ListTeams(ctx context.Context, req *tenantv1.ListTeamsRequest) (*tenantv1.ListTeamsResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}

	offset, err := decodeTeamCursor(req.GetPageToken())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	pageSize := resolveTeamPageSize(req.GetPageSize())

	tenantRef := tenantRefFromID(tenantID)
	teamRefs, err := s.authorizer.ListObjects(ctx, tenantRef, "parent", "team")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListObjects(teams): %v", err)
	}
	// Drop anything outside the caller's namespace before paginating, so the
	// page size and the cursor count real teams rather than filtered-out rows.
	owned := make([]string, 0, len(teamRefs))
	for _, ref := range teamRefs {
		if _, ok := teamIDFromRef(tenantID, ref); !ok {
			s.logger.WarnContext(ctx, "ListTeams: skipping team object outside the caller's namespace",
				slog.String("caller_tenant", tenantRef),
				slog.String("team_object", ref),
			)
			continue
		}
		owned = append(owned, ref)
	}
	// Deterministic order so pagination is stable across calls.
	sort.Strings(owned)

	out := &tenantv1.ListTeamsResponse{}
	end := offset + int(pageSize)
	if end > len(owned) {
		end = len(owned)
	}
	for i := offset; i < end; i++ {
		teamObj := owned[i]
		teamID, _ := teamIDFromRef(tenantID, teamObj)

		// Member count = |members| + |admins|. Two FGA round-trips per team
		// is acceptable at the realistic scale (low tens of teams per tenant).
		members, memberErr := s.authorizer.ListUsers(ctx, "team", teamObj, "member")
		if memberErr != nil {
			return nil, status.Errorf(codes.Internal, "fga ListUsers(member) for %s: %v", teamObj, memberErr)
		}
		admins, adminErr := s.authorizer.ListUsers(ctx, "team", teamObj, "admin")
		if adminErr != nil {
			return nil, status.Errorf(codes.Internal, "fga ListUsers(admin) for %s: %v", teamObj, adminErr)
		}
		out.Teams = append(out.Teams, &tenantv1.Team{
			Id:          teamID,
			DisplayName: "", // populated by a future display-name store
			MemberCount: int32(len(members) + len(admins)),
		})
	}
	if end < len(owned) {
		out.NextPageToken = encodeTeamCursor(end)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// ListTeamMembers (#396)
// ---------------------------------------------------------------------------

// ListTeamMembers enumerates the members and admins of a single team.
// Enforces a cross-tenant guard: the team must belong to the caller's tenant
// (verified via the FGA parent relation written at team-create time).
func (s *TenantAdminServer) ListTeamMembers(ctx context.Context, req *tenantv1.ListTeamMembersRequest) (*tenantv1.ListTeamMembersResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	offset, err := decodeTeamCursor(req.GetPageToken())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	pageSize := resolveTeamPageSize(req.GetPageSize())

	tenantRef := tenantRefFromID(tenantID)
	teamObj, err := teamRef(tenantID, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	// Cross-tenant denial: verify the requested team actually belongs to the
	// caller's tenant before exposing its roster. The namespace already makes
	// another tenant's team unnameable from here, so this Check now answers
	// "does this team exist?" rather than "is it yours?" — it stays because
	// existence is still the precondition for a roster read, and because the
	// parent edge remains the single authority on team ownership.
	owned, checkErr := s.authorizer.Check(ctx, tenantRef, "parent", teamObj)
	if checkErr != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant parent: %v", checkErr)
	}
	if !owned {
		return nil, status.Error(codes.PermissionDenied, "team not in caller's tenant")
	}

	admins, err := s.authorizer.ListUsers(ctx, "team", teamObj, "admin")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListUsers(admin): %v", err)
	}
	memberRefs, err := s.authorizer.ListUsers(ctx, "team", teamObj, "member")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListUsers(member): %v", err)
	}

	// Build a deduplicated, ordered list. Admin status wins over member.
	adminSet := make(map[string]struct{}, len(admins))
	for _, a := range admins {
		adminSet[a] = struct{}{}
	}
	combined := make([]string, 0, len(admins)+len(memberRefs))
	seen := make(map[string]struct{}, len(admins)+len(memberRefs))
	for _, u := range admins {
		if _, ok := seen[u]; !ok {
			combined = append(combined, u)
			seen[u] = struct{}{}
		}
	}
	for _, u := range memberRefs {
		if _, ok := seen[u]; !ok {
			combined = append(combined, u)
			seen[u] = struct{}{}
		}
	}
	sort.Strings(combined)

	out := &tenantv1.ListTeamMembersResponse{}
	end := offset + int(pageSize)
	if end > len(combined) {
		end = len(combined)
	}
	for i := offset; i < end; i++ {
		userRef := combined[i]
		userID := stripFGATypePrefix(userRef, "user")
		_, isAdmin := adminSet[userRef]
		m := &tenantv1.TeamMember{
			UserId:  userID,
			IsAdmin: isAdmin,
		}
		// Enrich display_name/email from the IdP, mirroring ListMembers — the
		// roster must show who the member is, not a raw Zitadel sub. Best-
		// effort: on failure/empty the dashboard falls back to the user id.
		if s.idpClient != nil {
			profile, profileErr := s.idpClient.GetUserProfile(ctx, userID)
			switch {
			case profileErr != nil:
				reason := "profile_lookup_failed"
				switch {
				case errors.Is(profileErr, idp.ErrUnreachable):
					reason = "directory_unavailable"
				case errors.Is(profileErr, idp.ErrNotFound):
					reason = "profile_not_found"
				}
				s.logger.WarnContext(ctx, "ListTeamMembers: identity enrichment failed",
					slog.String("user_id", userID),
					slog.String("reason", reason),
					slog.String("error", profileErr.Error()))
			case profile.DisplayName == "" && profile.Email == "":
				s.logger.WarnContext(ctx, "ListTeamMembers: identity enrichment returned an empty profile",
					slog.String("user_id", userID),
					slog.String("reason", "empty_profile"))
			default:
				m.DisplayName = profile.DisplayName
				m.Email = profile.Email
			}
		}
		out.Members = append(out.Members, m)
	}
	if end < len(combined) {
		out.NextPageToken = encodeTeamCursor(end)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// CreateTeam (#396)
// ---------------------------------------------------------------------------

// CreateTeam writes the (tenant:X, parent, team:X/Y) FGA tuple that anchors the
// new team under the caller's tenant. The team_id must be provided by the
// caller; the daemon does not generate IDs.
//
// There is no claim to contend for and therefore nothing here to race. The
// object id is built from the caller's own tenant (teamRef, team_object_ref.go),
// which comes from the ext-authz context via requireCallerTenant and never from
// the wire, so two tenants that both ask for team id "ops" address
// `team:acme/ops` and `team:evil-co/ops` — different objects, each with exactly
// one possible parent. The previous shape claimed a globally shared id, so it
// needed a read ("does anyone else already parent this?") followed by a write,
// and a cluster-wide advisory lock to make the pair atomic; namespacing deletes
// the read, the lock and the shared id together.
//
// The Write stays idempotent: re-issuing CreateTeam for a team you already own
// is a no-op in FGA and a success here, matching the previous behaviour.
func (s *TenantAdminServer) CreateTeam(ctx context.Context, req *tenantv1.CreateTeamRequest) (*tenantv1.CreateTeamResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}

	tenantRef := tenantRefFromID(tenantID)
	teamObj, err := teamRef(tenantID, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	if err := s.authorizer.Write(ctx, []authz.Tuple{
		{User: tenantRef, Relation: "parent", Object: teamObj},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Write team parent: %v", err)
	}
	return &tenantv1.CreateTeamResponse{
		Team: &tenantv1.Team{
			Id:          req.GetTeamId(),
			DisplayName: req.GetDisplayName(),
			MemberCount: 0,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// DeleteTeam (#396)
// ---------------------------------------------------------------------------

// DeleteTeam removes the team from the caller's tenant. It first verifies the
// team belongs to the tenant, then deletes the parent tuple. Member and admin
// tuples on the team are left to garbage-collection; they become inaccessible
// once the parent relation is gone.
func (s *TenantAdminServer) DeleteTeam(ctx context.Context, req *tenantv1.DeleteTeamRequest) (*tenantv1.DeleteTeamResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	tenantRef := tenantRefFromID(tenantID)
	teamObj, err := teamRef(tenantID, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	// Cross-tenant denial: verify the team belongs to the caller's tenant.
	owned, err := s.authorizer.Check(ctx, tenantRef, "parent", teamObj)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant parent: %v", err)
	}
	if !owned {
		return nil, status.Error(codes.PermissionDenied, "team not in caller's tenant")
	}

	if err := s.authorizer.Delete(ctx, []authz.Tuple{
		{User: tenantRef, Relation: "parent", Object: teamObj},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Delete team parent: %v", err)
	}
	return &tenantv1.DeleteTeamResponse{}, nil
}

// ---------------------------------------------------------------------------
// AddTeamMember (#396)
// ---------------------------------------------------------------------------

// AddTeamMember writes a (user:X, member, team:Y) FGA tuple. Idempotent: if
// the tuple already exists, FGA returns success (the Write is a no-op).
func (s *TenantAdminServer) AddTeamMember(ctx context.Context, req *tenantv1.AddTeamMemberRequest) (*tenantv1.AddTeamMemberResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	tenantRef := tenantRefFromID(tenantID)
	teamObj, err := teamRef(tenantID, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	// Cross-tenant denial.
	owned, err := s.authorizer.Check(ctx, tenantRef, "parent", teamObj)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant parent: %v", err)
	}
	if !owned {
		return nil, status.Error(codes.PermissionDenied, "team not in caller's tenant")
	}

	userRef := "user:" + req.GetUserId()

	// Verify the target user actually belongs to the caller's tenant before
	// adding them to one of that tenant's teams. Without this check, any
	// caller with AddTeamMember access could add an arbitrary caller-supplied
	// user ID — one from a different tenant entirely, or simply a guessed ID
	// — to a team in their own tenant, handing that user whatever access the
	// team grants despite never having been a member of the tenant at all.
	// Spec: identity-assertion-gaps finding 4.
	isTenantMember, err := s.authorizer.Check(ctx, userRef, "member", tenantRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check user tenant membership: %v", err)
	}
	if !isTenantMember {
		return nil, status.Errorf(codes.PermissionDenied, "user is not a member of this tenant")
	}

	if err := s.authorizer.Write(ctx, []authz.Tuple{
		{User: userRef, Relation: "member", Object: teamObj},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Write member: %v", err)
	}
	return &tenantv1.AddTeamMemberResponse{}, nil
}

// ---------------------------------------------------------------------------
// RemoveTeamMember (#396)
// ---------------------------------------------------------------------------

// RemoveTeamMember deletes both the member and admin tuples for the user on
// the team. Removing only the member tuple while leaving the admin tuple would
// allow the admin relation (which implies member) to persist. Idempotent for
// each tuple: only tuples that exist are deleted.
func (s *TenantAdminServer) RemoveTeamMember(ctx context.Context, req *tenantv1.RemoveTeamMemberRequest) (*tenantv1.RemoveTeamMemberResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	tenantRef := tenantRefFromID(tenantID)
	teamObj, err := teamRef(tenantID, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	userRef := "user:" + req.GetUserId()

	// Cross-tenant denial.
	owned, err := s.authorizer.Check(ctx, tenantRef, "parent", teamObj)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant parent: %v", err)
	}
	if !owned {
		return nil, status.Error(codes.PermissionDenied, "team not in caller's tenant")
	}

	// Check which tuples exist before deleting — FGA errors on deleting
	// non-existent tuples.
	checks := []authz.CheckRequest{
		{User: userRef, Relation: "member", Object: teamObj},
		{User: userRef, Relation: "admin", Object: teamObj},
	}
	present, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga BatchCheck member/admin: %v", err)
	}

	var toDelete []authz.Tuple
	if present[0] {
		toDelete = append(toDelete, authz.Tuple{User: userRef, Relation: "member", Object: teamObj})
	}
	if present[1] {
		toDelete = append(toDelete, authz.Tuple{User: userRef, Relation: "admin", Object: teamObj})
	}
	if len(toDelete) > 0 {
		if err := s.authorizer.Delete(ctx, toDelete); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Delete member/admin: %v", err)
		}
	}
	return &tenantv1.RemoveTeamMemberResponse{}, nil
}

// ---------------------------------------------------------------------------
// SetTeamAdmin (#396)
// ---------------------------------------------------------------------------

// SetTeamAdmin promotes or demotes a team member's admin status.
//
// When is_admin is true: ensures both the member and admin tuples exist (the
// admin relation implies member in the FGA model, but writing both is the
// convention for clarity and correctness across model versions).
//
// When is_admin is false: removes only the admin tuple, leaving member intact.
// If the user held neither, this is a no-op.
func (s *TenantAdminServer) SetTeamAdmin(ctx context.Context, req *tenantv1.SetTeamAdminRequest) (*tenantv1.SetTeamAdminResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	tenantRef := tenantRefFromID(tenantID)
	teamObj, err := teamRef(tenantID, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	userRef := "user:" + req.GetUserId()

	// Cross-tenant denial.
	owned, err := s.authorizer.Check(ctx, tenantRef, "parent", teamObj)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant parent: %v", err)
	}
	if !owned {
		return nil, status.Error(codes.PermissionDenied, "team not in caller's tenant")
	}

	if req.GetIsAdmin() {
		// Promote: ensure both member and admin tuples exist.
		checks := []authz.CheckRequest{
			{User: userRef, Relation: "member", Object: teamObj},
			{User: userRef, Relation: "admin", Object: teamObj},
		}
		present, batchErr := s.authorizer.BatchCheck(ctx, checks)
		if batchErr != nil {
			return nil, status.Errorf(codes.Internal, "fga BatchCheck member/admin: %v", batchErr)
		}
		var toWrite []authz.Tuple
		if !present[0] {
			toWrite = append(toWrite, authz.Tuple{User: userRef, Relation: "member", Object: teamObj})
		}
		if !present[1] {
			toWrite = append(toWrite, authz.Tuple{User: userRef, Relation: "admin", Object: teamObj})
		}
		if len(toWrite) > 0 {
			if err := s.authorizer.Write(ctx, toWrite); err != nil {
				return nil, status.Errorf(codes.Internal, "fga Write member/admin: %v", err)
			}
		}
	} else {
		// Demote: remove only the admin tuple if it exists.
		adminPresent, checkErr := s.authorizer.Check(ctx, userRef, "admin", teamObj)
		if checkErr != nil {
			return nil, status.Errorf(codes.Internal, "fga Check admin: %v", checkErr)
		}
		if adminPresent {
			if err := s.authorizer.Delete(ctx, []authz.Tuple{
				{User: userRef, Relation: "admin", Object: teamObj},
			}); err != nil {
				return nil, status.Errorf(codes.Internal, "fga Delete admin: %v", err)
			}
		}
	}
	return &tenantv1.SetTeamAdminResponse{}, nil
}
