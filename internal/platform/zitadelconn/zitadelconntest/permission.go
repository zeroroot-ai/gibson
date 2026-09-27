// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest

import "net/http"

// Permission is a Zitadel permission string exactly as it appears in Zitadel
// v4.18.0's cmd/defaults.yaml RolePermissionMappings (e.g. "user.grant.write").
type Permission string

// Permissions this fake's handlers currently gate. Not every permission
// Zitadel defines — only the ones the endpoints in this package implement.
const (
	PermOrgMemberWrite    Permission = "org.member.write"
	PermOrgMemberDelete   Permission = "org.member.delete"
	PermProjectRoleRead   Permission = "project.role.read"
	PermProjectRoleWrite  Permission = "project.role.write"
	PermProjectGrantRead  Permission = "project.grant.read"
	PermProjectGrantWrite Permission = "project.grant.write"
	PermUserGrantRead     Permission = "user.grant.read"
	PermUserGrantWrite    Permission = "user.grant.write"
	PermUserGrantDelete   Permission = "user.grant.delete"
	// PermIAMMemberWrite stands in for the iam.* family IAM_OWNER alone
	// carries. Nothing in this package's endpoints requires it; it exists so
	// a test can prove that granting IAM_ORG_MANAGER — which does NOT carry
	// it — still refuses a call that would need it, the way a real Zitadel
	// refuses the daemon or the tenant-operator credential today.
	PermIAMMemberWrite Permission = "iam.member.write"
)

// BuiltinRolePermissions is a partial mirror of Zitadel v4.18.0's built-in
// RolePermissionMappings (cmd/defaults.yaml), restricted to the permissions
// this package's endpoints gate (see the Perm* constants above). It is not a
// complete copy of every permission each role actually carries — only enough
// for a test to grant a caller one of these role names and get the same
// accept/refuse behavior this package's handlers would show against the
// real permission, for the calls this fake implements.
//
// Sources (hosted#199/#200 permission research, verified against
// github.com/zitadel/zitadel tag v4.18.0, cmd/defaults.yaml):
//   - IAM_OWNER: every permission, including iam.*.
//   - IAM_ORG_MANAGER: org.*, user.*, user.grant.*, project.*, project.grant.*,
//     session.read/delete — but NOT iam.*.
//   - IAM_USER_MANAGER: user.*, user.grant.*, project.grant.read/write/delete,
//     org.member.read/delete — but NOT org.member.write.
//   - IAM_LOGIN_CLIENT: user.grant.read/write (no delete), org.member.read/write
//     (no delete), project.grant.read — no user.grant.delete, no
//     org.member.delete.
var BuiltinRolePermissions = map[string][]Permission{
	"IAM_OWNER": {
		PermOrgMemberWrite, PermOrgMemberDelete,
		PermProjectRoleRead, PermProjectRoleWrite,
		PermProjectGrantRead, PermProjectGrantWrite,
		PermUserGrantRead, PermUserGrantWrite, PermUserGrantDelete,
		PermIAMMemberWrite,
	},
	"IAM_ORG_MANAGER": {
		PermOrgMemberWrite, PermOrgMemberDelete,
		PermProjectRoleRead, PermProjectRoleWrite,
		PermProjectGrantRead, PermProjectGrantWrite,
		PermUserGrantRead, PermUserGrantWrite, PermUserGrantDelete,
	},
	"IAM_USER_MANAGER": {
		PermOrgMemberDelete, // read+delete, no write
		PermProjectRoleRead,
		PermProjectGrantRead, PermProjectGrantWrite,
		PermUserGrantRead, PermUserGrantWrite, PermUserGrantDelete,
	},
	"IAM_LOGIN_CLIENT": {
		PermOrgMemberWrite, // read+write, no delete
		PermProjectRoleRead,
		PermProjectGrantRead,
		PermUserGrantRead, PermUserGrantWrite, // no delete
	},
}

// GrantRoles restricts every subsequent request this Identity serves to the
// permissions the named built-in roles carry (per BuiltinRolePermissions).
// A call whose gated permission is not in that set is refused exactly the
// way real Zitadel refuses it (403 permission_denied for a v2 Connect
// endpoint, or the v1 Management 403 shape for the org-member endpoint).
//
// An Identity that never calls GrantRoles enforces nothing (every gated call
// succeeds), so every existing test that predates this permission gate
// keeps passing unchanged.
func (f *Identity) GrantRoles(roles ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	granted := make(map[Permission]bool)
	for _, role := range roles {
		for _, perm := range BuiltinRolePermissions[role] {
			granted[perm] = true
		}
	}
	f.grantedPermissions = granted
}

// requirePermission reports whether perm is granted, and if not, writes the
// matching Zitadel-shaped refusal to w. connectProtocol selects the error
// wire shape: true for a v2 Connect service (writeConnectError,
// "permission_denied"), false for the v1 Management API
// (writeManagementError, gRPC code 7 = PermissionDenied, HTTP 403).
//
// f.grantedPermissions == nil (GrantRoles never called) means unrestricted:
// every call is allowed, preserving every test written before this gate
// existed.
func (f *Identity) requirePermission(w http.ResponseWriter, perm Permission, connectProtocol bool) bool {
	f.mu.Lock()
	granted := f.grantedPermissions
	f.mu.Unlock()
	if granted == nil || granted[perm] {
		return true
	}
	if connectProtocol {
		writeConnectError(w, "permission_denied", "Errors.PermissionDenied", "AUTH-permd1")
	} else {
		writeManagementError(w, http.StatusForbidden, 7, "Errors.PermissionDenied", "AUTH-permd1")
	}
	return false
}
