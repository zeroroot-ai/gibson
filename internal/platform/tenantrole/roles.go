// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tenantrole holds the one list of tenant roles (ADR-0093 decision
// 2) and, in later files, the one function that copies a person's Zitadel
// role grant into its FGA copy (ADR-0093 decision 3).
package tenantrole

import "strings"

// Role is a tenant role key on the gibson Zitadel project.
type Role string

// The four tenant roles. A tenant user holds at most one.
const (
	Owner  Role = "owner"
	Admin  Role = "admin"
	Editor Role = "editor"
	Viewer Role = "viewer"
)

// Def is one project role as Zitadel stores it: a role key plus the display
// name shown in the Zitadel console.
type Def struct {
	Key         Role
	DisplayName string
}

// All is the complete set of tenant roles, in order. The platform-operator
// creates exactly these on the gibson project, and the tenant-operator
// grants exactly these to each tenant org.
var All = []Def{
	{Owner, "Owner"},
	{Admin, "Admin"},
	{Editor, "Editor"},
	{Viewer, "Viewer"},
}

// Keys returns the role keys of All as plain strings, in the same order,
// for a Zitadel project-grant call that wants []string.
func Keys() []string {
	keys := make([]string, len(All))
	for i, d := range All {
		keys[i] = string(d.Key)
	}
	return keys
}

// Relation is the FGA relation on tenant:<id> that holds this role. Editor
// maps to the older "writer" relation name and Viewer to "member": both
// predate ADR-0093 and are kept so the FGA model and every existing Check
// call need no change.
func (r Role) Relation() string {
	switch r {
	case Owner:
		return "owner"
	case Admin:
		return "admin"
	case Editor:
		return "writer"
	case Viewer:
		return "member"
	}
	return ""
}

// Relations is the set of FGA relation names a tenant role ever occupies.
// The write guard (tools/gibsoncheck) imports this to recognize a role
// write on a tenant object.
var Relations = []string{"owner", "admin", "writer", "member"}

// Parse returns the Role for a Zitadel project role key. ok is false for
// any key outside the four declared in All.
func Parse(key string) (Role, bool) {
	for _, d := range All {
		if string(d.Key) == key {
			return d.Key, true
		}
	}
	return "", false
}

// FromRelation maps an FGA relation name back to the Role that writes it.
// The existing SetTenantRole API takes relation names (admin, writer,
// member), so this is the boundary that translates an incoming request
// into the tenant role vocabulary.
func FromRelation(rel string) (Role, bool) {
	for _, d := range All {
		if d.Key.Relation() == rel {
			return d.Key, true
		}
	}
	return "", false
}

// IsZitadelUserSubject reports whether subject is a "user:<id>" FGA
// reference that COULD be a Zitadel user grant — i.e. not obviously a
// SPIFFE-derived identity smuggled in under the "user" type.
//
// This is Sync's boundary against non-Zitadel `user:`-typed subjects such as
// the exit-test runner's SPIFFE-derived identity ("user:zeroroot.ai/platform/
// e2e-runner", gibson#14 fixtures): that subject is not backed by any
// Zitadel grant, so Sync must never read, write or delete a role tuple for
// it (owner decision D2, option b). Real Zitadel ids are decimal snowflakes
// and never contain "/"; every SPIFFE id does (it is a URI path), so "/" is
// the discriminator, not "must be all digits" — a stricter numeric check
// would also reject the human-readable ids ("user-1", "bob-id") that test
// fixtures across the daemon and the operators use for the very same "user"
// type, which are not Zitadel ids either but ARE meant to be synced.
//
// It exists here, not just as a filter inline in each Tuples adapter,
// because both the daemon's authz.Authorizer adapter and the
// tenant-operator's fga.Client adapter need the identical rule.
func IsZitadelUserSubject(subject string) bool {
	const prefix = "user:"
	if !strings.HasPrefix(subject, prefix) {
		return false
	}
	id := subject[len(prefix):]
	return id != "" && !strings.ContainsAny(id, "/")
}
