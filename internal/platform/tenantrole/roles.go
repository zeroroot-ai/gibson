// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tenantrole holds the one list of tenant roles (ADR-0093 decision
// 2) and, in later files, the one function that copies a person's Zitadel
// role grant into its FGA copy (ADR-0093 decision 3).
package tenantrole

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
