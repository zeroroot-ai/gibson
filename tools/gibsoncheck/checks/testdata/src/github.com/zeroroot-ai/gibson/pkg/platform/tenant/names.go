// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tenant is an analyzer-fixture stub of the real
// pkg/platform/tenant package: just the one method the tenantrolewrite
// guard recognizes as a tenant-object constructor.
package tenant

// Names mirrors the real per-tenant name helper.
type Names struct {
	Slug string
}

// FGAObject mirrors the real method: it returns the tenant's FGA object.
func (n Names) FGAObject() string {
	return "tenant:" + n.Slug
}
