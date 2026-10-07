// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package zitadel is an analyzer-fixture stub of the real
// operators/platform/internal/clients/zitadel package. It carries only what
// the orgmemberwrite guard resolves types against: the Client interface's
// org-member methods.
package zitadel

import "context"

// Client mirrors the real Zitadel Management API interface, trimmed to the
// two methods the orgmemberwrite guard matches by qualified name.
type Client interface {
	AddOrgMember(ctx context.Context, orgID, userID string, roles []string) error
	RemoveOrgMember(ctx context.Context, orgID, userID string) error
}
