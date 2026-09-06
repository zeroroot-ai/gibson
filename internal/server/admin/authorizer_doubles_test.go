// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
)

// errListUsersOfTypeNotStubbed is what a test double answers when a test
// reaches ListUsersOfType without having been set up for it.
//
// It is an error and not an empty slice on purpose. ListUsersOfType backs
// CreateTeam's "is this team id already claimed by another tenant?" gate, and
// that gate reads an empty answer as "not claimed, go ahead". A double that
// silently answers "nobody" would make the gate pass in every test that did
// not deliberately arrange for it — which is how the bug this replaces was
// able to ship.
var errListUsersOfTypeNotStubbed = errors.New("ListUsersOfType not stubbed on this test double")

// ListUsersOfType is a security gate in this package; a double that is
// not set up for it must fail the gate loudly rather than answer "nobody".
func (m *membersAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}
