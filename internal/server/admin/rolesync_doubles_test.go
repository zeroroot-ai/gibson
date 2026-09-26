// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

// rolesync_doubles_test.go: shared test doubles for tests that exercise
// SetTenantRole, TransferOwnership and AcceptInvitation now that they write
// through a *tenantrole.Syncer (ADR-0093) instead of the authorizer
// directly. fakeGrants is the Zitadel side; the FGA side reuses whatever
// authz.Authorizer the test already builds (it must implement
// authz.TupleReader and authz.AtomicWriter for tenantrole.AuthzTuples to
// accept it — ownershipAuthorizer in tenant_admin_ownership_test.go does).

import (
	"context"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

type fakeGrant struct {
	id, userID, userOrgID, orgID string
	roleKeys                     []string
	active                       bool
}

// fakeGrants is an in-memory tenantrole.Grants. Every grant it creates has
// UserOrgID == orgID (one tenant per person, ADR-0093 decision 1) unless a
// test mutates it directly through seed.
type fakeGrants struct {
	mu     sync.Mutex
	grants map[string]*fakeGrant
	nextID int

	listErr, createErr, updateErr, deleteErr error
}

func newFakeGrants() *fakeGrants {
	return &fakeGrants{grants: map[string]*fakeGrant{}}
}

// seed installs a grant directly, for a test that needs to start from a
// specific Zitadel state rather than letting Assign/Create build it.
func (g *fakeGrants) seed(orgID, userID string, r tenantrole.Role) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nextID++
	id := fmt.Sprintf("grant-%d", g.nextID)
	g.grants[id] = &fakeGrant{id: id, userID: userID, userOrgID: orgID, orgID: orgID, roleKeys: []string{string(r)}, active: true}
}

func (g *fakeGrants) List(_ context.Context, orgID string, userIDs []string) ([]tenantrole.Grant, error) {
	if g.listErr != nil {
		return nil, g.listErr
	}
	var want map[string]bool
	if len(userIDs) > 0 {
		want = map[string]bool{}
		for _, id := range userIDs {
			want[id] = true
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []tenantrole.Grant
	for _, gr := range g.grants {
		if gr.orgID != orgID {
			continue
		}
		if want != nil && !want[gr.userID] {
			continue
		}
		out = append(out, tenantrole.Grant{
			ID: gr.id, UserID: gr.userID, UserOrgID: gr.userOrgID, OrgID: gr.orgID,
			RoleKeys: append([]string(nil), gr.roleKeys...), Active: gr.active,
		})
	}
	return out, nil
}

func (g *fakeGrants) Create(_ context.Context, orgID, userID string, r tenantrole.Role) (string, error) {
	if g.createErr != nil {
		return "", g.createErr
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nextID++
	id := fmt.Sprintf("grant-%d", g.nextID)
	g.grants[id] = &fakeGrant{id: id, userID: userID, userOrgID: orgID, orgID: orgID, roleKeys: []string{string(r)}, active: true}
	return id, nil
}

func (g *fakeGrants) Update(_ context.Context, grantID string, r tenantrole.Role) error {
	if g.updateErr != nil {
		return g.updateErr
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.grants[grantID]
	if !ok {
		return tenantrole.ErrNotFound
	}
	gr.roleKeys = []string{string(r)}
	return nil
}

func (g *fakeGrants) Delete(_ context.Context, grantID string) error {
	if g.deleteErr != nil {
		return g.deleteErr
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.grants, grantID)
	return nil
}
