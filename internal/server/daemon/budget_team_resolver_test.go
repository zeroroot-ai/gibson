// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// budgetResolverAuthorizer answers ListObjects with a canned team list and
// errors on everything else — the resolver must not reach any other method.
type budgetResolverAuthorizer struct {
	authz.Authorizer
	objects []string
	err     error
}

func (a *budgetResolverAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	if a.err != nil {
		return nil, a.err
	}
	if relation != "member" || objectType != "team" || !strings.HasPrefix(user, "user:") {
		return nil, errors.New("budget resolver asked the wrong question: " + user + "/" + relation + "/" + objectType)
	}
	return a.objects, nil
}

// TestBudgetTeamResolver_StripsTheTenantNamespace pins the mapping from
// tenant-namespaced FGA team object ids back to the bare ids budget keys use.
//
// Budget keys are `budget:tenant:<tenant>:team:<id>`, already tenant-scoped, so
// returning the raw `team:<tenant>/<id>` object would key
// `…:team:acme/eng` and silently miss the budget an admin configured for `eng`.
// Budgets do not fail loudly when they miss; they just stop enforcing.
func TestBudgetTeamResolver_StripsTheTenantNamespace(t *testing.T) {
	resolve := newBudgetTeamResolver(&budgetResolverAuthorizer{
		objects: []string{"team:acme/eng", "team:acme/ops"},
	}, nil)

	got, err := resolve(context.Background(), "acme", "alice")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if strings.Join(got, ",") != "eng,ops" {
		t.Errorf("resolver returned %v, want the bare ids [eng ops]", got)
	}
}

// TestBudgetTeamResolver_DropsForeignAndLegacyObjects is the cross-tenant half:
// a team object outside the caller's namespace must not be charged to this
// tenant's budget, and a legacy un-namespaced object belongs to nobody.
func TestBudgetTeamResolver_DropsForeignAndLegacyObjects(t *testing.T) {
	resolve := newBudgetTeamResolver(&budgetResolverAuthorizer{
		objects: []string{"team:acme/eng", "team:other-co/eng", "team:legacy", "team:acme-corp/eng"},
	}, nil)

	got, err := resolve(context.Background(), "acme", "alice")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(got) != 1 || got[0] != "eng" {
		t.Errorf("resolver returned %v, want only the caller's own [eng]", got)
	}
}

// TestBudgetTeamResolver_DegradesOnLookupFailure keeps the pre-existing
// contract: a lookup failure falls back to tenant+user scopes rather than
// failing the LLM call.
func TestBudgetTeamResolver_DegradesOnLookupFailure(t *testing.T) {
	resolve := newBudgetTeamResolver(&budgetResolverAuthorizer{err: errors.New("fga down")}, nil)

	got, err := resolve(context.Background(), "acme", "alice")
	if err != nil || got != nil {
		t.Errorf("resolver = %v, %v; want nil, nil so the enforcer degrades to tenant+user scopes", got, err)
	}
}

// TestBudgetTeamResolver_RequiresBothIdentifiers pins the guard that keeps an
// empty tenant from producing the prefix "team:/" and matching nothing useful.
func TestBudgetTeamResolver_RequiresBothIdentifiers(t *testing.T) {
	resolve := newBudgetTeamResolver(&budgetResolverAuthorizer{objects: []string{"team:acme/eng"}}, nil)

	for _, tc := range []struct{ name, tenant, user string }{
		{"no tenant", "", "alice"},
		{"no user", "acme", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolve(context.Background(), tc.tenant, tc.user)
			if err != nil || got != nil {
				t.Errorf("resolver = %v, %v; want nil, nil", got, err)
			}
		})
	}
}
