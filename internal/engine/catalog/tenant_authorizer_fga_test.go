// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package catalog

import (
	"context"
	"errors"
	"testing"
)

// tupleChecker answers a Check from a set of "user|relation|object" keys.
type tupleChecker struct {
	allow map[string]bool
	err   error
	seen  []string
}

func (c *tupleChecker) Check(_ context.Context, user, relation, object string) (bool, error) {
	key := user + "|" + relation + "|" + object
	c.seen = append(c.seen, key)
	if c.err != nil {
		return false, c.err
	}
	return c.allow[key], nil
}

// The tenant asks tenant_can_execute with itself as the subject, and the
// answer is the answer of the model. Another tenant that holds the grant gives
// this tenant nothing, because the subject names the asking tenant only.
func TestTenantAuthorizer_AsksTheTenantNotTheUserset(t *testing.T) {
	const object = "component:connector/github"
	fga := &tupleChecker{allow: map[string]bool{
		"tenant:acme|tenant_can_execute|" + object: true,
		"tenant:beta|tenant_can_execute|" + object: true,
	}}
	a := NewTenantAuthorizer(fga, NewFGAAuthorizer(fga))
	caller := Caller{Subject: TenantSetSubject("acme"), Tenant: "acme"}

	ok, err := a.CanExecute(context.Background(), caller, mustMCP(t, "github", "list"))
	if err != nil || !ok {
		t.Fatalf("CanExecute = (%v, %v), want (true, nil)", ok, err)
	}
	if len(fga.seen) != 1 || fga.seen[0] != "tenant:acme|tenant_can_execute|"+object {
		t.Fatalf("checks = %v, want the one tenant check", fga.seen)
	}

	// A tenant with no grant is refused, whatever another tenant holds.
	other := Caller{Subject: TenantSetSubject("gamma"), Tenant: "gamma"}
	if ok, err := a.CanExecute(context.Background(), other, mustMCP(t, "github", "list")); err != nil || ok {
		t.Fatalf("CanExecute(gamma) = (%v, %v), want (false, nil)", ok, err)
	}
}

// A caller that is not the tenant set of its own tenant gets an error and no
// check. This covers a person, an agent, a subject of another tenant and a
// tenant name that would build another reference.
func TestTenantAuthorizer_RefusesACallerThatIsNotTheTenantSet(t *testing.T) {
	cases := map[string]Caller{
		"a person":                  {Subject: "user:alice", Tenant: "acme"},
		"an agent":                  {Subject: "agent_principal:a1", Tenant: "acme"},
		"the set of another tenant": {Subject: TenantSetSubject("beta"), Tenant: "acme"},
		"no tenant":                 {Subject: TenantSetSubject(""), Tenant: ""},
		"a separator":               {Subject: TenantSetSubject("a#b"), Tenant: "a#b"},
	}
	for name, caller := range cases {
		t.Run(name, func(t *testing.T) {
			fga := &tupleChecker{allow: map[string]bool{}}
			ok, err := NewTenantAuthorizer(fga, NewFGAAuthorizer(fga)).CanExecute(context.Background(), caller, mustMCP(t, "github", "list"))
			if ok || err == nil {
				t.Fatalf("CanExecute = (%v, %v), want (false, error)", ok, err)
			}
			if len(fga.seen) != 0 {
				t.Fatalf("checks = %v, want none", fga.seen)
			}
		})
	}
}

// An error of the check is no answer. The call fails closed with the error.
func TestTenantAuthorizer_FailsClosedOnACheckError(t *testing.T) {
	boom := errors.New("fga down")
	fga := &tupleChecker{err: boom}
	ok, err := NewTenantAuthorizer(fga, NewFGAAuthorizer(fga)).CanExecute(context.Background(),
		Caller{Subject: TenantSetSubject("acme"), Tenant: "acme"}, mustMCP(t, "github", "list"))
	if ok || !errors.Is(err, boom) {
		t.Fatalf("CanExecute = (%v, %v), want (false, fga down)", ok, err)
	}
}

// A source other than a connector tool goes to the base authorizer.
func TestTenantAuthorizer_DelegatesANativeToolToTheBase(t *testing.T) {
	fga := &tupleChecker{allow: map[string]bool{"user:alice|can_execute|component:tool/nmap": true}}
	a := NewTenantAuthorizer(fga, NewFGAAuthorizer(fga))
	ok, err := a.CanExecute(context.Background(), Caller{Subject: "user:alice", Tenant: "acme"}, mustNative(t, "nmap"))
	if err != nil || !ok {
		t.Fatalf("CanExecute = (%v, %v), want (true, nil)", ok, err)
	}
}
