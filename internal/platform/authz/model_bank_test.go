// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

package authz_test

import (
	"context"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/require"
)

// TestModel_BankAndJob exercises the bank and job types (ADR-0019,
// gibson#1708) against a real OpenFGA loaded from model.fga.
//
// The properties it pins are the ones the design turns on:
//   - a person owns their bank and manages it; another tenant member does not;
//   - a tenant-owned bank is managed by a tenant admin, not by every member;
//   - can_send is wider than can_manage, and every principal kind can hold it;
//   - a job inherits sending and reading from its bank, so the ordinary case
//     needs no per-job tuple;
//   - can_close is NOT implied by can_send, or a worker could close its own
//     job — the one rule the whole scorer design rests on.
func TestModel_BankAndJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	const (
		tenantA     = "tenant:acme"
		tenantB     = "tenant:other"
		userAlice   = "user:alice"
		userBob     = "user:bob"
		userAdmin   = "user:admin"
		userCarol   = "user:carol"
		agentNode   = "agent_principal:job-node"
		agentWorker = "agent_principal:member"
		bankAlice   = "bank:alice-bank"
		bankTenant  = "bank:tenant-bank"
		jobOne      = "job:job-1"
	)

	addTuples := func(c *fgaclient.OpenFgaClient, tuples ...fgaclient.ClientTupleKey) {
		t.Helper()
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: tuples}).Execute()
		require.NoError(t, err)
	}
	checkAllow := func(c *fgaclient.OpenFgaClient, user, relation, object string) bool {
		t.Helper()
		resp, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{
			User: user, Relation: relation, Object: object,
		}).Execute()
		require.NoError(t, err, "check %s %s %s", user, relation, object)
		return resp.GetAllowed()
	}
	newClient := func(t *testing.T) *fgaclient.OpenFgaClient {
		t.Helper()
		mgmt := newRawFGAClient(t, baseURL)
		storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
			Name: storeNameFor("bank", t),
		}).Execute()
		require.NoError(t, err)
		storeID := storeResp.GetId()
		modelID := loadModelFromDSL(t, ctx, baseURL, storeID)
		c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
			ApiUrl: baseURL, StoreId: storeID, AuthorizationModelId: modelID,
		})
		require.NoError(t, err)
		return c
	}
	// seed puts alice, bob and admin in acme, carol in another tenant, and
	// creates one person-owned bank and one tenant-owned bank.
	seed := func(c *fgaclient.OpenFgaClient) {
		t.Helper()
		addTuples(c,
			fgaclient.ClientTupleKey{User: userAdmin, Relation: "admin", Object: tenantA},
			fgaclient.ClientTupleKey{User: userAlice, Relation: "member", Object: tenantA},
			fgaclient.ClientTupleKey{User: userBob, Relation: "member", Object: tenantA},
			fgaclient.ClientTupleKey{User: userCarol, Relation: "member", Object: tenantB},
			fgaclient.ClientTupleKey{User: tenantA, Relation: "parent", Object: bankAlice},
			fgaclient.ClientTupleKey{User: userAlice, Relation: "owner", Object: bankAlice},
			fgaclient.ClientTupleKey{User: tenantA, Relation: "parent", Object: bankTenant},
			fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_owned", Object: bankTenant},
		)
	}

	t.Run("bank/the owner manages their own bank", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		require.True(t, checkAllow(c, userAlice, "owner", bankAlice), "the owner manages")
		require.True(t, checkAllow(c, userAlice, "can_send", bankAlice), "the owner sends")
		require.True(t, checkAllow(c, userAlice, "can_read", bankAlice), "the owner reads")
	})

	t.Run("bank/another tenant member does not manage a person's bank", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		require.False(t, checkAllow(c, userBob, "owner", bankAlice),
			"a bank is one person's; a tenant member does not get to change its size")
		require.False(t, checkAllow(c, userBob, "can_send", bankAlice),
			"sending is granted, never inherited from tenant membership")
	})

	t.Run("bank/a tenant admin manages a tenant-owned bank", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		require.True(t, checkAllow(c, userAdmin, "owner", bankTenant),
			"a tenant-owned bank runs on the tenant's credential, so a tenant admin manages it")
		require.False(t, checkAllow(c, userBob, "owner", bankTenant),
			"an ordinary member does not manage a tenant-owned bank")
		require.False(t, checkAllow(c, userAdmin, "owner", bankAlice),
			"a tenant admin does not manage a person's own bank")
	})

	t.Run("bank/can_send is granted to any principal kind", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		addTuples(c,
			fgaclient.ClientTupleKey{User: userBob, Relation: "can_send", Object: bankAlice},
			fgaclient.ClientTupleKey{User: agentNode, Relation: "can_send", Object: bankAlice},
			fgaclient.ClientTupleKey{User: "tenant:acme#member", Relation: "can_send", Object: bankTenant},
		)
		require.True(t, checkAllow(c, userBob, "can_send", bankAlice), "a granted person sends")
		require.True(t, checkAllow(c, agentNode, "can_send", bankAlice), "a granted agent sends")
		require.True(t, checkAllow(c, userBob, "can_send", bankTenant), "a tenant-wide grant reaches every member")
		require.False(t, checkAllow(c, userBob, "owner", bankAlice),
			"sending never implies managing")
		require.True(t, checkAllow(c, userBob, "can_read", bankAlice),
			"a caller that may send may see the bank it sends to")
	})

	t.Run("bank/another tenant is refused", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		require.False(t, checkAllow(c, userCarol, "can_read", bankAlice))
		require.False(t, checkAllow(c, userCarol, "can_send", bankAlice))
		require.False(t, checkAllow(c, userCarol, "owner", bankAlice))
	})

	t.Run("job/inherits sending and reading from its bank", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		addTuples(c,
			fgaclient.ClientTupleKey{User: bankAlice, Relation: "parent", Object: jobOne},
			fgaclient.ClientTupleKey{User: agentNode, Relation: "opened_by", Object: jobOne},
		)
		require.True(t, checkAllow(c, userAlice, "can_send", jobOne),
			"the bank owner sends to a job on their bank with no per-job tuple")
		require.True(t, checkAllow(c, userAlice, "can_read", jobOne))
		require.True(t, checkAllow(c, agentNode, "can_send", jobOne), "the opener sends")
		require.False(t, checkAllow(c, userBob, "can_send", jobOne),
			"a tenant member with no grant on the bank cannot send to its jobs")
	})

	t.Run("job/can_close is not implied by can_send", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		addTuples(c,
			fgaclient.ClientTupleKey{User: bankAlice, Relation: "parent", Object: jobOne},
			fgaclient.ClientTupleKey{User: agentNode, Relation: "opened_by", Object: jobOne},
			// The worker is given sending so it can ask a question. It must
			// not be able to close the job it is working on.
			fgaclient.ClientTupleKey{User: agentWorker, Relation: "can_send", Object: bankAlice},
		)
		require.True(t, checkAllow(c, agentWorker, "can_send", jobOne), "the worker may send")
		require.False(t, checkAllow(c, agentWorker, "can_close", jobOne),
			"the worker never closes its own job: a scorer does")
		require.True(t, checkAllow(c, userAlice, "can_close", jobOne),
			"the bank owner may close")
		require.True(t, checkAllow(c, agentNode, "can_close", jobOne),
			"the principal that opened the job may close it")
	})

	t.Run("job/a named scorer closes exactly its own job", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		const jobTwo = "job:job-2"
		addTuples(c,
			fgaclient.ClientTupleKey{User: bankAlice, Relation: "parent", Object: jobOne},
			fgaclient.ClientTupleKey{User: bankAlice, Relation: "parent", Object: jobTwo},
			fgaclient.ClientTupleKey{User: agentNode, Relation: "scorer", Object: jobOne},
		)
		require.True(t, checkAllow(c, agentNode, "can_close", jobOne),
			"a verifier granted scorer on this job closes it")
		require.False(t, checkAllow(c, agentNode, "can_close", jobTwo),
			"the scorer grant is per job, never per bank")
		require.True(t, checkAllow(c, agentNode, "can_read", jobOne),
			"a scorer reads the job it judges")
	})
}
