// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: the belief training exit test (ADR-0106, gibson#616).
//
// In plain words: a tenant gets something to learn from, its nightly trainer
// runs once, and the next mission of the tenant pins the new belief version.
//
// exit-test-belief-training.yml runs the two tests below in order, with the
// trainer Job between them:
//
//  1. TestBeliefTraining_Seed runs one nmap mission for the tenant and labels
//     an item of its review queue, so the World holds a training row.
//  2. The workflow starts a Job from the belief-trainer CronJob of the tenant
//     and waits for it to complete.
//  3. TestBeliefTraining_NextMissionPins runs one more mission and asserts
//     that the World records a stored version of the tenant on it
//     (tenant-<id>-v<n>), not the embedded default. The daemon pins a stored
//     version only when tenant_belief_artifacts holds a current row.
//
// It needs GIBSON_TEST_FIXTURES_ENABLED=true and DAEMON_GRPC_ADDR, like the
// other in-cluster suites.
package e2e

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	"github.com/zeroroot-ai/sdk/auth"
)

// beliefTenant is the tenant that the baseline profile provisions.
const beliefTenant = "primary"

// storedBeliefVersion is the form of a version that the store wrote.
var storedBeliefVersion = regexp.MustCompile(`^tenant-` + beliefTenant + `-v[0-9]+$`)

// runBeliefMission enables nmap, runs one nmap mission to a terminal state
// and returns its definition id.
func runBeliefMission(t *testing.T, ctx context.Context, clients *helpers.GRPCClientSet, name string) string {
	t.Helper()
	membership := tenantv1.NewMembershipServiceClient(clients.Conn())
	_, err := membership.SetCatalogEnabled(ctx, &tenantv1.SetCatalogEnabledRequest{ComponentRef: toolComponentRef, Enabled: true})
	require.NoError(t, err, "enable %s for %s", toolComponentRef, beliefTenant)

	targetID, err := helpers.RegisterTestTarget(ctx, clients.Daemon, toolTargetName, toolTargetURL)
	require.NoError(t, err, "register the synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(auth.ContextWithTenantString(c, beliefTenant), clients.Daemon, targetID)
	})

	defID := createToolMissionDefinition(t, ctx, clients.Daemon, name, toolName)
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	events, err := helpers.Subscribe(runCtx, clients.Daemon, defID, targetID)
	require.NoError(t, err, "run the %s mission", name)
	terminal, collected, err := helpers.WaitForTerminal(runCtx, events, 8*time.Minute)
	require.NoError(t, err, "the %s mission must reach a terminal state", name)
	require.Equal(t, "mission_completed", terminal.EventType,
		"the %s mission must complete; reason: %s", name, failureReason(terminal, collected))
	return defID
}

// TestBeliefTraining_Seed gives the tenant a training row: a mission, then a
// label on an item of the review queue.
func TestBeliefTraining_Seed(t *testing.T) {
	checkTestFixturesEnabled(t)
	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), beliefTenant)

	runBeliefMission(t, ctx, clients, "belief-training-seed")

	world := worldpb.NewWorldServiceClient(clients.Conn())
	var queue *worldpb.ListReviewQueueResponse
	deadline := time.Now().Add(2 * time.Minute)
	for {
		queue, err = world.ListReviewQueue(ctx, &worldpb.ListReviewQueueRequest{})
		require.NoError(t, err, "ListReviewQueue")
		if len(queue.GetItems()) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	require.NotEmpty(t, queue.GetItems(), "the mission left nothing in the review queue to label")
	item := queue.GetItems()[0]
	_, err = world.SubmitLabel(ctx, &worldpb.SubmitLabelRequest{
		TargetId: item.GetTargetId(), Verdict: "true_positive", IdempotencyKey: "belief-training-seed-" + item.GetTargetId(),
	})
	require.NoError(t, err, "label %s %s", item.GetKind(), item.GetTargetId())
	t.Logf("labelled %s %s as a true positive", item.GetKind(), item.GetTargetId())
}

// TestBeliefTraining_NextMissionPins runs after the trainer Job: the next
// mission of the tenant pins a stored version.
func TestBeliefTraining_NextMissionPins(t *testing.T) {
	checkTestFixturesEnabled(t)
	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), beliefTenant)

	before := map[string]bool{}
	world := worldpb.NewWorldServiceClient(clients.Conn())
	list, err := world.ListMissions(ctx, &worldpb.ListMissionsRequest{})
	require.NoError(t, err, "ListMissions")
	for _, m := range list.GetMissions() {
		before[m.GetId()] = true
	}

	runBeliefMission(t, ctx, clients, "belief-training-pin")

	list, err = world.ListMissions(ctx, &worldpb.ListMissionsRequest{})
	require.NoError(t, err, "ListMissions")
	var pinned []string
	for _, m := range list.GetMissions() {
		if !before[m.GetId()] {
			pinned = append(pinned, m.GetBeliefModel())
		}
	}
	require.NotEmpty(t, pinned, "the new mission is not in the World")
	for _, v := range pinned {
		require.Regexp(t, storedBeliefVersion, v,
			"the next mission pinned %q, want a stored version of the tenant: the trainer stored nothing current", v)
	}
	t.Logf("the next mission pinned %v", pinned)
}
