// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: the bank exit test (ADR-0019, gibson#1718).
//
// In plain words: a bank of two members comes up on a real key, both report
// idle, one job opens and reaches a member, the job closes with a verdict, a
// stranger tenant cannot read it, and the bank scales to zero.
//
// It asserts states, ids and counts, never model text. It needs:
//
//   - GIBSON_TEST_FIXTURES_ENABLED=true (the production-safety gate)
//   - DAEMON_GRPC_ADDR (the test-mode daemon, authz off)
//   - EXIT_TEST_ANTHROPIC_API_KEY (a real key; the test skips without it and
//     says so, because only a human can set the repository secret)
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	bankTenant         = "bank-e2e-tenant"
	bankStrangerTenant = "bank-e2e-stranger"
	bankProviderName   = "exit-anthropic"
	bankMembersReady   = 5 * time.Minute
	bankTurnDeadline   = 8 * time.Minute
	bankScaleDown      = 5 * time.Minute
)

// TestBank is the whole proof, in the order the issue names it.
func TestBank(t *testing.T) {
	checkTestFixturesEnabled(t)
	key := os.Getenv("EXIT_TEST_ANTHROPIC_API_KEY")
	if key == "" {
		t.Skip("EXIT_TEST_ANTHROPIC_API_KEY is not set: the bank exit test needs a real key, which only a human can add as a repository secret (gibson#1718). Nothing was tested.")
	}

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	providers := tenantv1.NewProviderServiceClient(clients.Conn())
	banks := bankpb.NewBankServiceClient(clients.Conn())
	jobs := jobpb.NewJobServiceClient(clients.Conn())
	ctx := auth.ContextWithTenantString(context.Background(), bankTenant)
	stranger := auth.ContextWithTenantString(context.Background(), bankStrangerTenant)

	t.Run("the key goes into the tenant's provider configuration through the RPC", func(t *testing.T) {
		_, err := providers.CreateProvider(ctx, &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
			Name: bankProviderName, Type: "anthropic", SetAsDefault: true,
			Credentials: map[string]string{"api_key": key},
		}})
		if status.Code(err) == codes.AlreadyExists {
			err = nil
		}
		require.NoError(t, err, "CreateProvider(%s)", bankProviderName)
	})

	var bankID string
	t.Run("a bank of two comes up and both members report idle", func(t *testing.T) {
		created, err := banks.CreateBank(ctx, &bankpb.CreateBankRequest{
			Name: "exit-bank", TenantOwned: true, DesiredCount: 2,
			LoginShape: bankpb.LoginShape_LOGIN_SHAPE_ANTHROPIC_API_KEY, ProviderConfigName: bankProviderName,
			AgentName: "claude", MaxJobsInFlight: 1,
		})
		require.NoError(t, err, "CreateBank")
		bankID = created.GetBank().GetId()
		require.NotEmpty(t, bankID)
		members := waitForMembers(t, ctx, banks, bankID, 2, bankpb.MemberState_MEMBER_STATE_IDLE, bankMembersReady)
		for _, m := range members {
			require.NotEmpty(t, m.GetSandboxId(), "member %s must run in a sandbox", m.GetId())
		}
	})
	t.Cleanup(func() {
		if bankID == "" {
			return
		}
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = banks.DeleteBank(auth.ContextWithTenantString(c, bankTenant), &bankpb.DeleteBankRequest{Id: bankID})
	})

	var jobID string
	t.Run("one job opens, reaches a member, and closes with a verdict", func(t *testing.T) {
		opened, err := jobs.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: bankID, Spec: &jobpb.JobSpec{
			Goal: "Reply with the single word DONE and stop.",
		}})
		require.NoError(t, err, "OpenJob")
		jobID = opened.GetJob().GetId()
		require.NotEmpty(t, jobID)

		// The member claims it and reports working, then waiting when the
		// turn ends. The states are the proof; the words are not.
		j := waitForJobState(t, ctx, jobs, jobID, bankTurnDeadline,
			jobpb.JobState_JOB_STATE_WORKING, jobpb.JobState_JOB_STATE_WAITING)
		require.NotEmpty(t, j.GetMemberId(), "a working job names its member")
		j = waitForJobState(t, ctx, jobs, jobID, bankTurnDeadline, jobpb.JobState_JOB_STATE_WAITING)
		require.NotEmpty(t, j.GetClaudeSessionId(), "a turn that ended names the Claude session that holds it")

		closed, err := jobs.CloseJob(ctx, &jobpb.CloseJobRequest{JobId: jobID, Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 1})
		require.NoError(t, err, "CloseJob")
		require.Equal(t, jobpb.JobState_JOB_STATE_CLOSED, closed.GetJob().GetState())
		require.Equal(t, jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, closed.GetJob().GetVerdict())

		waitForMembers(t, ctx, banks, bankID, 2, bankpb.MemberState_MEMBER_STATE_IDLE, bankMembersReady)
	})

	t.Run("a stranger tenant cannot read the job or the bank", func(t *testing.T) {
		_, err := jobs.GetJob(stranger, &jobpb.GetJobRequest{JobId: jobID})
		require.Equal(t, codes.NotFound, status.Code(err), "a job the tenant does not own must be NOT_FOUND, not a leak")
		_, err = banks.GetBank(stranger, &bankpb.GetBankRequest{Id: bankID})
		require.Equal(t, codes.NotFound, status.Code(err), "a bank the tenant does not own must be NOT_FOUND")
	})

	t.Run("scale to zero, and the sandboxes go", func(t *testing.T) {
		zero := int32(0)
		_, err := banks.UpdateBank(ctx, &bankpb.UpdateBankRequest{Id: bankID, DesiredCount: &zero})
		require.NoError(t, err, "UpdateBank(desired_count=0)")
		waitForMembers(t, ctx, banks, bankID, 0, bankpb.MemberState_MEMBER_STATE_UNSPECIFIED, bankScaleDown)
	})
}

// waitForMembers polls ListMembers until the bank has exactly want members
// and every one reports the state (unspecified means any state).
func waitForMembers(t *testing.T, ctx context.Context, banks bankpb.BankServiceClient, bankID string, want int, state bankpb.MemberState, deadline time.Duration) []*bankpb.Member {
	t.Helper()
	end := time.Now().Add(deadline)
	var last []*bankpb.Member
	for time.Now().Before(end) {
		resp, err := banks.ListMembers(ctx, &bankpb.ListMembersRequest{BankId: bankID})
		require.NoError(t, err, "ListMembers")
		last = resp.GetMembers()
		ok := len(last) == want
		for _, m := range last {
			if state != bankpb.MemberState_MEMBER_STATE_UNSPECIFIED && m.GetStatus().GetState() != state {
				ok = false
			}
		}
		if ok {
			return last
		}
		time.Sleep(5 * time.Second)
	}
	states := make([]string, 0, len(last))
	for _, m := range last {
		states = append(states, m.GetId()+"="+m.GetStatus().GetState().String())
	}
	t.Fatalf("bank %s: wanted %d members in %s within %s, have %v", bankID, want, state, deadline, states)
	return nil
}

// waitForJobState polls GetJob until the job is in one of the states.
func waitForJobState(t *testing.T, ctx context.Context, jobs jobpb.JobServiceClient, jobID string, deadline time.Duration, states ...jobpb.JobState) *jobpb.Job {
	t.Helper()
	end := time.Now().Add(deadline)
	var last *jobpb.Job
	for time.Now().Before(end) {
		resp, err := jobs.GetJob(ctx, &jobpb.GetJobRequest{JobId: jobID})
		require.NoError(t, err, "GetJob")
		last = resp.GetJob()
		for _, s := range states {
			if last.GetState() == s {
				return last
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("job %s: wanted one of %v within %s, is %s", jobID, states, deadline, last.GetState())
	return nil
}
