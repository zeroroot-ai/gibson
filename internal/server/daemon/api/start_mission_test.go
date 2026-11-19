// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/sdk/auth"
)

// scriptedQuota fails the check that the test names.
type scriptedQuota struct {
	MissionQuotaChecker
	missionErr, agentErr error
}

func (q scriptedQuota) CheckMissionQuota(context.Context) error { return q.missionErr }
func (q scriptedQuota) CheckAgentQuota(context.Context) error   { return q.agentErr }

// StartMission is the one function that starts a mission for a caller. It passes
// the whole request, with the target set, to the daemon.
func TestStartMission_PassesTheWholeRequestToTheDaemon(t *testing.T) {
	var got RunMissionData
	d := &mockDaemon{runMissionFn: func(_ context.Context, req RunMissionData) (string, error) {
		got = req
		return "m-1", nil
	}}
	srv := NewDaemonServer(d, nil, nil)
	req := RunMissionData{
		MissionDefinitionID: "def-1", TargetIDs: []string{"t1", "t2"}, Variables: map[string]string{"k": "v"},
		NameSuffix: " (a2a 1)", CreatedBy: principal.Principal{Kind: principal.Component, ID: "agent_principal:9"},
	}

	id, err := srv.StartMission(auth.WithTenant(context.Background(), auth.MustNewTenantID("acme")), req)

	require.NoError(t, err)
	assert.Equal(t, "m-1", id)
	assert.Equal(t, req, got)
}

// A failure of the daemon after admission keeps its gRPC status.
func TestStartMission_KeepsTheStatusOfAFailedStart(t *testing.T) {
	d := &mockDaemon{runMissionFn: func(context.Context, RunMissionData) (string, error) {
		return "", status.Error(codes.NotFound, "mission definition not found")
	}}
	_, err := NewDaemonServer(d, nil, nil).StartMission(context.Background(), RunMissionData{})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	d.runMissionFn = func(context.Context, RunMissionData) (string, error) { return "", errors.New("boom") }
	_, err = NewDaemonServer(d, nil, nil).StartMission(context.Background(), RunMissionData{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err), "an error with no status becomes Internal")
}

// A refusal of admission comes before the daemon starts anything.
func TestStartMission_RefusesBeforeTheDaemonStartsAnything(t *testing.T) {
	exhausted := status.Error(codes.ResourceExhausted, "quota used up")
	tests := []struct {
		name  string
		quota MissionQuotaChecker
		setup func(*DaemonServer, sqlmock.Sqlmock)
		code  codes.Code
	}{
		{name: "the mission quota is used up", quota: scriptedQuota{missionErr: exhausted}, code: codes.ResourceExhausted},
		{name: "the agent quota is used up", quota: scriptedQuota{agentErr: exhausted}, code: codes.ResourceExhausted},
		{name: "a quota check that fails with no status", quota: scriptedQuota{agentErr: errors.New("redis down")},
			code: codes.Internal},
		{
			name: "the tenant is suspended",
			setup: func(_ *DaemonServer, m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("acme").
					WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("suspended"))
			},
			code: codes.FailedPrecondition,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started := false
			d := &mockDaemon{runMissionFn: func(context.Context, RunMissionData) (string, error) {
				started = true
				return "m-1", nil
			}}
			srv, mock := mockedConnectionServer(t)
			srv.daemon = d
			srv.quotaManager = tt.quota
			if tt.setup != nil {
				tt.setup(srv, mock)
			}
			ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

			_, err := srv.StartMission(ctx, RunMissionData{MissionDefinitionID: "def-1", TargetIDs: []string{"t1"}})

			require.Error(t, err)
			wantCode(t, tt.name, err, tt.code)
			assert.False(t, started, "the daemon started a mission after the refusal")
		})
	}
}
