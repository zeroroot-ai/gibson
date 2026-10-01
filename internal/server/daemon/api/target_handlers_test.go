// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	targetpb "github.com/zeroroot-ai/sdk/api/gen/gibson/target/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/target"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// emptyTargetStore behaves like the Redis target store for an unknown id: it
// returns an error that wraps types.ErrTargetNotFound.
type emptyTargetStore struct{}

func (emptyTargetStore) Create(context.Context, *types.Target) error { return nil }
func (emptyTargetStore) Get(_ context.Context, id types.ID) (*types.Target, error) {
	return nil, fmt.Errorf("%w: %s", types.ErrTargetNotFound, id)
}
func (emptyTargetStore) List(context.Context, *types.TargetFilter) ([]*types.Target, error) {
	return nil, nil
}
func (emptyTargetStore) Update(context.Context, *types.Target) error { return nil }
func (emptyTargetStore) Delete(context.Context, types.ID) error      { return nil }

func TestTargetRPCs_MissingTargetIsNotFound(t *testing.T) {
	srv := (&DaemonServer{}).WithTargetService(target.NewService(emptyTargetStore{}))
	ctx := auth.ContextWithTenantString(context.Background(), "tenant-a")
	id := types.NewID().String()

	cases := map[string]func() error{
		"GetTarget": func() error {
			_, err := srv.GetTarget(ctx, &daemonpb.GetTargetRequest{TargetId: id})
			return err
		},
		"UpdateTarget": func() error {
			_, err := srv.UpdateTarget(ctx, &daemonpb.UpdateTargetRequest{Target: &targetpb.Target{Id: id, Name: "x"}})
			return err
		},
		"DeleteTarget": func() error {
			_, err := srv.DeleteTarget(ctx, &daemonpb.DeleteTargetRequest{TargetId: id})
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			require.Equal(t, codes.NotFound, status_grpc.Code(err), "got: %v", err)
		})
	}
}

// TestProtoTarget_SecretNameSurvivesBothDirections is the gibson#485 fixture at
// the wire boundary, which is exactly where the old field lost the value: it was
// accepted only when it parsed as a UUID and dropped in silence otherwise, so a
// caller writing "goat-kubeconfig" had the name swallowed with no error.
func TestProtoTarget_SecretNameSurvivesBothDirections(t *testing.T) {
	in := &types.Target{
		ID:         types.NewID(),
		Name:       "kubernetes-goat",
		Type:       "custom",
		SecretName: "goat-kubeconfig",
		AuthType:   types.AuthTypeAPIKey,
		Status:     types.TargetStatusActive,
		Timeout:    30,
		URL:        "https://goat.internal:8080",
	}

	p, err := toProtoTarget(in)
	require.NoError(t, err)
	require.Equal(t, "goat-kubeconfig", p.GetSecretName(),
		"a secret name is not a UUID and must reach the wire as written")

	back := fromProtoTarget(p)
	require.NotNil(t, back)
	require.Equal(t, "goat-kubeconfig", back.SecretName)
	require.Equal(t, in.AuthType, back.AuthType,
		"auth_type states the shape of the secret, so it travels with the name")
}

// A target that needs no secret names none, in both directions.
func TestProtoTarget_NoSecretNameStaysEmpty(t *testing.T) {
	p, err := toProtoTarget(&types.Target{
		ID: types.NewID(), Name: "public", Type: "custom",
		Status: types.TargetStatusActive, Timeout: 30,
	})
	require.NoError(t, err)
	require.Empty(t, p.GetSecretName())
	require.Empty(t, fromProtoTarget(p).SecretName)
}

func TestFromProtoTarget_NilIsNil(t *testing.T) {
	require.Nil(t, fromProtoTarget(nil))
}
