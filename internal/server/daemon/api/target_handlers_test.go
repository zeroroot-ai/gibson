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

func TestFromProtoTarget_NilIsNil(t *testing.T) {
	require.Nil(t, fromProtoTarget(nil))
}
