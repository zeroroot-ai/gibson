// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
)

// downStore is a Timeline store that cannot load, so the hydrate of each
// tenant fails and the Registry returns a stopped engine.
type downStore struct{}

var errDownStore = errors.New("the store is down")

func (downStore) Append(context.Context, string, string, brain.Event) (string, error) {
	return "", errDownStore
}

func (downStore) LoadForReplay(context.Context, string, string) ([]brain.Event, error) {
	return nil, errDownStore
}

func (downStore) WriteSnapshot(context.Context, string, brain.WorldSnapshot) (string, error) {
	return "", errDownStore
}

func (downStore) LoadHistory(context.Context, string) ([]brain.Event, error) {
	return nil, errDownStore
}

func (downStore) LoadSnapshot(context.Context, string) (*brain.WorldSnapshot, error) {
	return nil, errDownStore
}

func (downStore) TrimTo(context.Context, string, string) error { return errDownStore }

func downRegistry(t *testing.T) *brain.Registry {
	t.Helper()
	reg := brain.NewRegistry(context.Background())
	reg.WithStoreFactory(func(context.Context, string) brain.TimelineStore { return downStore{} })
	return reg
}

// During a store outage a read returns Unavailable, not the empty World of
// the stopped engine (gibson#826).
func TestWorldRead_AStoppedEngineIsUnavailable(t *testing.T) {
	srv := NewWorldServer(downRegistry(t), slog.New(slog.DiscardHandler))
	_, err := srv.ListMissions(tenantCtx(t, "tenant-a"), &worldpb.ListMissionsRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
}

func TestListMissions_AStoppedEngineIsUnavailable(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger(), brainRegistry: downRegistry(t)}
	_, _, err := d.ListMissions(tenantCtx(t, "tenant-a"), false, "", "", 0, 0)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
}

// A live engine still serves.
func TestWorldRead_ALiveEngineServes(t *testing.T) {
	srv := NewWorldServer(brain.NewRegistry(context.Background()), slog.New(slog.DiscardHandler))
	if _, err := srv.ListMissions(tenantCtx(t, "tenant-a"), &worldpb.ListMissionsRequest{}); err != nil {
		t.Fatalf("ListMissions: %v", err)
	}
}
