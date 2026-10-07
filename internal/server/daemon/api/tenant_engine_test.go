// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

// failingTimelineStore cannot load, so the hydrate of each tenant fails and
// the Registry returns a stopped engine.
type failingTimelineStore struct{}

var errStoreDown = errors.New("the store is down")

func (failingTimelineStore) Append(context.Context, string, string, brain.Event) (string, error) {
	return "", errStoreDown
}

func (failingTimelineStore) LoadForReplay(context.Context, string, string) ([]brain.Event, error) {
	return nil, errStoreDown
}

func (failingTimelineStore) WriteSnapshot(context.Context, string, brain.WorldSnapshot) (string, error) {
	return "", errStoreDown
}

func (failingTimelineStore) LoadHistory(context.Context, string) ([]brain.Event, error) {
	return nil, errStoreDown
}

func (failingTimelineStore) LoadSnapshot(context.Context, string) (*brain.WorldSnapshot, error) {
	return nil, errStoreDown
}

func (failingTimelineStore) TrimTo(context.Context, string, string) error { return errStoreDown }

func stoppedRegistry() *brain.Registry {
	reg := brain.NewRegistry(context.Background(), func(context.Context, string) (brain.TimelineStore, error) { return failingTimelineStore{}, nil })
	return reg
}

// A handler that reads a stopped tenant World answers Unavailable (gibson#826).
func TestTenantEngine_AStoppedEngineIsUnavailable(t *testing.T) {
	reg := stoppedRegistry()
	if _, ok := TenantEngine(reg, "acme"); ok {
		t.Fatal("TenantEngine returned a stopped engine")
	}
	if _, ok := TenantEngine(brain.NewRegistry(context.Background(), braintest.StoreFactory()), "acme"); !ok {
		t.Fatal("TenantEngine refused a live engine")
	}
	if _, _, err := (&DomainPackService{registry: reg}).engine(tenantCtx("acme"), "ListDomainPacks"); status.Code(err) != codes.Unavailable {
		t.Errorf("DomainPackService: code %v, want Unavailable", status.Code(err))
	}
	if _, err := (&OntologyExtensionService{registry: reg}).engine(tenantCtx("acme"), "ListProposals"); status.Code(err) != codes.Unavailable {
		t.Errorf("OntologyExtensionService: code %v, want Unavailable", status.Code(err))
	}
}
