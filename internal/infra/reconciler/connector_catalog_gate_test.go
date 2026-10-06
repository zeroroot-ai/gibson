// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

// connector_catalog_gate_test.go — the ADR-0067 platform catalog gate seeder,
// and the CatalogFanout exclusion that keeps connectors out of the
// tenant_enabled fan-out.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

func TestSeedComponentCatalogGate_WritesMissingOnly(t *testing.T) {
	a := &recordingAuthorizer{
		listObjects: map[listObjectsKey][]string{
			{User: "system_tenant:_system", Relation: "platform_enabled", ObjectType: "component"}: {
				"component:connector/hosted-fixture",
			},
		},
	}
	err := SeedComponentCatalogGate(context.Background(), a,
		[]CatalogRef{{Kind: "connector", ID: "hosted-fixture"}, {Kind: "connector", ID: "gitlab"}}, slog.Default())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(a.writes) != 1 {
		t.Fatalf("wrote %d tuples, want 1 (only the missing entry): %+v", len(a.writes), a.writes)
	}
	want := authz.Tuple{
		User:     "system_tenant:_system",
		Relation: "platform_enabled",
		Object:   "component:connector/gitlab",
	}
	if a.writes[0] != want {
		t.Fatalf("tuple = %+v, want %+v", a.writes[0], want)
	}
}

func TestSeedComponentCatalogGate_ConvergedIsNoop(t *testing.T) {
	a := &recordingAuthorizer{
		listObjects: map[listObjectsKey][]string{
			{User: "system_tenant:_system", Relation: "platform_enabled", ObjectType: "component"}: {
				// Unprefixed results are tolerated, matching CatalogFanout.
				"connector/hosted-fixture",
			},
		},
	}
	if err := SeedComponentCatalogGate(context.Background(), a, []CatalogRef{{Kind: "connector", ID: "hosted-fixture"}}, slog.Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(a.writes) != 0 {
		t.Fatalf("converged seed must write nothing, wrote: %+v", a.writes)
	}
}

// failingAuthorizer wraps recordingAuthorizer to fail ListObjects or Write.
type failingAuthorizer struct {
	recordingAuthorizer
	listErr   error
	writeErr  error
	deleteErr error
}

func (a *failingAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	if a.listErr != nil {
		return nil, a.listErr
	}
	return a.recordingAuthorizer.ListObjects(ctx, user, relation, objectType)
}

func (a *failingAuthorizer) Write(ctx context.Context, tuples []authz.Tuple) error {
	if a.writeErr != nil {
		return a.writeErr
	}
	return a.recordingAuthorizer.Write(ctx, tuples)
}

func (a *failingAuthorizer) Delete(ctx context.Context, tuples []authz.Tuple) error {
	if a.deleteErr != nil {
		return a.deleteErr
	}
	return a.recordingAuthorizer.Delete(ctx, tuples)
}

func TestSeedComponentCatalogGate_ErrorsPropagate(t *testing.T) {
	boom := context.DeadlineExceeded
	if err := SeedComponentCatalogGate(context.Background(),
		&failingAuthorizer{listErr: boom}, []CatalogRef{{Kind: "connector", ID: "hosted-fixture"}}, slog.Default()); err == nil {
		t.Fatal("list error must propagate")
	}
	if err := SeedComponentCatalogGate(context.Background(),
		&failingAuthorizer{writeErr: boom}, []CatalogRef{{Kind: "connector", ID: "hosted-fixture"}}, slog.Default()); err == nil {
		t.Fatal("write error must propagate")
	}
	if err := SeedComponentCatalogGate(context.Background(),
		&failingAuthorizer{}, nil, slog.Default()); err != nil {
		t.Fatalf("empty catalog must be a no-op: %v", err)
	}
}

// A cluster that has the platform_enabled tuple of a component that left the
// catalog loses it at the next seed (gibson#750). A component of a kind that
// another seeder owns, and a listed component, keep their tuples.
func TestPruneComponentCatalogGate_DeletesRetiredOnly(t *testing.T) {
	a := &recordingAuthorizer{
		listObjects: map[listObjectsKey][]string{
			{User: "system_tenant:_system", Relation: "platform_enabled", ObjectType: "component"}: {
				"component:connector/osv",
				"component:connector/gitlab",
				"tool/retired-tool",
				"component:domainpack/web",
			},
		},
	}
	listed := []CatalogRef{{Kind: "connector", ID: "gitlab"}}
	if err := PruneComponentCatalogGate(context.Background(), a,
		[]string{"connector", "tool"}, listed, slog.Default()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	want := []authz.Tuple{
		{User: "system_tenant:_system", Relation: "platform_enabled", Object: "component:connector/osv"},
		{User: "system_tenant:_system", Relation: "platform_enabled", Object: "component:tool/retired-tool"},
	}
	if len(a.deletes) != len(want) || a.deletes[0] != want[0] || a.deletes[1] != want[1] {
		t.Fatalf("deleted %+v, want %+v", a.deletes, want)
	}
	if len(a.writes) != 0 {
		t.Fatalf("prune wrote %+v", a.writes)
	}
}

func TestPruneComponentCatalogGate_ConvergedAndErrors(t *testing.T) {
	a := &recordingAuthorizer{
		listObjects: map[listObjectsKey][]string{
			{User: "system_tenant:_system", Relation: "platform_enabled", ObjectType: "component"}: {"component:connector/gitlab"},
		},
	}
	listed := []CatalogRef{{Kind: "connector", ID: "gitlab"}}
	if err := PruneComponentCatalogGate(context.Background(), a, []string{"connector"}, listed, slog.Default()); err != nil || len(a.deletes) != 0 {
		t.Fatalf("converged prune: err %v, deleted %+v", err, a.deletes)
	}
	if err := PruneComponentCatalogGate(context.Background(), a, nil, listed, slog.Default()); err != nil {
		t.Fatalf("no kinds must be a no-op: %v", err)
	}
	if err := PruneComponentCatalogGate(context.Background(),
		&failingAuthorizer{listErr: context.DeadlineExceeded}, []string{"connector"}, listed, slog.Default()); err == nil {
		t.Fatal("list error must propagate")
	}
	del := &failingAuthorizer{deleteErr: context.DeadlineExceeded}
	del.listObjects = map[listObjectsKey][]string{
		{User: "system_tenant:_system", Relation: "platform_enabled", ObjectType: "component"}: {"component:connector/osv"},
	}
	if err := PruneComponentCatalogGate(context.Background(), del, []string{"connector"}, listed, slog.Default()); err == nil {
		t.Fatal("delete error must propagate")
	}
}
