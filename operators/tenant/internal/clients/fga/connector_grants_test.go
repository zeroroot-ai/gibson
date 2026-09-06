// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga_test

// connector_grants_test.go — unit tests for the connector component grant
// helpers (ADR-0067, gibson#1548). Independent stub from the plugin/secrets
// test stubs to avoid cross-file coupling, mirroring their pattern.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

type connectorStubFGAClient struct {
	written   []fga.Tuple
	deleted   []fga.Tuple
	writeErr  error
	deleteErr error
}

func (s *connectorStubFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}

func (s *connectorStubFGAClient) WriteConditional(_ context.Context, _ fga.ConditionalTuple) error {
	return nil
}

func (s *connectorStubFGAClient) Delete(_ context.Context, tuples []fga.Tuple) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, tuples...)
	return nil
}

func (s *connectorStubFGAClient) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) {
	return nil, nil
}

func (s *connectorStubFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

func (s *connectorStubFGAClient) Ping(_ context.Context) error { return nil }

func TestConnectorComponentTuples_Shape(t *testing.T) {
	tuples := fga.ConnectorComponentTuples("gitlab", "acme")
	if len(tuples) != 2 {
		t.Fatalf("tuple count = %d, want 2", len(tuples))
	}
	wantObject := "component:connector/gitlab"
	wantRelations := map[string]bool{"owner": false, "tenant_enabled": false}
	for _, tuple := range tuples {
		if tuple.User != "tenant:acme" {
			t.Errorf("user = %q, want %q (bare tenant ref — the model computes member grants from owner)",
				tuple.User, "tenant:acme")
		}
		if tuple.Object != wantObject {
			t.Errorf("object = %q, want %q", tuple.Object, wantObject)
		}
		seen, ok := wantRelations[tuple.Relation]
		if !ok {
			t.Errorf("unexpected relation %q", tuple.Relation)
		} else if seen {
			t.Errorf("relation %q appears twice", tuple.Relation)
		}
		wantRelations[tuple.Relation] = true
	}
	for rel, seen := range wantRelations {
		if !seen {
			t.Errorf("relation %q missing from the tuple set", rel)
		}
	}
}

func TestWriteConnectorComponentGrants_WritesBothTuples(t *testing.T) {
	stub := &connectorStubFGAClient{}
	if err := fga.WriteConnectorComponentGrants(context.Background(), stub, "gitlab", "acme"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(stub.written) != 2 {
		t.Fatalf("wrote %d tuples, want 2: %+v", len(stub.written), stub.written)
	}
}

func TestWriteConnectorComponentGrants_Idempotent_AlreadyExists(t *testing.T) {
	stub := &connectorStubFGAClient{
		writeErr: fmt.Errorf("fga 400: %w", clients.ErrAlreadyExists),
	}
	if err := fga.WriteConnectorComponentGrants(context.Background(), stub, "gitlab", "acme"); err != nil {
		t.Fatalf("already-exists must be idempotent success, got: %v", err)
	}
}

func TestWriteConnectorComponentGrants_PropagatesOtherErrors(t *testing.T) {
	stub := &connectorStubFGAClient{
		writeErr: fmt.Errorf("dial: %w", clients.ErrUnreachable),
	}
	err := fga.WriteConnectorComponentGrants(context.Background(), stub, "gitlab", "acme")
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Fatalf("error chain lost the sentinel: %v", err)
	}
}

func TestDeleteConnectorComponentGrants_DeletesBothTuples(t *testing.T) {
	stub := &connectorStubFGAClient{}
	if err := fga.DeleteConnectorComponentGrants(context.Background(), stub, "gitlab", "acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(stub.deleted) != 2 {
		t.Fatalf("deleted %d tuples, want 2: %+v", len(stub.deleted), stub.deleted)
	}
}

func TestDeleteConnectorComponentGrants_PropagatesErrors(t *testing.T) {
	stub := &connectorStubFGAClient{
		deleteErr: fmt.Errorf("dial: %w", clients.ErrUnreachable),
	}
	if err := fga.DeleteConnectorComponentGrants(context.Background(), stub, "gitlab", "acme"); err == nil {
		t.Fatal("want error, got nil")
	}
}

func TestLegacyConnectorInvokeTuple_ShapeAndDelete(t *testing.T) {
	got := fga.LegacyConnectorInvokeTuple("gitlab", "acme")
	want := fga.Tuple{User: "tenant:acme#member", Relation: "can_invoke", Object: "plugin:acme/gitlab"}
	if got != want {
		t.Fatalf("tuple = %+v, want %+v", got, want)
	}
	stub := &connectorStubFGAClient{}
	if err := fga.DeleteLegacyConnectorInvokeTuple(context.Background(), stub, "gitlab", "acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(stub.deleted) != 1 || stub.deleted[0] != want {
		t.Fatalf("deleted = %+v, want exactly the legacy tuple", stub.deleted)
	}
	failing := &connectorStubFGAClient{deleteErr: fmt.Errorf("dial: %w", clients.ErrUnreachable)}
	if err := fga.DeleteLegacyConnectorInvokeTuple(context.Background(), failing, "gitlab", "acme"); err == nil {
		t.Fatal("want error propagation")
	}
}
