// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// produced_component_test.go covers EnrollProducedComponent (gibson#33): an
// agent enrolls a component that it produced, under the policy of the
// 2026-08-02 grill.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

const (
	testProducer = "agent_principal:sa-producer"
	testOwner    = "user-owner"
	testImage    = "ghcr.io/acme/scanner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// memProducedStore is an in-memory producedComponentStore.
type memProducedStore struct {
	mu       sync.Mutex
	rows     map[string]string // tenant|kind|name -> principal
	reserved int
	err      error
}

func newMemProducedStore() *memProducedStore { return &memProducedStore{rows: map[string]string{}} }

func (m *memProducedStore) Reserve(_ context.Context, tenantID, _, _ string, c ProducedComponent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	key := tenantID + "|" + c.Kind + "|" + c.Name
	if _, ok := m.rows[key]; ok {
		return errProducedExists
	}
	m.rows[key] = ""
	m.reserved++
	return nil
}

func (m *memProducedStore) Bind(_ context.Context, tenantID, kind, name, principalID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[tenantID+"|"+kind+"|"+name] = principalID
	return nil
}

func (m *memProducedStore) Release(_ context.Context, tenantID, kind, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID + "|" + kind + "|" + name
	if m.rows[key] == "" {
		delete(m.rows, key)
	}
	return nil
}

func producedServer(t *testing.T) (*DaemonServer, *fakeAuthorizer, *memProducedStore, *fakeAuditWriter, *fakeIDPClient) {
	t.Helper()
	az := newFakeAuthorizer().
		allow("tenant:acme", "belongs_to", testProducer).
		withUsers("agent_principal", testProducer, "owner", "user:"+testOwner)
	store := newMemProducedStore()
	aud := &fakeAuditWriter{}
	idpc := &fakeIDPClient{}
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(idpc).
		WithAuthorizer(az).
		WithTenantAdminAuditWriter(aud)
	srv.producedComponents = store
	return srv, az, store, aud, idpc
}

func tool(name string) ProducedComponent {
	return ProducedComponent{Kind: "tool", Name: name, Version: "0.1.0", Image: testImage}
}

// enrollmentTuples reports which of the three tuples of an enrollment of
// port-sniffer in acme the writes hold: the owner, the tenant, and the
// tenant enablement.
func enrollmentTuples(tuples []authz.Tuple, principal string) (owner, belongs, enabled bool) {
	for _, tu := range tuples {
		switch {
		case tu.Relation == "owner" && tu.Object == principal && tu.User == "user:"+testOwner:
			owner = true
		case tu.Relation == "belongs_to" && tu.Object == principal && tu.User == "tenant:acme":
			belongs = true
		case tu.Relation == "tenant_enabled" && tu.User == "tenant:acme" && strings.Contains(tu.Object, "port-sniffer"):
			enabled = true
		}
	}
	return owner, belongs, enabled
}

func TestEnrollProducedComponent_EnrollsAnUntrustedComponentOwnedByTheProducerOwner(t *testing.T) {
	srv, az, store, aud, _ := producedServer(t)

	got, err := srv.EnrollProducedComponent(context.Background(), "acme", testProducer, tool("port-sniffer"))
	if err != nil {
		t.Fatalf("EnrollProducedComponent: %v", err)
	}
	if got.BootstrapToken == "" || !strings.HasPrefix(got.PrincipalID, "tool_principal:") {
		t.Fatalf("got %+v, want a tool principal and a token", got)
	}
	if got.ExpiresAt.IsZero() {
		t.Error("the token must state its end")
	}
	owner, belongs, enabled := enrollmentTuples(az.writtenTuples(), got.PrincipalID)
	if !owner || !belongs || !enabled {
		t.Errorf("tuples: owner=%v belongs_to=%v tenant_enabled=%v, want all", owner, belongs, enabled)
	}
	events := aud.recorded()
	if len(events) != 1 || events[0].Action != "component.enrolled_by_agent" || events[0].ActorID != testProducer {
		t.Errorf("audit = %+v, want one component.enrolled_by_agent by the producer", events)
	}
	if store.rows["acme|tool|port-sniffer"] != got.PrincipalID {
		t.Errorf("the record does not name the new principal: %+v", store.rows)
	}
}

// No count refuses an enrollment: a tenant enrolls more components than the
// old cap of 25.
func TestEnrollProducedComponent_NoCountLimit(t *testing.T) {
	srv, _, store, _, idpc := producedServer(t)
	for i := range 30 {
		if _, err := srv.EnrollProducedComponent(context.Background(), "acme", testProducer, tool(fmt.Sprintf("tool-%02d", i))); err != nil {
			t.Fatalf("enrollment %d: %v", i, err)
		}
	}
	if idpc.createCalls != 30 || store.reserved != 30 {
		t.Errorf("creates = %d, reserved = %d, want 30 of each", idpc.createCalls, store.reserved)
	}
}

func TestEnrollProducedComponent_ARecordErrorFailsClosed(t *testing.T) {
	srv, _, store, _, _ := producedServer(t)
	store.err = errors.New("db down")
	_, err := srv.EnrollProducedComponent(context.Background(), "acme", testProducer, tool("a-tool"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable when the record cannot be written, got %v", err)
	}
}

func TestEnrollProducedComponent_NoStoreFailsClosed(t *testing.T) {
	srv, _, _, _, _ := producedServer(t)
	srv.producedComponents = nil
	_, err := srv.EnrollProducedComponent(context.Background(), "acme", testProducer, tool("a-tool"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable with no record store, got %v", err)
	}
}

func TestEnrollProducedComponent_CrossTenantIsRefused(t *testing.T) {
	srv, _, _, _, idpc := producedServer(t)
	// The producer belongs to acme, not to beta.
	_, err := srv.EnrollProducedComponent(context.Background(), "beta", testProducer, tool("a-tool"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for a producer of another tenant, got %v", err)
	}
	if idpc.createCalls != 0 {
		t.Error("a refused enrollment must create no account")
	}
}

func TestEnrollProducedComponent_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		producer string
		c        ProducedComponent
		want     codes.Code
	}{
		"a tool as the producer":   {"tool_principal:t-1", tool("a-tool"), codes.PermissionDenied},
		"a person as the producer": {"user-1", tool("a-tool"), codes.PermissionDenied},
		"an unknown kind":          {testProducer, ProducedComponent{Kind: "model", Name: "a-thing", Version: "1", Image: testImage}, codes.InvalidArgument},
		"a bad name":               {testProducer, tool("A"), codes.InvalidArgument},
		"no version":               {testProducer, ProducedComponent{Kind: "tool", Name: "a-tool", Image: testImage}, codes.InvalidArgument},
		"an image with no digest":  {testProducer, ProducedComponent{Kind: "tool", Name: "a-tool", Version: "1", Image: "ghcr.io/acme/scanner:latest"}, codes.InvalidArgument},
		"a catalog name":           {testProducer, tool("nmap"), codes.PermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _, _, _, idpc := producedServer(t)
			_, err := srv.EnrollProducedComponent(context.Background(), "acme", tc.producer, tc.c)
			if status.Code(err) != tc.want {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if idpc.createCalls != 0 {
				t.Error("a refused enrollment must create no account")
			}
		})
	}
}

func TestEnrollProducedComponent_AProducerWithNoOwnerIsRefused(t *testing.T) {
	srv, az, _, _, _ := producedServer(t)
	az.users = map[string][]string{}
	_, err := srv.EnrollProducedComponent(context.Background(), "acme", testProducer, tool("a-tool"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for a producer with no owner, got %v", err)
	}
}

func TestEnrollProducedComponent_AFailedProvisionReleasesTheReservation(t *testing.T) {
	srv, _, store, _, _ := producedServer(t)
	srv.cgMinter = nil // the mint fails, so the account rolls back
	_, err := srv.EnrollProducedComponent(context.Background(), "acme", testProducer, tool("a-tool"))
	if err == nil {
		t.Fatal("want an error when the token cannot be minted")
	}
	if len(store.rows) != 0 {
		t.Errorf("the reservation must be released, rows=%+v", store.rows)
	}
}

// The enrollment refuses a call with no tenant, with no authorizer, with an
// owner that cannot be read, and a name that a produced component holds.
func TestEnrollProducedComponent_MoreRefusals(t *testing.T) {
	ctx := context.Background()
	srv, az, _, _, _ := producedServer(t)
	if _, err := srv.EnrollProducedComponent(ctx, "", testProducer, tool("a-tool")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no tenant: %v", err)
	}
	az.listUsersErr = errors.New("fga down")
	if _, err := srv.EnrollProducedComponent(ctx, "acme", testProducer, tool("a-tool")); status.Code(err) != codes.Internal {
		t.Fatalf("an owner that cannot be read: %v", err)
	}
	az.listUsersErr = nil
	if _, err := srv.EnrollProducedComponent(ctx, "acme", testProducer, tool("a-tool")); err != nil {
		t.Fatalf("first enrollment: %v", err)
	}
	if _, err := srv.EnrollProducedComponent(ctx, "acme", testProducer, tool("a-tool")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a taken name: %v", err)
	}
	srv.authorizer = nil
	if _, err := srv.EnrollProducedComponent(ctx, "acme", testProducer, tool("b-tool")); status.Code(err) != codes.Unavailable {
		t.Fatalf("no authorizer: %v", err)
	}
}
