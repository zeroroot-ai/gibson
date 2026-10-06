// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
)

const connectorServiceName = "gibson.tenant.v1.ConnectorService"

// registerConnector serves ConnectorService over the platform database. It
// needs no Kubernetes client (gibson#662).
func TestRegisterConnector_ServesWithNoKubeClient(t *testing.T) {
	d := &daemonImpl{
		logger:     testObservabilityLogger(),
		authorizer: wiringAuthorizer{},
	}
	srv := grpc.NewServer()

	d.registerConnector(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[connectorServiceName]; !ok {
		t.Fatal("ConnectorService must be registered when a kube client is present")
	}
}

// The platform catalog gate needs the authorizer: without one the service is
// not registered (fail closed, ADR-0067), matching the missing-kube path.
func TestRegisterConnector_SkipsWithoutAuthorizer(t *testing.T) {
	d := &daemonImpl{logger: testObservabilityLogger()}
	srv := grpc.NewServer()

	d.registerConnector(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[connectorServiceName]; ok {
		t.Fatal("ConnectorService must not be registered without an authorizer")
	}
}

// fakeTenantConnectors is an in-memory tenant connector list.
type fakeTenantConnectors struct {
	rows []tenantconnector.Connector
	err  error
}

func (f *fakeTenantConnectors) List(_ context.Context, tenant string) ([]tenantconnector.Connector, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []tenantconnector.Connector
	for _, r := range f.rows {
		if r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out, nil
}

// The lister adapter returns the connector ids of one tenant from the store,
// and a store error fails the call.
func TestTenantConnectorLister(t *testing.T) {
	store := &fakeTenantConnectors{rows: []tenantconnector.Connector{
		{TenantID: "acme", ConnectorID: "gitlab"},
		{TenantID: "acme", ConnectorID: "slack"},
		{TenantID: "other", ConnectorID: "gitlab"},
	}}
	l := &tenantConnectorLister{store: store}
	ids, err := l.ListEnabledConnectors(context.Background(), "acme")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 2 || ids[0] != "gitlab" || ids[1] != "slack" {
		t.Fatalf("ids = %v, want the two acme connectors", ids)
	}

	store.err = errors.New("db down")
	if _, err := l.ListEnabledConnectors(context.Background(), "acme"); err == nil {
		t.Fatal("a store error must fail the list")
	}

	d := &daemonImpl{logger: testObservabilityLogger()}
	if d.connectorLister(context.Background()) == nil {
		t.Fatal("the daemon must return a lister")
	}
}
