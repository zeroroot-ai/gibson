// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"k8s.io/client-go/rest"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

const connectorServiceName = "gibson.tenant.v1.ConnectorService"

// A pre-set connectorKube is returned by connectorKubeClient without an
// API-server round trip, and registerConnector serves ConnectorService over it.
// This is the hermetic path the daemon takes once the client is built (the
// cluster-config path needs a real cluster and is exercised only in bringup).
func TestRegisterConnector_ServesOverInjectedClient(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		connectorKube: fakeConnectorKube(t),
		authorizer:    wiringAuthorizer{},
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
	d := &daemonImpl{logger: testObservabilityLogger(), connectorKube: fakeConnectorKube(t)}
	srv := grpc.NewServer()

	d.registerConnector(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[connectorServiceName]; ok {
		t.Fatal("ConnectorService must not be registered without an authorizer")
	}
}

// connectorKubeClient caches the client on the daemon: a pre-set one is returned
// as-is, with no error and no cluster lookup.
func TestConnectorKubeClient_ReturnsCachedClient(t *testing.T) {
	want := fakeConnectorKube(t)
	d := &daemonImpl{logger: testObservabilityLogger(), connectorKube: want}

	got, err := d.connectorKubeClient()
	if err != nil {
		t.Fatalf("connectorKubeClient: %v", err)
	}
	if got != want {
		t.Fatal("connectorKubeClient must return the cached client")
	}
}

// TestNewConnectorKubeClient builds the narrow ConnectorService client over a
// dummy rest.Config. The client is lazy, so no API server is contacted; the
// scheme must recognize the ConnectorInstance API.
func TestNewConnectorKubeClient(t *testing.T) {
	kube, err := newConnectorKubeClient(&rest.Config{Host: "https://127.0.0.1:6443"})
	if err != nil {
		t.Fatalf("newConnectorKubeClient: %v", err)
	}
	if kube == nil {
		t.Fatal("client must not be nil")
	}
	if !kube.Scheme().Recognizes(connectorv1alpha1.SchemeGroupVersion.WithKind("ConnectorInstance")) {
		t.Error("client scheme must recognize ConnectorInstance")
	}
}

// The lister adapter returns the tenant's ConnectorInstance names only, and a
// daemon without a kube client yields a nil lister (ListConnectors then fails
// closed in the discovery server).
func TestConnectorInstanceLister(t *testing.T) {
	kube := fakeConnectorKube(t)
	seed := func(name, ns string) {
		ci := &connectorv1alpha1.ConnectorInstance{}
		ci.Name = name
		ci.Namespace = ns
		if err := kube.Create(context.Background(), ci); err != nil {
			t.Fatalf("seed %s/%s: %v", ns, name, err)
		}
	}
	seed("gitlab", "tenant-acme")
	seed("osv", "tenant-acme")
	seed("gitlab", "tenant-other")

	l := &connectorInstanceLister{kube: kube}
	ids, err := l.ListEnabledConnectors(context.Background(), "acme")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want the two acme connectors", ids)
	}

	d := &daemonImpl{logger: testObservabilityLogger(), connectorKube: kube}
	if d.connectorLister(context.Background()) == nil {
		t.Fatal("daemon with a kube client must return a lister")
	}
}
