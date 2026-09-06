// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"errors"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// connectorInstance builds a ConnectorInstance CR in tenant namespace ns with
// the given connector name and auth kind, mirroring what
// ConnectorService.EnableConnector writes (Name == Spec.Connector).
func connectorInstance(ns, connector string, auth connectorv1alpha1.ConnectorAuthKind) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: connector, Namespace: ns},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: connector,
			Shape:     connectorv1alpha1.ConnectorShapeRemote,
			Auth:      auth,
		},
	}
}

// instanceLister builds a controller-runtime fake client seeded with the given
// ConnectorInstances — hermetic, no cluster, no Postgres.
func instanceLister(t *testing.T, objs ...ctrlclient.Object) ctrlclient.Client {
	t.Helper()
	scheme := apiruntime.NewScheme()
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("connector scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// An oauth connector carries a vendor token and a secret connector carries a
// customer-supplied static credential (ADR-0015); both are published by the
// materializer, so the source returns both as (tenant, connector) pairs. A
// none-auth connector has nothing to publish and is dropped.
func TestConnectorInstanceCatalogSource_ReturnsCredentialBearingConnectors(t *testing.T) {
	src := &ConnectorInstanceCatalogSource{
		Lister: instanceLister(t,
			connectorInstance("tenant-acme", "connector-gitlab", connectorv1alpha1.ConnectorAuthOAuth),
			connectorInstance("tenant-acme", "connector-pat", connectorv1alpha1.ConnectorAuthSecret),
			connectorInstance("tenant-globex", "connector-github", connectorv1alpha1.ConnectorAuthOAuth),
			connectorInstance("tenant-globex", "connector-public", connectorv1alpha1.ConnectorAuthNone),
		),
	}

	desired, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}

	got := desiredKeys(desired)
	sort.Strings(got)
	want := []string{"acme/connector-gitlab", "acme/connector-pat", "globex/connector-github"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// The tenant is recovered from the CR's namespace (tenant-<id>). A CR outside a
// tenant namespace is skipped, not fatal, so one stray object never starves the
// rest of the fleet.
func TestConnectorInstanceCatalogSource_SkipsNonTenantNamespace(t *testing.T) {
	src := &ConnectorInstanceCatalogSource{
		Lister: instanceLister(t,
			connectorInstance("tenant-acme", "connector-gitlab", connectorv1alpha1.ConnectorAuthOAuth),
			connectorInstance("kube-system", "connector-stray", connectorv1alpha1.ConnectorAuthOAuth),
		),
	}

	desired, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if got := desiredKeys(desired); len(got) != 1 || got[0] != "acme/connector-gitlab" {
		t.Fatalf("got %v, want [acme/connector-gitlab]", got)
	}
}

// An empty cluster yields no desired connectors and no error.
func TestConnectorInstanceCatalogSource_EmptyCluster(t *testing.T) {
	src := &ConnectorInstanceCatalogSource{Lister: instanceLister(t)}
	desired, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if len(desired) != 0 {
		t.Fatalf("got %v, want none", desiredKeys(desired))
	}
}

// A list failure fails the whole pass: the token reconciler must skip the tick
// and retry, never act on a partial set.
func TestConnectorInstanceCatalogSource_ListErrorFailsThePass(t *testing.T) {
	src := &ConnectorInstanceCatalogSource{Lister: erroringLister{}}
	_, err := src.DesiredConnectors(context.Background())
	if err == nil {
		t.Fatal("a list failure must surface as an error")
	}
}

type erroringLister struct{}

func (erroringLister) List(_ context.Context, _ ctrlclient.ObjectList, _ ...ctrlclient.ListOption) error {
	return errors.New("api server unreachable")
}

// A CR whose tenant namespace has no id (namespace == "tenant-") is a malformed
// tenant and is skipped, not fatal; a valid sibling still comes through.
func TestConnectorInstanceCatalogSource_SkipsMalformedTenantNamespace(t *testing.T) {
	src := &ConnectorInstanceCatalogSource{
		Lister: instanceLister(t,
			connectorInstance("tenant-", "connector-orphan", connectorv1alpha1.ConnectorAuthOAuth),
			connectorInstance("tenant-acme", "connector-gitlab", connectorv1alpha1.ConnectorAuthOAuth),
		),
	}

	desired, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if got := desiredKeys(desired); len(got) != 1 || got[0] != "acme/connector-gitlab" {
		t.Fatalf("got %v, want [acme/connector-gitlab]", got)
	}
}

// When Spec.Connector is empty the connector id falls back to the CR name
// (BuildConnectorInstance sets Name == Spec.Connector, so this pins the
// fallback for any hand-authored CR that omits the field).
func TestConnectorInstanceCatalogSource_FallsBackToCRName(t *testing.T) {
	ci := connectorInstance("tenant-acme", "connector-gitlab", connectorv1alpha1.ConnectorAuthOAuth)
	ci.Spec.Connector = "" // omit the field; Name stays "connector-gitlab"
	src := &ConnectorInstanceCatalogSource{Lister: instanceLister(t, ci)}

	desired, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if got := desiredKeys(desired); len(got) != 1 || got[0] != "acme/connector-gitlab" {
		t.Fatalf("got %v, want [acme/connector-gitlab] (name fallback)", got)
	}
}
