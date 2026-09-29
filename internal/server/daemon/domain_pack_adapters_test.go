// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

const domainPackServiceName = "gibson.tenant.v1.DomainPackService"

// registerDomainPack requires both a brain registry and an authorizer
// (ADR-0033, gibson#381), the same "don't register without a required
// dependency" pattern registerConnector follows (ADR-0067).
func TestRegisterDomainPack_ServesWithRegistryAndAuthorizer(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background()),
		authorizer:    wiringAuthorizer{},
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[domainPackServiceName]; !ok {
		t.Fatal("DomainPackService must be registered when a brain registry and authorizer are present")
	}
}

// A nil domainPackCatalog must not block registration: registerDomainPack
// lazily constructs an empty one (mirrors the daemon's own newInfrastructure
// wiring), so a daemon that reaches this point before that field is set
// still serves the (empty) catalog rather than skipping registration.
func TestRegisterDomainPack_ConstructsCatalogWhenNil(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background()),
		authorizer:    wiringAuthorizer{},
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if d.domainPackCatalog == nil {
		t.Fatal("registerDomainPack must construct a catalog when none is wired")
	}
	if _, ok := srv.GetServiceInfo()[domainPackServiceName]; !ok {
		t.Fatal("DomainPackService must still be registered")
	}
}

// An already-wired catalog (the normal newInfrastructure path) is reused,
// not replaced.
func TestRegisterDomainPack_ReusesWiredCatalog(t *testing.T) {
	want := ontology.NewDomainPackCatalog(ontology.DomainPack{Name: "main", Version: 1})
	d := &daemonImpl{
		logger:            testObservabilityLogger(),
		brainRegistry:     brain.NewRegistry(context.Background()),
		authorizer:        wiringAuthorizer{},
		domainPackCatalog: want,
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if d.domainPackCatalog != want {
		t.Fatal("registerDomainPack must reuse the already-wired catalog, not replace it")
	}
}

func TestRegisterDomainPack_SkipsWithoutAuthorizer(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background()),
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[domainPackServiceName]; ok {
		t.Fatal("DomainPackService must not be registered without an authorizer")
	}
}

func TestRegisterDomainPack_SkipsWithoutBrainRegistry(t *testing.T) {
	d := &daemonImpl{
		logger:     testObservabilityLogger(),
		authorizer: wiringAuthorizer{},
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[domainPackServiceName]; ok {
		t.Fatal("DomainPackService must not be registered without a brain registry")
	}
}
