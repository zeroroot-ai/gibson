// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

const domainPackServiceName = "gibson.tenant.v1.DomainPackService"

// registerDomainPack requires both a brain registry and an authorizer
// (ADR-0133, gibson#381), the same "don't register without a required
// dependency" pattern registerConnector follows (ADR-0067).
func TestRegisterDomainPack_ServesWithRegistryAndAuthorizer(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background(), braintest.StoreFactory()),
		authorizer:    wiringAuthorizer{},
		platformDB:    testPlatformDB(t),
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[domainPackServiceName]; !ok {
		t.Fatal("DomainPackService must be registered when a brain registry and authorizer are present")
	}
}

// A nil domainPackCatalog must not block registration: registerDomainPack
// lazily constructs one seeded with the platform's skeleton "main" pack
// (mirrors the daemon's own newInfrastructure wiring, gibson#382), so a
// daemon that reaches this point before that field is set still serves the
// seeded catalog rather than skipping registration.
func TestRegisterDomainPack_ConstructsCatalogWhenNil(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background(), braintest.StoreFactory()),
		authorizer:    wiringAuthorizer{},
		platformDB:    testPlatformDB(t),
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if d.domainPackCatalog == nil {
		t.Fatal("registerDomainPack must construct a catalog when none is wired")
	}
	if _, ok := d.domainPackCatalog.Get(ontology.MainDomainPackName); !ok {
		t.Fatal("the lazily-constructed catalog must carry the seed \"main\" pack")
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
		brainRegistry:     brain.NewRegistry(context.Background(), braintest.StoreFactory()),
		authorizer:        wiringAuthorizer{},
		platformDB:        testPlatformDB(t),
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
		brainRegistry: brain.NewRegistry(context.Background(), braintest.StoreFactory()),
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
		platformDB: testPlatformDB(t),
	}
	srv := grpc.NewServer()

	d.registerDomainPack(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[domainPackServiceName]; ok {
		t.Fatal("DomainPackService must not be registered without a brain registry")
	}
}

// testPlatformDB returns a database handle for a wiring test. The wiring
// opens no query, so a mock with no expectation is enough. In production
// platformDB is never nil after Start (gibson#246).
func testPlatformDB(t *testing.T) *sql.DB {
	t.Helper()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestRegisterDomainPack_RegistersTheComplianceService: the compliance
// reader is served next to the Domain Pack service (gibson#674).
func TestRegisterDomainPack_RegistersTheComplianceService(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background(), braintest.StoreFactory()),
		authorizer:    wiringAuthorizer{},
		platformDB:    testPlatformDB(t),
	}
	srv := grpc.NewServer()
	d.registerDomainPack(context.Background(), srv)
	if _, ok := srv.GetServiceInfo()["gibson.tenant.v1.ComplianceService"]; !ok {
		t.Fatal("ComplianceService must be registered with the Domain Pack service")
	}
}
