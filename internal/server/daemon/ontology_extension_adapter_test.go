// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

const ontologyExtensionServiceName = "gibson.tenant.v1.OntologyExtensionService"

// TestRegisterOntologyExtension_ServesWithBrainRegistry proves
// OntologyExtensionService is wired into the real service-registration path
// (ADR-0133, gibson#392) — no flag, no parallel path (ADR-0027):
// a daemon with a brain registry registers the service.
func TestRegisterOntologyExtension_ServesWithBrainRegistry(t *testing.T) {
	d := &daemonImpl{
		logger:        testObservabilityLogger(),
		brainRegistry: brain.NewRegistry(context.Background(), braintest.StoreFactory()),
		platformDB:    testPlatformDB(t),
	}
	srv := grpc.NewServer()

	d.registerOntologyExtension(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[ontologyExtensionServiceName]; !ok {
		t.Fatal("OntologyExtensionService must be registered when a brain registry is present")
	}
}

// TestRegisterOntologyExtension_SkipsWithoutBrainRegistry mirrors
// TestRegisterDomainPack_SkipsWithoutBrainRegistry: never register a service
// backed by a nil registry.
func TestRegisterOntologyExtension_SkipsWithoutBrainRegistry(t *testing.T) {
	d := &daemonImpl{
		logger: testObservabilityLogger(),
	}
	srv := grpc.NewServer()

	d.registerOntologyExtension(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[ontologyExtensionServiceName]; ok {
		t.Fatal("OntologyExtensionService must not be registered without a brain registry")
	}
}
