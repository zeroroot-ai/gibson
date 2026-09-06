// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// componentCatalogGateState carries what the startup catalog seed found to
// /readyz, so "the platform offers no component" is a state an operator can
// read rather than one log line at startup (gibson#1744).
type componentCatalogGateState struct {
	mu             sync.Mutex
	refusal        error
	credentialPath string
}

// newComponentCatalogGateState records which credential file the verifier was
// told to read. The path is what the readiness message names when no
// credential is mounted, so an operator is told the fix, not the symptom.
func newComponentCatalogGateState(credentialPath string) *componentCatalogGateState {
	return &componentCatalogGateState{credentialPath: credentialPath}
}

// recordRefusal stores the seed's error. A nil error means every catalog image
// verified.
func (s *componentCatalogGateState) recordRefusal(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusal = err
}

// status reports the seed outcome.
//
// Degraded is reserved for the case an operator can act on and the platform
// should be taken out of service for: a credential IS mounted and the registry
// still refused, which means the token is wrong or the images are not signed.
// With no credential mounted the answer is Healthy with the missing mount
// named: every install that pulls anonymously today would otherwise leave
// service the moment this check shipped, and a rollout that removes every
// daemon is not a better report than a wrong one.
func (s *componentCatalogGateState) status() sdktypes.HealthStatus {
	s.mu.Lock()
	refusal, path := s.refusal, s.credentialPath
	s.mu.Unlock()

	if refusal == nil {
		return sdktypes.NewHealthyStatus("component catalog: every catalog image verified")
	}
	if supplychain.DockerConfigPresent(path) {
		return sdktypes.NewDegradedStatus(
			"component catalog: the registry credential at "+path+
				" did not let every catalog image verify, so those components are not offered: "+refusal.Error(),
			nil,
		)
	}
	return sdktypes.NewHealthyStatus(
		"component catalog: no registry credential is mounted at " + path +
			", so an image on a private registry cannot verify and its component is not offered: " + refusal.Error())
}

// registerComponentCatalogReadiness publishes the seed outcome on /readyz.
// The health server is built before Start reaches the catalog seed, so this
// takes it as given, exactly like every other readiness registration here.
func (d *daemonImpl) registerComponentCatalogReadiness(ctx context.Context, state *componentCatalogGateState) {
	d.healthServer.RegisterReadinessCheck("component_catalog_gate", func(context.Context) sdktypes.HealthStatus {
		return state.status()
	})
	d.logger.Debug(ctx, "registered component catalog gate readiness check")
}
