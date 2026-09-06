// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
)

// liveEventPublisher adapts the live-agents registry to the launcher's
// EventPublisher seam. The launcher describes a run with its own
// sandboxed.LiveInstance and never imports the registry (ADR-0016 S11); this
// adapter is the one place the two shapes meet.
type liveEventPublisher struct {
	registry *liveagents.Registry
}

// newLiveEventPublisher wraps a registry. A nil registry yields a nil
// publisher, which disables the live console in the launcher.
func newLiveEventPublisher(registry *liveagents.Registry) sandboxed.EventPublisher {
	if registry == nil {
		return nil
	}
	return liveEventPublisher{registry: registry}
}

// RegisterInstance implements sandboxed.EventPublisher.
func (p liveEventPublisher) RegisterInstance(tenant string, inst sandboxed.LiveInstance) (publish func([]byte), finish func()) {
	return p.registry.RegisterInstance(tenant, liveagents.Instance{
		RunID:         inst.RunID,
		AgentName:     inst.AgentName,
		SandboxID:     inst.SandboxID,
		SandboxClass:  inst.SandboxClass,
		ComponentKind: inst.ComponentKind,
		StartedAt:     inst.StartedAt,
		MissionID:     inst.MissionID,
		MissionRunID:  inst.MissionRunID,
	})
}
