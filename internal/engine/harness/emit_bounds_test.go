// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/protobuf/proto"
)

// observeRequestOfSize builds an ObserveRequest whose wire size is exactly n
// bytes, padding the host's ssh_host_key to make up the difference.
func observeRequestOfSize(t *testing.T, n int) *harnesspb.ObserveRequest {
	t.Helper()
	build := func(pad int) *harnesspb.ObserveRequest {
		return &harnesspb.ObserveRequest{
			Context: &harnesspb.ContextInfo{MissionId: "m1", AgentName: "probe", TaskId: "task-1"},
			Observation: &harnesspb.ObserveRequest_Host{
				Host: &harnesspb.HostObservation{
					Address:    "10.0.0.1",
					SshHostKey: strings.Repeat("k", pad),
				},
			},
		}
	}
	// Solve for the padding that lands the encoded message on exactly n bytes.
	// Each added byte of key adds one byte to the message except at the
	// varint-length boundaries, so converge by measuring.
	pad := n
	for range 8 {
		size := proto.Size(build(pad))
		if size == n {
			return build(pad)
		}
		pad += n - size
		if pad < 0 {
			t.Fatalf("cannot build an ObserveRequest of %d bytes", n)
		}
	}
	t.Fatalf("failed to converge on an ObserveRequest of exactly %d bytes", n)
	return nil
}

// boundsService builds a service whose registry has a harness under the
// ("m1", "probe") pair every request in this file uses. Attribution needs the
// mission record (gibson#1256), so the cases that expect the sink to be reached
// need a registry; the rejection cases deliberately do not, and are asserted
// against a registry-less service to prove the caps hold whether or not the
// brain is wired.
func boundsService(sink ObservationSink) *HarnessCallbackService {
	registry := NewCallbackHarnessRegistry()
	registry.Register("m1", "probe", &observeMockHarness{
		missionID: types.NewID(),
		tenantID:  "tenant-a",
		targetID:  types.NewID(),
	})
	return NewHarnessCallbackServiceWithRegistry(slog.Default(), registry, WithObservationSink(sink))
}

// TestObserveRejectsOverSizePayload is the no-partial-state test for the
// canonical emit path: an over-limit observation must be refused and must not
// reach the observation sink, which is the only thing standing between the
// handler and the Timeline.
func TestObserveRejectsOverSizePayload(t *testing.T) {
	t.Run("at the limit reaches the sink", func(t *testing.T) {
		reached := 0
		svc := boundsService(func(context.Context, ObservationAttribution, *harnesspb.ObserveRequest) error {
			reached++
			return nil
		})

		req := observeRequestOfSize(t, emitbounds.MaxPayloadBytes)
		resp, err := svc.Observe(auth.ContextWithTenantString(context.Background(), "tenant-a"), req)
		if err != nil {
			t.Fatalf("Observe returned a transport error: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("observation of exactly MaxPayloadBytes rejected: %v", resp.Error.Message)
		}
		if reached != 1 {
			t.Fatalf("sink reached %d times, want 1", reached)
		}
	})

	t.Run("one byte over is rejected and writes nothing", func(t *testing.T) {
		reached := 0
		svc := boundsService(func(context.Context, ObservationAttribution, *harnesspb.ObserveRequest) error {
			reached++
			return nil
		})

		req := observeRequestOfSize(t, emitbounds.MaxPayloadBytes+1)
		resp, err := svc.Observe(auth.ContextWithTenantString(context.Background(), "tenant-a"), req)
		if err != nil {
			t.Fatalf("Observe returned a transport error: %v", err)
		}
		if resp.Error == nil {
			t.Fatal("observation of MaxPayloadBytes+1 accepted; want rejection")
		}
		if resp.Error.Code != commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
			t.Errorf("error code = %v, want INVALID_ARGUMENT", resp.Error.Code)
		}
		if !strings.Contains(resp.Error.Message, emitbounds.LimitPayloadBytes) {
			t.Errorf("error %q does not name the limit that was exceeded", resp.Error.Message)
		}
		if reached != 0 {
			t.Fatalf("rejected observation reached the sink %d times; a rejected emit must write nothing", reached)
		}
	})

	t.Run("rejection does not depend on the sink being wired", func(t *testing.T) {
		svc := NewHarnessCallbackService(slog.Default())
		resp, err := svc.Observe(auth.ContextWithTenantString(context.Background(), "tenant-a"), observeRequestOfSize(t, emitbounds.MaxPayloadBytes+1))
		if err != nil {
			t.Fatalf("Observe returned a transport error: %v", err)
		}
		if resp.Error == nil {
			t.Fatal("over-size observation accepted when the sink is unwired; the bound must not depend on wiring")
		}
	})
}

// TestObserveRejectsOverCountPerTask exercises the observations-per-task cap at
// the RPC boundary.
func TestObserveRejectsOverCountPerTask(t *testing.T) {
	reached := 0
	svc := boundsService(func(context.Context, ObservationAttribution, *harnesspb.ObserveRequest) error {
		reached++
		return nil
	})

	small := func() *harnesspb.ObserveRequest {
		return &harnesspb.ObserveRequest{
			Context: &harnesspb.ContextInfo{MissionId: "m1", AgentName: "probe", TaskId: "task-1"},
			Observation: &harnesspb.ObserveRequest_Host{
				Host: &harnesspb.HostObservation{Address: "10.0.0.1"},
			},
		}
	}

	for i := range emitbounds.MaxObservationsPerTask {
		resp, err := svc.Observe(auth.ContextWithTenantString(context.Background(), "tenant-a"), small())
		if err != nil {
			t.Fatalf("Observe returned a transport error: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("observation %d of MaxObservationsPerTask rejected: %v", i+1, resp.Error.Message)
		}
	}
	if reached != emitbounds.MaxObservationsPerTask {
		t.Fatalf("sink reached %d times, want %d", reached, emitbounds.MaxObservationsPerTask)
	}

	resp, err := svc.Observe(auth.ContextWithTenantString(context.Background(), "tenant-a"), small())
	if err != nil {
		t.Fatalf("Observe returned a transport error: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("observation MaxObservationsPerTask+1 accepted; want rejection")
	}
	if resp.Error.Code != commonpb.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED {
		t.Errorf("error code = %v, want RESOURCE_EXHAUSTED", resp.Error.Code)
	}
	if reached != emitbounds.MaxObservationsPerTask {
		t.Fatalf("the over-limit observation reached the sink (%d calls); a rejected emit must write nothing", reached)
	}

	// A different task keeps its own budget.
	other := small()
	other.Context.TaskId = "task-2"
	resp, err = svc.Observe(auth.ContextWithTenantString(context.Background(), "tenant-a"), other)
	if err != nil {
		t.Fatalf("Observe returned a transport error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("a second task was charged against the first task's budget: %v", resp.Error.Message)
	}
}

// TestObserveTaskKeyFallsBackToAgentRun records that an emitter which omits the
// explicit task id is still charged against something narrower than "all
// traffic": the (mission, agent) pair the harness registry itself is keyed by.
func TestObserveTaskKeyFallsBackToAgentRun(t *testing.T) {
	explicit := observeTaskKey(&harnesspb.ContextInfo{MissionId: "m1", AgentName: "probe", TaskId: "task-1"})
	if explicit != "task-1" {
		t.Errorf("observeTaskKey = %q, want the explicit task id", explicit)
	}
	fallback := observeTaskKey(&harnesspb.ContextInfo{MissionId: "m1", AgentName: "probe"})
	if fallback != "m1/probe" {
		t.Errorf("observeTaskKey = %q, want the agent-run key", fallback)
	}
	if observeTaskKey(&harnesspb.ContextInfo{MissionId: "m1", AgentName: "recon"}) == fallback {
		t.Error("two agents in one mission share a budget; they are different agent runs")
	}
}
