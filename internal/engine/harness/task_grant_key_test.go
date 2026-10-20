// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// A grant names one task. An emitter that spreads its observations over many
// task ids in the body is still charged against the task of its grant, so it
// cannot dodge the cap (gibson#1235).
func TestObserveCapFollowsTheTaskOfTheGrant(t *testing.T) {
	svc := boundsService(t, func(context.Context, ObservationAttribution, *harnesspb.ObserveRequest) error { return nil })
	claims := grantClaims(t, "tenant-a", "m1")
	claims.TaskID = "task-grant"
	ctx := withGrantMissionRun(withTaskGrantClaims(auth.ContextWithTenantString(context.Background(), "tenant-a"), claims), "run-1")

	observe := func(bodyTask string) *harnesspb.ObserveResponse {
		resp, err := svc.Observe(ctx, &harnesspb.ObserveRequest{
			Context: &harnesspb.ContextInfo{MissionId: "m1", AgentName: "probe", TaskId: bodyTask},
			Observation: &harnesspb.ObserveRequest_Host{
				Host: &harnesspb.HostObservation{Address: "10.0.0.1"},
			},
		})
		if err != nil {
			t.Fatalf("Observe returned a transport error: %v", err)
		}
		return resp
	}

	for i := range emitbounds.MaxObservationsPerTask {
		// Each call names another task in the body.
		if resp := observe("body-task-" + string(rune('a'+i%26)) + time.Duration(i).String()); resp.Error != nil {
			t.Fatalf("observation %d rejected: %v", i+1, resp.Error.Message)
		}
	}
	if resp := observe("one-more-body-task"); resp.Error == nil {
		t.Fatal("a fresh body task id bought a fresh budget; the grant decides the task")
	}
}

// The events that the service publishes carry the task of the verified grant,
// not the task that the body names (gibson#1235).
func TestPublishedEventsCarryTheTaskOfTheGrant(t *testing.T) {
	data := make(chan map[string]interface{}, 8)
	svc := newTaskKeyEventService(t, data)

	claims := grantClaims(t, "acme", "mission-A")
	claims.TaskID = "task-grant"
	ctx := withGrantMissionRun(withTaskGrantClaims(auth.ContextWithTenantString(context.Background(), "acme"), claims), "run-1")
	_, err := svc.LLMComplete(ctx, &harnesspb.LLMCompleteRequest{
		Context:  &harnesspb.ContextInfo{MissionId: "mission-A", AgentName: "recon-agent", TaskId: "task-body"},
		Slot:     "default",
		Messages: []*harnesspb.LLMMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("LLMComplete: %v", err)
	}
	select {
	case got := <-data:
		if got["task_id"] != "task-grant" {
			t.Fatalf("event task_id = %v, want the task of the grant", got["task_id"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event was published")
	}
}

func newTaskKeyEventService(t *testing.T, data chan map[string]interface{}) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, "mission-A", "recon-agent", newCompletingHarness("acme"))
	return NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		registry,
		WithEventBus(dataBus{data}),
	)
}

// dataBus sends the Data map of each published event to a channel.
type dataBus struct{ data chan map[string]interface{} }

func (b dataBus) Publish(_ context.Context, event interface{}) error {
	if v, ok := dataOf(event); ok {
		b.data <- v
	}
	return nil
}

// dataOf reads the Data map of a published event, whatever struct carries it.
func dataOf(event interface{}) (map[string]interface{}, bool) {
	field := reflect.ValueOf(event).FieldByName("Data")
	if !field.IsValid() {
		return nil, false
	}
	data, ok := field.Interface().(map[string]interface{})
	return data, ok
}
