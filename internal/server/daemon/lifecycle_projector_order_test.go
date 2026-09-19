// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// TestLifecycleProjector_PublishesInTimelineOrder is the regression for the
// lost node reason on gibson#14.
//
// One tick applies WorkCompleted(err) and then, through the completion system,
// MissionDone. The tap projected node.failed and the terminal status a few
// microseconds apart and published each in its own goroutine. Each did its own
// XADD, so the status could land on the stream first. RunMission ends its
// stream on the terminal status, so the client never saw why the node failed:
// the suite read "a work item failed" and nothing else.
//
// The sink here holds the first publish for a moment. Under a goroutine per
// event the second publish enters during that hold, which the in-flight
// counter catches. Under the ordered drainer the second publish waits.
func TestLifecycleProjector_PublishesInTimelineOrder(t *testing.T) {
	eng := brain.NewEngine("acme")
	// The same systems the daemon installs (brain.Registry): the completion
	// system is what turns the failed work into MissionDone inside the tick.
	for _, sys := range brain.ExecutorSystems() {
		eng.AddSystem(sys)
	}

	var (
		mu        sync.Mutex
		got       []api.EventData
		inflight  atomic.Int32
		overlap   atomic.Bool
		published = make(chan struct{}, 16)
	)
	tap := &lifecycleProjectorTap{
		tenant: "acme",
		eng:    eng,
		logger: slog.Default(),
		publish: func(out api.EventData) {
			if inflight.Add(1) > 1 {
				overlap.Store(true)
			}
			time.Sleep(50 * time.Millisecond) // the XADD round trip
			mu.Lock()
			got = append(got, out)
			mu.Unlock()
			inflight.Add(-1)
			published <- struct{}{}
		},
	}
	eng.Subscribe(tap.apply)

	eng.Submit(brain.MissionProjected{ID: "m1", Nodes: []brain.WorkNode{{ID: "probe", Kind: "tool", Target: "nmap"}}})
	eng.Submit(brain.MissionStarted{ID: "m1"})
	tickOrFail(t, eng)

	// The scheduler dispatched the one node in that tick (node.started). The
	// dispatch gate's refusal comes back as the work's error.
	workID := onlyWorkID(t, eng)
	eng.Submit(brain.WorkCompleted{ID: workID, Err: `tool "nmap" is not enabled for tenant "acme"`})
	// This tick folds the failure and runs the completion system: node.failed
	// and status=failed leave the tap back to back.
	tickOrFail(t, eng)

	// status running, node.started, node.failed, status failed.
	for i := range 4 {
		select {
		case <-published:
		case <-time.After(10 * time.Second):
			mu.Lock()
			t.Fatalf("published %d of 4 lifecycle events: %+v", i, got)
		}
	}

	if overlap.Load() {
		t.Fatal("two lifecycle events were published concurrently: the terminal status can overtake node.failed on the stream")
	}
	mu.Lock()
	defer mu.Unlock()
	kinds := make([]string, 0, len(got))
	for _, e := range got {
		k := e.EventType
		if me := e.MissionEvent; me != nil && e.EventType == "status" {
			k += ":" + me.Payload["status"].(string)
		}
		kinds = append(kinds, k)
	}
	want := []string{"status:running", "node.started", "node.failed", "status:failed"}
	if len(kinds) != len(want) {
		t.Fatalf("published %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("published %v, want %v: the wire must carry the node's reason before the terminal status", kinds, want)
		}
	}
	if got[2].MissionEvent == nil || got[2].MissionEvent.Error == "" {
		t.Fatal("node.failed carried no error")
	}
}

// TestLifecycleProjector_FanOutReachesTheBus pins the sink the drainer feeds:
// an event reaches an in-process subscriber, a closed bus and a Redis stream
// with no client are logged and never stop the drainer.
func TestLifecycleProjector_FanOutReachesTheBus(t *testing.T) {
	bus := NewEventBus(slog.Default())
	tap := &lifecycleProjectorTap{
		tenant:      "acme",
		eventBus:    bus,
		redisStream: &RedisEventStream{}, // no state client: PublishEvent errors
		logger:      slog.Default(),
	}
	tap.publish = tap.fanOut

	ch, unsubscribe := bus.Subscribe(context.Background(), nil, "")
	defer unsubscribe()

	ev := ProjectBrainEvent(brain.MissionStarted{ID: "m1"}, "")
	if ev == nil {
		t.Fatal("MissionStarted must project to a status event")
	}
	tap.enqueue(*ev)

	select {
	case got := <-ch:
		if got.EventType != "status" || got.MissionEvent == nil || got.MissionEvent.MissionID != "m1" {
			t.Fatalf("bus delivered %+v, want the status event for m1", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event never reached the in-process bus")
	}

	// A closed bus is an error the drainer logs and survives.
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
	tap.fanOut(*ev)
}
