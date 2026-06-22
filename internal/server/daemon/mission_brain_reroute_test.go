package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
)

func TestMissionGoal(t *testing.T) {
	if g := missionGoal(nil); g != "" {
		t.Errorf("nil mission: want empty, got %q", g)
	}
	if g := missionGoal(&mission.Mission{}); g != "" {
		t.Errorf("no metadata: want empty, got %q", g)
	}
	m := &mission.Mission{Metadata: map[string]any{"goal": "get a shell"}}
	if g := missionGoal(m); g != "get a shell" {
		t.Errorf("metadata goal: got %q", g)
	}
	m2 := &mission.Mission{Metadata: map[string]any{"goal": 42}} // non-string
	if g := missionGoal(m2); g != "" {
		t.Errorf("non-string goal: want empty, got %q", g)
	}
}

// completingDispatcher completes any dispatched agent immediately (stand-in for
// the harness dispatch) so a scripted mission reaches a terminal state.
type completingDispatcher struct{ eng *brain.Engine }

func (c *completingDispatcher) Dispatch(req brain.DispatchRequest) {
	c.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Result: "ok"})
}

func TestAwaitBrainMission_ReturnsCompleted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := brain.NewRegistry(ctx, brain.ExecutorSystems()...)
	disp := &completingDispatcher{}
	reg.OnEngine(func(e *brain.Engine) {
		disp.eng = e
		brain.WireExecutor(ctx, e, brain.ExecutorDeps{
			Dispatcher:    disp,
			Decider:       &noopDecider{},
			Catalog:       func() []brain.Capability { return nil },
			DrainInterval: 5 * time.Millisecond,
		})
	})
	eng := reg.For("t1")
	eng.Submit(brain.MissionProjected{ID: "m1", Nodes: []brain.WorkNode{
		{ID: "a", Kind: "agent", Target: "recon"},
	}})

	var mm missionManager
	status, errMsg := mm.awaitBrainMission(ctx, eng, "m1")
	if status != mission.MissionStatusCompleted {
		t.Fatalf("want completed, got %s (%s)", status, errMsg)
	}
}

func TestAwaitBrainMission_CtxCancelledReturnsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	eng := brain.NewEngine("t1") // no systems → mission never completes
	eng.Submit(brain.MissionProjected{ID: "m1", Goal: "x"})

	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	var mm missionManager
	status, _ := mm.awaitBrainMission(ctx, eng, "m1")
	if status != mission.MissionStatusCancelled {
		t.Fatalf("want cancelled, got %s", status)
	}
}

type noopDecider struct{}

func (noopDecider) Decide(context.Context, brain.MissionContext) (brain.DeciderOutput, error) {
	return brain.DeciderOutput{}, nil
}
