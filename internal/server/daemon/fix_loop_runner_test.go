// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

type fakePlacerQuerier struct{ places []component.Place }

func (f fakePlacerQuerier) FindingPlaces(context.Context, string, string) ([]component.Place, error) {
	return f.places, nil
}

func TestApplicationPlacer(t *testing.T) {
	ctx := context.Background()
	host := component.Place{Label: component.PlaceHost, Key: "h1"}
	app := component.Place{Label: component.PlaceApplication, Key: "a1"}
	tests := []struct {
		name    string
		querier any
		want    string
		wantErr bool
	}{
		{"application", fakePlacerQuerier{places: []component.Place{app, host}}, "a1", false},
		{"host only has no application", fakePlacerQuerier{places: []component.Place{host}}, "", false},
		{"no querier is an error", nil, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applicationPlacer{querier: func() any { return tc.querier }}.Application(ctx, "t1", "f1")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

// With no callback manager, the revert fails and takes no other path.
func TestGovernedRevert_NeedsTheCallbackManager(t *testing.T) {
	g := governedRevert{callback: func() *harness.CallbackManager { return nil }}
	if _, err := g.CallConnectorForTenant(context.Background(), "acme", "m1", "gitlab", "revert_merge_request", nil); err == nil {
		t.Fatal("want an error with no callback manager")
	}
}

// A runner with no interval and no logger takes the defaults, and a step over
// a World with no merge request submits nothing.
func TestNewFixLoopRunner_Defaults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	reg.For("acme")
	r := &stubFixReader{}
	w, err := fixloop.NewWatcher(r, r, applicationPlacer{querier: func() any { return nil }}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewFixLoopRunner(reg, w, 0, nil)
	if runner.interval <= 0 || runner.logger == nil {
		t.Fatalf("runner = %+v", runner)
	}
	runner.step(ctx)
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()
	cancel()
	<-done
}

type stubFixReader struct{}

func (*stubFixReader) MergeRequest(context.Context, string, string) (fixloop.MergeFact, error) {
	return fixloop.MergeFact{}, nil
}

func (*stubFixReader) Deploy(context.Context, string, string) (fixloop.DeployFact, error) {
	return fixloop.DeployFact{}, nil
}

func (*stubFixReader) Health(context.Context, string, string, time.Time, time.Duration) (fixloop.HealthFact, error) {
	return fixloop.HealthFact{}, nil
}

func (*stubFixReader) Revert(context.Context, string, string, string) (fixloop.RevertFact, error) {
	return fixloop.RevertFact{}, nil
}
