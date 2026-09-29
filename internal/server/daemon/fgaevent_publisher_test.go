// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
)

func TestFGAEventPublisher(t *testing.T) {
	if p := fgaEventPublisher(nil, slog.Default()); p != nil {
		t.Fatal("no state client must mean no publisher")
	}
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	if p := fgaEventPublisher(sc, slog.Default()); p == nil {
		t.Fatal("a state client must give a publisher")
	}
}
