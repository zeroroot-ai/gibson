// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/fgaevent"
)

// fgaEventPublisher is the daemon's publisher of FGA write events, on the
// same Redis the state client uses. A daemon with no state client publishes
// nothing, and ext-authz falls back to its cache TTL (hosted#204).
func fgaEventPublisher(sc *state.StateClient, log *slog.Logger) fgaevent.Publisher {
	if sc == nil {
		log.Warn("no state client: FGA write events are not published, the ext-authz cache TTL bounds role changes")
		return nil
	}
	return fgaevent.NewRedisPublisher(sc.Client(), log, 0)
}
