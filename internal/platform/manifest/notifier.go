// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// notifier is the concrete ManifestNotifier — wraps a VersionStore and
// an Invalidator so every write-path call site can invoke a single
// Notify. Safe for concurrent use.
type notifier struct {
	versions VersionStore
	inv      Invalidator
	log      *slog.Logger

	// systemFanout, when non-nil, enumerates every tenant that must be
	// notified for _system mutations. If nil, _system mutations notify
	// only the literal "_system" tenant; production deployments should
	// wire a fanout that returns the real tenant list.
	systemFanout SystemTenantEnumerator

	// dedupWindow keeps repeated notifications for the same (tenant, reason)
	// from flooding Redis during tight write loops. A 100ms window is
	// tight enough to catch burst writes and loose enough to never stall.
	dedupWindow time.Duration
	recent      sync.Map // key: tenant+"|"+reason → lastFiredUnixMicro (int64)
}

// SystemTenantEnumerator returns every tenant ID that should be
// invalidated when a _system component or policy changes. Implementations
// typically list tenants from the tenant-operator state store.
type SystemTenantEnumerator interface {
	AllTenantIDs(ctx context.Context) ([]string, error)
}

// StaticTenantEnumerator is a simple SystemTenantEnumerator backed by a
// fixed list. Tests and dev-mode setups can use this; production wires a
// live enumerator against the tenant-operator state.
type StaticTenantEnumerator struct {
	Tenants []string
}
