// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"
	"sync"
)

// notifier is the concrete ManifestNotifier — wraps a VersionStore and
// an Invalidator so every write-path call site can invoke a single
// Notify. Safe for concurrent use.
type notifier struct {
	versions VersionStore

	recent sync.Map // key: tenant+"|"+reason → lastFiredUnixMicro (int64)
}

// SystemTenantEnumerator returns every tenant ID that should be
// invalidated when a _system component or policy changes. Implementations
// typically list tenants from the tenant-operator state store.
type SystemTenantEnumerator interface {
	AllTenantIDs(ctx context.Context) ([]string, error)
}
