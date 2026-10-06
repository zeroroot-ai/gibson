// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"sync"
)

// notifier is the concrete ManifestNotifier — wraps a VersionStore and
// an Invalidator so every write-path call site can invoke a single
// Notify. Safe for concurrent use.
type notifier struct {
	versions VersionStore

	recent sync.Map // key: tenant+"|"+reason → lastFiredUnixMicro (int64)
}
