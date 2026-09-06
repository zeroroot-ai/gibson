// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package liveagents

import "errors"

// ErrInstanceNotFound is returned by Registry.Subscribe when the tenant does
// not own a running instance with the requested run id. A foreign run id and a
// nonexistent run id return the same error, so the surface never confirms that
// another tenant's run id exists.
var ErrInstanceNotFound = errors.New("liveagents: running agent instance not found")
