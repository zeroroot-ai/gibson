// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"errors"
)

// ErrStopIteration is the sentinel error returned by a ForEachTenant callback
// to signal that iteration should halt immediately. It is not treated as a
// failure — ForEachTenant returns nil when this is the only "error" received.
var ErrStopIteration = errors.New("admin: stop iteration")
