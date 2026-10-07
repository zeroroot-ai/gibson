// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package saga

import "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"

// ErrPermanent is re-exported from clients so saga callers can reference it
// from a single import. Use WrapPermanent to create a permanent error and
// IsPermanent to test for one.
var ErrPermanent = clients.ErrPermanent
