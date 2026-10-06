// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// ErrWorldUnavailable is the answer of a read handler while the engine of the
// tenant is stopped. Handlers return it as it is, so the caller sees the code.
var ErrWorldUnavailable = status_grpc.Error(codes.Unavailable, "the World of the tenant is not available; try again later")

// TenantEngine returns the brain engine of a tenant for a handler that reads
// the tenant World, and false when that engine is stopped.
//
// A Registry returns a stopped engine when the hydrate of the tenant fails
// (gibson#825). A stopped engine holds an empty World, which is not the fold
// of the Timeline (ADR-0163). A read from it would answer "nothing" during a
// store outage, so the handler returns ErrWorldUnavailable instead
// (gibson#826). The cause stays in the log of the Registry and does not go
// to the caller.
func TenantEngine(reg *brain.Registry, tenant string) (*brain.Engine, bool) {
	eng := reg.For(tenant)
	if eng.Err() != nil {
		return nil, false
	}
	return eng, true
}
