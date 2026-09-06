// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// taskGrantContextKey is the unexported key the verified task grant is stored
// under. A local type keeps it from colliding with any other package's key.
type taskGrantContextKey struct{}

// withTaskGrantClaims returns a context carrying the claims of the task grant
// the request presented, already verified.
//
// The claims go on the context in the one place that verifies them, the scope
// interceptor. A handler that needs to know WHICH job or WHICH task a callback
// belongs to reads them here rather than from a request field: a member can
// name any job in its body, but it cannot forge the grant the daemon minted for
// one dispatch.
func withTaskGrantClaims(ctx context.Context, claims sdkcg.Claims) context.Context {
	return context.WithValue(ctx, taskGrantContextKey{}, claims)
}

// TaskGrantClaimsFromContext returns the verified task-grant claims on ctx, and
// whether the request carried a task grant at all.
//
// A request authenticated some other way — a component's own agent+jwt, a
// person through Envoy — carries none, and a handler that needs one must refuse
// rather than guess.
func TaskGrantClaimsFromContext(ctx context.Context) (sdkcg.Claims, bool) {
	claims, ok := ctx.Value(taskGrantContextKey{}).(sdkcg.Claims)
	return claims, ok
}
