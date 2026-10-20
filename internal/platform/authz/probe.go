// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"fmt"
)

// Probe asks FGA one well-formed question and reports whether FGA answered it.
// Both an allow and a deny are a pass. Any error is a failure: an outage, a bad
// token and a wrong store ID all leave the daemon unable to decide, so none of
// them may pass as ready.
func Probe(ctx context.Context, a Authorizer) error {
	if _, err := a.Check(ctx, "user:_probe", "platform_operator", "system_tenant:_probe"); err != nil {
		return fmt.Errorf("authz: FGA probe failed: %w", err)
	}
	return nil
}
