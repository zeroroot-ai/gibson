// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package helpers — test_target.go
//
// The synthetic scan target the exit tests run their missions against. It is
// created through DaemonService/CreateTarget under the caller's tenant, and
// deleted the same way. The previous version wrote a target document straight
// into Redis at gibson:target:<id>; the daemon's state client keys every
// tenant's targets under its own prefix, so the run answered "target not
// found" for a document that was there (gibson#14, run 35421412151). A
// fixture that bypasses the producer proves nothing about it.
package helpers

import (
	"context"
	"fmt"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	targetpb "github.com/zeroroot-ai/sdk/api/gen/gibson/target/v1"
)

// RegisterTestTarget creates a web target named name at targetURL for the
// tenant on ctx and returns its id.
func RegisterTestTarget(ctx context.Context, daemon daemonpb.DaemonServiceClient, name, targetURL string) (string, error) {
	resp, err := daemon.CreateTarget(ctx, &daemonpb.CreateTargetRequest{
		Target: &targetpb.Target{
			Name:        name,
			Type:        "web",
			Url:         targetURL,
			Status:      "active",
			Description: "exit-test fixture",
			Tags:        []string{"e2e", "test-fixture"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("test_target: CreateTarget(%s): %w", name, err)
	}
	if resp.GetTargetId() == "" {
		return "", fmt.Errorf("test_target: CreateTarget(%s): empty target id", name)
	}
	return resp.GetTargetId(), nil
}

// DeleteTestTarget removes the target. Errors are ignored: the cluster is
// torn down after the run and a leftover fixture harms nothing.
func DeleteTestTarget(ctx context.Context, daemon daemonpb.DaemonServiceClient, targetID string) {
	_, _ = daemon.DeleteTarget(ctx, &daemonpb.DeleteTargetRequest{TargetId: targetID})
}
