// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// The enroller passes the spec to the tenant-admin surface and returns its
// gRPC status unchanged, so the caller sees the code.
func TestProducedEnroller_PassesTheStatusThrough(t *testing.T) {
	p := producedEnroller{srv: &api.DaemonServer{}}
	_, err := p.EnrollProduced(context.Background(), "acme", "user:someone", component.ProducedComponentSpec{
		Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: "ghcr.io/x/y@sha256:aa",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a producer that is not an agent: %v, want PermissionDenied", err)
	}
}
