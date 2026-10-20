// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// kekProvider is a key provider that answers with a fixed key or error.
type kekProvider struct {
	key []byte
	err error
}

func (p kekProvider) GetEncryptionKey(context.Context) ([]byte, error) { return p.key, p.err }
func (kekProvider) Name() string                                       { return "test" }
func (kekProvider) Health(context.Context) types.HealthStatus          { return types.HealthStatus{} }
func (kekProvider) Close() error                                       { return nil }

func TestWireOperatorPageTokens(t *testing.T) {
	ctx := context.Background()
	if err := wireOperatorPageTokens(ctx, &api.DaemonServer{}, nil); err == nil {
		t.Error("a daemon with no key provider must not start")
	}
	if err := wireOperatorPageTokens(ctx, &api.DaemonServer{}, kekProvider{err: errors.New("vault down")}); err == nil {
		t.Error("a KEK read failure must stop the daemon")
	}
	if err := wireOperatorPageTokens(ctx, &api.DaemonServer{}, kekProvider{key: []byte("short")}); err == nil {
		t.Error("a short KEK must stop the daemon")
	}
	if err := wireOperatorPageTokens(ctx, &api.DaemonServer{}, kekProvider{key: bytes.Repeat([]byte{3}, 32)}); err != nil {
		t.Errorf("a valid KEK: %v", err)
	}
}
