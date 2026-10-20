// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// kekProvider is a key provider with one fixed master KEK, or an error.
type kekProvider struct {
	kek   []byte
	err   error
	calls int
}

func (p *kekProvider) GetEncryptionKey(context.Context) ([]byte, error) {
	p.calls++
	return p.kek, p.err
}
func (p *kekProvider) Name() string                              { return "test" }
func (p *kekProvider) Health(context.Context) types.HealthStatus { return types.HealthStatus{} }
func (p *kekProvider) Close() error                              { return nil }

func TestNewPageKeys(t *testing.T) {
	ctx := context.Background()

	_, err := (&daemonImpl{}).newPageKeys(ctx)
	require.Error(t, err, "no key provider")

	_, err = (&daemonImpl{keyProvider: &kekProvider{err: errors.New("vault down")}}).newPageKeys(ctx)
	require.ErrorContains(t, err, "vault down")

	_, err = (&daemonImpl{keyProvider: &kekProvider{kek: []byte("short")}}).newPageKeys(ctx)
	require.ErrorContains(t, err, "too short")

	p := &kekProvider{kek: make([]byte, 32)}
	d := &daemonImpl{keyProvider: p}
	first, err := d.newPageKeys(ctx)
	require.NoError(t, err)
	second, err := d.newPageKeys(ctx)
	require.NoError(t, err)
	require.Same(t, first, second, "one construction")
	require.Equal(t, 1, p.calls)
	require.Same(t, first, d.pageKeys)
}

// An RPC with no signer is an internal error, not a nil pointer.
func TestWorldService_PageOfWithoutASigner(t *testing.T) {
	srv, _ := newWorldPageServer(t)
	_, err := srv.pageOf(worldTenantCtx("acme"), "NoSuchRPC", 1, "")
	require.Equal(t, codes.Internal, status.Code(err))
}
