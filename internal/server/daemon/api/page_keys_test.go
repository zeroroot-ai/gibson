// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
)

// testPageKeys returns a key source with a fixed KEK, for the paging tests.
func testPageKeys(t *testing.T) *pagetoken.Keys {
	t.Helper()
	keys, err := pagetoken.NewKeys(bytes.Repeat([]byte{3}, 32))
	require.NoError(t, err)
	return keys
}

func TestPageTokenStatus_MapsTheErrors(t *testing.T) {
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(pageTokenStatus(pagetoken.ErrBadToken)))
	assert.Equal(t, codes.Internal, status_grpc.Code(pageTokenStatus(errors.New("other"))))
}

func TestWithPageKeys_SetsTheKeys(t *testing.T) {
	keys := testPageKeys(t)
	assert.Same(t, keys, (&DaemonServer{}).WithPageKeys(keys).pageKeys)
}

func TestPageOf_WithoutKeysIsInternalAndAForgedTokenIsInvalid(t *testing.T) {
	_, err := pageOf(nil, "tenant-things", 10, "", "acme")
	assert.Equal(t, codes.Internal, status_grpc.Code(err))

	_, err = pageOf(testPageKeys(t), "tenant-things", 10, "forged.token", "acme")
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))

	p, err := pageOf(testPageKeys(t), "tenant-things", 10, "", "acme")
	require.NoError(t, err)
	assert.Equal(t, 10, p.Limit())
}
