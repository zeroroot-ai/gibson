// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

// The daemon builds the page keys once, before it registers any service. When
// the key provider fails, buildGRPCServer returns the error and no service is
// silently missing.
func TestBuildGRPCServer_ReturnsThePageKeysError(t *testing.T) {
	d := &daemonImpl{
		logger:      testObservabilityLogger(),
		config:      &config.Config{},
		grpcAddr:    "127.0.0.1:0",
		keyProvider: &kekProvider{err: errors.New("vault down")},
	}

	sub, err := d.buildGRPCServer(context.Background())

	require.Nil(t, sub)
	require.ErrorContains(t, err, "vault down")
}
