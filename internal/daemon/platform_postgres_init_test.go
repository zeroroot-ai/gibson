// Copyright 2026 Zero Day AI.
// Licensed under the Apache License, Version 2.0 (the "License").

package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/config"
)

// TestPlatformPostgres_MissingHost_FailsFast verifies the gibson#246 contract:
// an unconfigured platform-postgres host is a terminal startup error, not a
// silent downgrade to platformDB=nil. The chart always wires
// platform-postgres-rw, so an empty host means the deployment is misconfigured
// and the daemon must refuse to boot.
func TestPlatformPostgres_MissingHost_FailsFast(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PlatformPostgres.Host = ""

	d := newMinimalDaemon(cfg)
	err := d.initPlatformPostgres(context.Background())

	require.Error(t, err, "initPlatformPostgres must fail when no host is configured (no more silent platformDB=nil)")
	assert.Nil(t, d.platformDB, "platformDB must remain nil on failure")
	assert.True(t,
		strings.Contains(err.Error(), "platform-postgres") || strings.Contains(err.Error(), "host"),
		"error must name platform-postgres / host so an operator can fix it, got: %s", err.Error(),
	)
}

// TestPlatformPostgres_Unreachable_FailsFast verifies that a configured but
// unreachable platform-postgres host produces a fatal startup error from the
// ping probe rather than booting the daemon with platformDB=nil. The host
// points at loopback port 1, which is reserved and never has a listener, so
// the dial gets an immediate connection-refused and the test stays fast.
func TestPlatformPostgres_Unreachable_FailsFast(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PlatformPostgres.Host = "127.0.0.1" // loopback...
	cfg.PlatformPostgres.Port = 1           // ...reserved port, nothing listens → connection refused
	cfg.PlatformPostgres.Database = "gibson_dashboard"
	cfg.PlatformPostgres.Username = "gibson"
	cfg.PlatformPostgres.Password = "irrelevant"
	cfg.PlatformPostgres.SSLMode = "disable"

	d := newMinimalDaemon(cfg)
	err := d.initPlatformPostgres(context.Background())

	require.Error(t, err, "initPlatformPostgres must fail when platform-postgres is unreachable (no silent fallback)")
	assert.Nil(t, d.platformDB, "platformDB must remain nil when the ping fails")
	assert.Contains(t, err.Error(), "platform-postgres",
		"error must name platform-postgres so the broken dependency is identifiable in CrashLoopBackOff")
}
