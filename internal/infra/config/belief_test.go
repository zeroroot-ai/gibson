// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import (
	"strings"
	"testing"
	"time"
)

// The default config carries the default reload interval, and the validator
// refuses a negative one (gibson#615).
func TestBeliefConfig_ReloadInterval(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Belief.ReloadInterval != DefaultBeliefReloadInterval {
		t.Fatalf("default belief.reload_interval = %s, want %s", cfg.Belief.ReloadInterval, DefaultBeliefReloadInterval)
	}
	if err := NewValidator().Validate(cfg); err != nil {
		t.Fatalf("the default config does not validate: %v", err)
	}
	cfg.Belief.ReloadInterval = -time.Second
	err := NewValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "belief.reload_interval") {
		t.Fatalf("Validate of a negative interval = %v, want a belief.reload_interval error", err)
	}
}
