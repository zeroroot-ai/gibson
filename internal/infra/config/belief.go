// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import "time"

// DefaultBeliefReloadInterval is how often the daemon reads the current belief
// artifact version of each tenant when the config sets no interval.
const DefaultBeliefReloadInterval = 60 * time.Second

// BeliefConfig configures how the daemon loads the belief artifacts of each
// tenant from the platform Postgres (ADR-0106, gibson#615).
type BeliefConfig struct {
	// ReloadInterval is how often the daemon reads the current version of
	// each tenant. A tenant whose version changed gets the new artifacts.
	// Zero means DefaultBeliefReloadInterval. A negative value is refused.
	ReloadInterval time.Duration `mapstructure:"reload_interval" yaml:"reload_interval"`
}
