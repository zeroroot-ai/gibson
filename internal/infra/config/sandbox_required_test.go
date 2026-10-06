// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import (
	"errors"
	"testing"
)

// The daemon start refuses an install with no setec address (ADR-0142). The
// loader passes an empty address, because tools and tests read a config too.
func TestSandboxConfig_RequireSetec(t *testing.T) {
	empty := &SandboxConfig{}
	if err := empty.RequireSetec(); !errors.Is(err, ErrNoSetecAddress) {
		t.Errorf("empty address: err = %v, want ErrNoSetecAddress", err)
	}
	if err := empty.Validate(); err != nil {
		t.Errorf("the loader refused an empty address: %v", err)
	}
	set := &SandboxConfig{Setec: SandboxSetecConfig{Address: "setec:50051"}}
	if err := set.RequireSetec(); err != nil {
		t.Errorf("address set: %v", err)
	}
	if err := set.Validate(); err == nil {
		t.Error("an address with no mTLS files passed the shape check")
	}
}
