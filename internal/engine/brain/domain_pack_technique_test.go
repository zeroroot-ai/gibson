// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// The hierarchy of a pack is the core hierarchy with the techniques of the
// pack. A technique the pack does not add, or a pack with a bad category,
// holds nothing.
func TestDomainPackSnapshot_HoldsTechnique(t *testing.T) {
	pack := DomainPackSnapshot{Techniques: map[string]string{"dan_prompt": "jailbreak"}}
	if !pack.HoldsTechnique("dan_prompt") {
		t.Fatal("a technique of the pack must be in its hierarchy")
	}
	if pack.HoldsTechnique("not_in_the_pack") {
		t.Fatal("a technique the pack does not add must not be in its hierarchy")
	}
	bad := DomainPackSnapshot{Techniques: map[string]string{"dan_prompt": "no-such-category"}}
	if bad.HoldsTechnique("dan_prompt") {
		t.Fatal("a pack with a bad category holds no technique")
	}
}
