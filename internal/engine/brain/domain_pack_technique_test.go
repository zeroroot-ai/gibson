// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// The hierarchy of a pack is the core hierarchy with the techniques of the
// pack. A technique the pack does not add, or a pack with a bad category,
// holds nothing.
func TestDomainPackSnapshot_HoldsTechnique(t *testing.T) {
	pack := DomainPackSnapshot{Techniques: map[string]string{"default_credentials": "initial_access"}}
	if !pack.HoldsTechnique("default_credentials") {
		t.Fatal("a technique of the pack must be in its hierarchy")
	}
	if pack.HoldsTechnique("not_in_the_pack") {
		t.Fatal("a technique the pack does not add must not be in its hierarchy")
	}
	bad := DomainPackSnapshot{Techniques: map[string]string{"default_credentials": "no-such-category"}}
	if bad.HoldsTechnique("default_credentials") {
		t.Fatal("a pack with a bad category holds no technique")
	}
}
