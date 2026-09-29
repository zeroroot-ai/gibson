// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import "testing"

// TestFGAEventRedis: no URL means no subscriber, a bad URL is an error, a
// good URL with a password gives a client that carries it.
func TestFGAEventRedis(t *testing.T) {
	if c, err := fgaEventRedis("", "x"); c != nil || err != nil {
		t.Fatalf("empty url: client=%v err=%v, want nil, nil", c, err)
	}
	if _, err := fgaEventRedis("not a url", ""); err == nil {
		t.Fatal("a bad url must be an error, never a silent no-subscriber")
	}
	c, err := fgaEventRedis("redis://gibson-redis:6379/0", "secret")
	if err != nil || c == nil {
		t.Fatalf("good url: client=%v err=%v", c, err)
	}
	t.Cleanup(func() { _ = c.Close() })
}
