// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strings"
	"testing"
)

func TestRedactedURL_NeverShowsTheCredential(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"redis://:s3cret@gibson-redis-stack:6379", "redis://:xxxxx@gibson-redis-stack:6379"},
		{"redis://user:s3cret@host:6379/2", "redis://user:xxxxx@host:6379/2"},
		{"redis://host:6379", "redis://host:6379"},
		{"redis://:s3cret@host:6379\x7f", "<not a URL>"},
	} {
		got := redactedURL(tc.in)
		if got != tc.want {
			t.Errorf("redactedURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, "s3cret") {
			t.Errorf("redactedURL(%q) = %q shows the credential", tc.in, got)
		}
	}
}
