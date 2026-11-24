// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// A failed check is told apart by the cause in its chain, and the message
// names no detail of the authz store.
func TestClassifyAuthzFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want AuthzFault
	}{
		{"timeout", fmt.Errorf("check: %w", authz.ErrFgaTimeout), AuthzFaultTimeout},
		{"outage", fmt.Errorf("check: %w", authz.ErrFgaUnavailable), AuthzFaultUnavailable},
		{"bad credentials", fmt.Errorf("check: %w", authz.ErrFgaUnauthenticated), AuthzFaultNotSetUp},
		{"no store", fmt.Errorf("check: %w", authz.ErrFgaNotFound), AuthzFaultNotSetUp},
		{"no model", fmt.Errorf("check: %w", authz.ErrModelNotFound), AuthzFaultNotSetUp},
		{"invalid request", fmt.Errorf("check: %w", authz.ErrInvalidArgument), AuthzFaultInternal},
		{"unknown", errors.New("boom"), AuthzFaultInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := ClassifyAuthzFailure(tc.err)
			if got != tc.want {
				t.Fatalf("fault = %v, want %v", got, tc.want)
			}
			if msg == "" {
				t.Fatal("the message is empty")
			}
			if msg == tc.err.Error() {
				t.Fatalf("the message repeats the error: %q", msg)
			}
		})
	}
}
