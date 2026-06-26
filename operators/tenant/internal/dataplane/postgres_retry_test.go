// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestIsTransientCatalogErr verifies the classifier recognises the documented
// transient SQLSTATE classes (XX000, 40001, 40P01) and the "tuple concurrently
// deleted" message-only fallback, AND that unrelated PgErrors / generic errors
// are NOT misclassified as transient.
//
// This is the unit half of issue #48; the integration half (real Postgres
// concurrent reconcile producing XX000 → retry succeeds) lives in the e2e
// suite once the kind cluster is wired.
func TestIsTransientCatalogErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"xx000", &pgconn.PgError{Code: "XX000"}, true},
		{"serialization", &pgconn.PgError{Code: "40001"}, true},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, true},
		{"tuple-msg-no-code", errors.New("postgres: tuple concurrently deleted"), true},
		{"permission-denied-42501", &pgconn.PgError{Code: "42501"}, false},
		{"unique-violation-23505", &pgconn.PgError{Code: "23505"}, false},
		{"plain-error", errors.New("some random error"), false},
		{"wrapped-xx000", fmt.Errorf("dataplane: grant connect: %w", &pgconn.PgError{Code: "XX000"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientCatalogErr(tc.err); got != tc.want {
				t.Errorf("isTransientCatalogErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
