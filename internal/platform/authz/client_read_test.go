// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"strings"
	"testing"
)

// TestReadTuples_RefusesAnUnderSpecifiedFilter pins the argument check that
// runs before any network call.
//
// OpenFGA's Read API requires either an object filter or both a user and a
// relation. Sending it neither is not a harmless empty query — the server
// rejects it, and the caller (a migration that deletes tuples) would see an
// opaque transport error instead of a clear statement that its filter was
// wrong. The refusal happens locally so the error names the actual mistake.
func TestReadTuples_RefusesAnUnderSpecifiedFilter(t *testing.T) {
	// A zero-value fgaAuthorizer is enough: the guard must reject before it
	// touches f.client, so a nil client is never dereferenced. If the guard
	// were removed this test would panic rather than silently pass.
	f := &fgaAuthorizer{}

	for _, tc := range []struct{ name, user, relation, object string }{
		{"nothing at all", "", "", ""},
		{"user only", "tenant:acme", "", ""},
		{"relation only", "", "parent", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.ReadTuples(context.Background(), tc.user, tc.relation, tc.object)
			if err == nil {
				t.Fatal("ReadTuples accepted a filter OpenFGA cannot answer")
			}
			if !strings.Contains(err.Error(), "ReadTuples") {
				t.Errorf("error %q does not identify the call", err)
			}
		})
	}
}
