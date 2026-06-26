// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package main

import "fmt"

// validateFGAEnvKeys is the one-code-path slice deploy#195 startup contract
// for the tenant-operator. The operator refuses to boot when FGA_URL or
// FGA_STORE_ID are missing from the environment — the previous behaviour
// (silently inject a nil FGA client → saga steps skip) was an authz-bypass
// surface and has been deleted.
//
// The function is pure (takes a getenv functor) so the contract is testable
// without mutating process environment. main() wires it to os.Getenv.
//
// Returns a non-nil error naming the missing key(s) when the contract is
// violated; nil otherwise.
func validateFGAEnvKeys(getenv func(string) string) error {
	missing := []string{}
	if getenv("FGA_URL") == "" {
		missing = append(missing, "FGA_URL")
	}
	if getenv("FGA_STORE_ID") == "" {
		missing = append(missing, "FGA_STORE_ID")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf(
		"FGA env not configured — required: FGA_URL and FGA_STORE_ID, missing: %v "+
			"(one-code-path slice deploy#195: no more degraded-mode fallback)",
		missing,
	)
}
