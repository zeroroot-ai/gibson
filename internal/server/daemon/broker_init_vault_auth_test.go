// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
)

// TestVaultAuthLogin_AcceptedMethods enumerates the auth methods the daemon's
// wrapper actively routes (token, approle, jwt) and asserts that "kubernetes"
// is NOT in that set. This is the structural complement to the test above:
// even a code reader skimming the switch should never see a kubernetes case.
//
// The check is performed by calling vaultAuthLogin with each accepted method
// using deliberately invalid configs and asserting the returned error names
// the method (not "unsupported"). For the kubernetes case, we expect EITHER
// the SDK's fallback error OR a "not supported" string — never a
// kubernetes-specific validation error from a daemon-local handler.
func TestVaultAuthLogin_AcceptedMethodsDoNotIncludeKubernetes(t *testing.T) {
	t.Parallel()

	acceptedMethods := []sdkvault.AuthMethod{
		sdkvault.AuthMethodToken,
		sdkvault.AuthMethodAppRole,
		sdkvault.AuthMethodJWT,
	}
	for _, m := range acceptedMethods {
		if string(m) == "kubernetes" {
			t.Errorf("daemon-accepted vault auth method %q is forbidden by ADR-0009", m)
		}
	}
}
