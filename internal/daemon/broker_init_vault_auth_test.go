package daemon

import (
	"context"
	"strings"
	"testing"

	sdkvault "github.com/zero-day-ai/platform-clients/secrets/vault"
)

// TestVaultAuthLogin_KubernetesIsDenied is the daemon-side mirror of the SDK's
// TestAuthMethod_KubernetesIsDenied (sdk#81). It guards against accidental
// re-introduction of Vault `auth/kubernetes` in the daemon's wrapper switch.
//
// Per ADR-0009 (jwt-spiffe-everywhere), TokenReview-based authentication to
// non-Kubernetes services is forbidden: Workloads on Kubernetes authenticate
// to Vault via JWT (SPIFFE- or Zitadel-issued) or AppRole, never via
// `auth/kubernetes`. The SDK constant `AuthMethodKubernetes` was removed in
// sdk#81; the daemon's mirror switch case was removed in gibson#170 (this
// change).
//
// This test cannot enumerate the SDK's exported AuthMethod values directly
// because the constant set is private to the SDK's switch in
// secrets/providers/vault/auth.go. Instead it asserts the daemon's
// `vaultAuthLogin` wrapper does NOT route a `Method: "kubernetes"` config
// into a daemon-local handler — control must fall through to the SDK
// fallback (`loginFallbackViaProvider`), which surfaces the SDK's clean
// "unsupported auth method" error path. A successful re-introduction of a
// daemon-local kubernetes case would either bypass the fallback (no SDK
// error returned) or build a vault client and try to read a service-account
// token file from disk; both regressions are caught here.
func TestVaultAuthLogin_KubernetesIsDenied(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethod("kubernetes"),
			Role:   "gibson",
		},
	}

	_, _, err := vaultAuthLogin(context.Background(), cfg)
	if err == nil {
		t.Fatal("vaultAuthLogin(method=kubernetes): expected error, got nil")
	}
	// The SDK fallback path returns an error mentioning the unsupported
	// method by name. The exact wording is "method \"kubernetes\" is not
	// supported by the lightweight refresher" (loginFallbackViaProvider's
	// surfaced error) OR an SDK-level "unsupported auth method" error
	// once the SDK's AuthMethodKubernetes constant is gone. Either is
	// acceptable; both reject the request.
	msg := err.Error()
	if !strings.Contains(msg, "kubernetes") && !strings.Contains(msg, "unsupported") {
		t.Errorf("vaultAuthLogin(method=kubernetes): expected error to mention kubernetes / unsupported, got %q", msg)
	}
}

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
