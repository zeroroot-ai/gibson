package config

import (
	"fmt"
	"os"
	"strings"
)

// Mode is the deployment mode of the Gibson daemon.
//
// It controls security-sensitive runtime behaviours such as localhost-trust
// bypass acceptance, callback-listener bind-address validation, and the
// strictness of tenant-context resolution.
//
// Phase 1 default: ModeSelfhost (preserves current behaviour for existing
// self-hosted deployments while requiring SaaS deploys to set GIBSON_MODE=saas
// explicitly). Phase 5 will enforce stricter defaults when Mode=ModeSaaS.
type Mode int

const (
	// ModeUnset is the zero value — only ever present as an intermediate state
	// before config loading resolves the env var. Callers should never see it
	// because loadMode() falls back to ModeSelfhost on empty/unset input.
	ModeUnset Mode = iota

	// ModeSaaS is the Gibson SaaS control-plane mode (api.zero-day.ai).
	// Security-critical gates (TrustLocalhost refusal, 0.0.0.0 bind refusal,
	// SPIFFE-only callback auth) are enforced in this mode. Set via
	// GIBSON_MODE=saas.
	ModeSaaS

	// ModeSelfhost is the self-hosted on-premises / cloud-owned mode.
	// Security gates emit prominent warnings but do not fail startup. This is
	// the default when GIBSON_MODE is unset or empty, preserving the current
	// daemon behaviour for existing deployments.
	ModeSelfhost

	// ModeDev is the local development mode.
	// All security gates are advisory-only; unsafe binds and localhost trust are
	// permitted with audit-log annotations. Never use in production.
	ModeDev
)

// String returns the canonical lowercase string for the mode,
// matching the values accepted by ParseMode.
func (m Mode) String() string {
	switch m {
	case ModeSaaS:
		return "saas"
	case ModeSelfhost:
		return "selfhost"
	case ModeDev:
		return "dev"
	default:
		return "unset"
	}
}

// ParseMode parses a mode string case-insensitively and returns the
// corresponding Mode constant.
//
// Accepted values (case-insensitive): "saas", "selfhost", "dev".
// Empty string returns an error — callers that need a default should use
// loadMode(), which maps empty to ModeSelfhost.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "saas":
		return ModeSaaS, nil
	case "selfhost":
		return ModeSelfhost, nil
	case "dev":
		return ModeDev, nil
	case "":
		return ModeUnset, fmt.Errorf("config: GIBSON_MODE is empty; valid values are saas, selfhost, dev")
	default:
		return ModeUnset, fmt.Errorf("config: unrecognised GIBSON_MODE value %q; valid values are saas, selfhost, dev", s)
	}
}

// loadMode reads GIBSON_MODE from the environment and returns the resolved
// Mode. When the variable is unset or empty the default is ModeSelfhost, which
// preserves the existing daemon behaviour for self-hosted deployments.
//
// Returns an error only when the variable is set to an unrecognised value.
func loadMode() (Mode, error) {
	raw := os.Getenv("GIBSON_MODE")
	if raw == "" {
		return ModeSelfhost, nil
	}
	m, err := ParseMode(raw)
	if err != nil {
		return ModeUnset, err
	}
	return m, nil
}

// loadStrictTenant reads GIBSON_STRICT_TENANT from the environment and returns
// the resolved bool. Accepts "1", "true", "yes" (case-insensitive) as true;
// empty string or "0", "false", "no" as false. Any other value is a config
// load error.
//
// Default (unset / empty): false — preserves current (non-strict) behaviour in
// Phase 1. Phase 5 will flip the default and remove this flag.
func loadStrictTenant() (bool, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("GIBSON_STRICT_TENANT")))
	switch raw {
	case "", "0", "false", "no":
		return false, nil
	case "1", "true", "yes":
		return true, nil
	default:
		return false, fmt.Errorf(
			"config: invalid GIBSON_STRICT_TENANT value %q; accepted values are 1/true/yes (enable) or 0/false/no/empty (disable)",
			os.Getenv("GIBSON_STRICT_TENANT"),
		)
	}
}
