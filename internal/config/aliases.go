package config

import (
	"fmt"
	"log/slog"

	"github.com/spf13/viper"
)

// configAlias maps a deprecated configuration key to its replacement.
type configAlias struct {
	NewKey       string
	DeprecatedIn string
	RemovedIn    string
}

// configAliases maps deprecated config keys to their aliases.
// Example:
//
//	"auth.enabled": {NewKey: "auth.mode", DeprecatedIn: "v0.9.0", RemovedIn: "v0.11.0"}
var configAliases = map[string]configAlias{}

// applyConfigAliases checks for deprecated configuration keys and migrates them.
// If both old and new keys are set, the new key takes precedence and a warning is logged.
// If only the old key is set, its value is copied to the new key with a warning.
func applyConfigAliases(v *viper.Viper, logger *slog.Logger) {
	for oldKey, alias := range configAliases {
		if !v.IsSet(oldKey) {
			continue
		}
		if v.IsSet(alias.NewKey) {
			logger.Warn("deprecated config key ignored; new key takes precedence",
				"old_key", oldKey,
				"new_key", alias.NewKey,
				"deprecated_in", alias.DeprecatedIn,
			)
			continue
		}
		logger.Warn("deprecated config key used; migrate to new key",
			"old_key", oldKey,
			"new_key", alias.NewKey,
			"deprecated_in", alias.DeprecatedIn,
			"removed_in", alias.RemovedIn,
		)
		v.Set(alias.NewKey, v.Get(oldKey))
	}
}

// validateAliases checks for circular references in the alias map.
func validateAliases() error {
	for oldKey, alias := range configAliases {
		if _, circular := configAliases[alias.NewKey]; circular {
			return fmt.Errorf("circular config alias: %q -> %q -> ...", oldKey, alias.NewKey)
		}
	}
	return nil
}
