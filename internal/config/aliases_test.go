package config

import (
	"log/slog"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// saveAndRestoreAliases returns a cleanup function that restores configAliases
// to its state at the time of the call.
func saveAndRestoreAliases(t *testing.T) {
	t.Helper()
	original := make(map[string]configAlias, len(configAliases))
	for k, v := range configAliases {
		original[k] = v
	}
	t.Cleanup(func() {
		configAliases = original
	})
}

// TestConfigAliases_OldKeyMigrated verifies that when only the deprecated key
// is set, applyConfigAliases copies its value to the new key.
func TestConfigAliases_OldKeyMigrated(t *testing.T) {
	saveAndRestoreAliases(t)

	configAliases["old.key"] = configAlias{
		NewKey:       "new.key",
		DeprecatedIn: "v0.9.0",
		RemovedIn:    "v0.11.0",
	}

	v := viper.New()
	v.Set("old.key", "migrated-value")

	applyConfigAliases(v, slog.Default())

	assert.Equal(t, "migrated-value", v.Get("new.key"),
		"new.key should receive the value from old.key after migration")
}

// TestConfigAliases_NewKeyPrecedence verifies that when both old and new keys
// are set, the new key's value is preserved and not overwritten by the old one.
func TestConfigAliases_NewKeyPrecedence(t *testing.T) {
	saveAndRestoreAliases(t)

	configAliases["old.key"] = configAlias{
		NewKey:       "new.key",
		DeprecatedIn: "v0.9.0",
		RemovedIn:    "v0.11.0",
	}

	v := viper.New()
	v.Set("old.key", "old-value")
	v.Set("new.key", "new-value")

	applyConfigAliases(v, slog.Default())

	assert.Equal(t, "new-value", v.Get("new.key"),
		"new.key value must not be overwritten by old.key when both are set")
}

// TestConfigAliases_CircularDetection verifies that validateAliases returns an
// error when two alias entries form a cycle (a -> b, b -> a).
func TestConfigAliases_CircularDetection(t *testing.T) {
	saveAndRestoreAliases(t)

	configAliases["a"] = configAlias{NewKey: "b", DeprecatedIn: "v0.9.0", RemovedIn: "v0.11.0"}
	configAliases["b"] = configAlias{NewKey: "a", DeprecatedIn: "v0.9.0", RemovedIn: "v0.11.0"}

	err := validateAliases()
	require.Error(t, err, "validateAliases should return an error for a circular alias chain")
}
