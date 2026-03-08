package resolver

import (
	"fmt"
	"os"
	"regexp"
)

// MergeStrategy defines how configuration values should be merged.
type MergeStrategy string

const (
	// MergeStrategyReplace replaces the entire value with the new one
	MergeStrategyReplace MergeStrategy = "replace"

	// MergeStrategyDeepMerge recursively merges nested objects
	MergeStrategyDeepMerge MergeStrategy = "deep_merge"

	// MergeStrategyArrayAppend appends new array elements to existing ones
	MergeStrategyArrayAppend MergeStrategy = "array_append"
)

// ConfigMerger provides methods for merging configuration objects.
type ConfigMerger interface {
	// Merge merges two configuration maps using the specified strategy.
	Merge(base, override map[string]interface{}, strategy MergeStrategy) map[string]interface{}

	// MergeWithEnvExpansion merges and expands environment variables in the result.
	MergeWithEnvExpansion(base, override map[string]interface{}, strategy MergeStrategy) map[string]interface{}
}

// DefaultConfigMerger is the standard implementation of ConfigMerger.
type DefaultConfigMerger struct {
	// AllowMissingEnvVars determines if missing env vars should cause errors or use defaults
	AllowMissingEnvVars bool
}

// NewConfigMerger creates a new configuration merger.
func NewConfigMerger() ConfigMerger {
	return &DefaultConfigMerger{
		AllowMissingEnvVars: true,
	}
}

// Merge merges two configuration maps using the specified strategy.
// The base map provides default values, override provides overriding values.
func (m *DefaultConfigMerger) Merge(base, override map[string]interface{}, strategy MergeStrategy) map[string]interface{} {
	if base == nil {
		base = make(map[string]interface{})
	}
	if override == nil {
		return copyMap(base)
	}

	switch strategy {
	case MergeStrategyReplace:
		return m.mergeReplace(base, override)
	case MergeStrategyDeepMerge:
		return m.mergeDeep(base, override)
	case MergeStrategyArrayAppend:
		return m.mergeArrayAppend(base, override)
	default:
		// Default to deep merge
		return m.mergeDeep(base, override)
	}
}

// MergeWithEnvExpansion merges and expands environment variables.
func (m *DefaultConfigMerger) MergeWithEnvExpansion(base, override map[string]interface{}, strategy MergeStrategy) map[string]interface{} {
	result := m.Merge(base, override, strategy)
	return m.expandEnvVars(result)
}

// mergeReplace performs a simple replace merge: override completely replaces base.
func (m *DefaultConfigMerger) mergeReplace(base, override map[string]interface{}) map[string]interface{} {
	// Return a copy of override
	return copyMap(override)
}

// mergeDeep performs a deep merge: recursively merges nested objects.
func (m *DefaultConfigMerger) mergeDeep(base, override map[string]interface{}) map[string]interface{} {
	result := copyMap(base)

	for key, overrideVal := range override {
		baseVal, existsInBase := result[key]

		if !existsInBase {
			// Key doesn't exist in base, just add it
			result[key] = deepCopy(overrideVal)
			continue
		}

		// Both base and override have this key - merge based on type
		baseMap, baseIsMap := baseVal.(map[string]interface{})
		overrideMap, overrideIsMap := overrideVal.(map[string]interface{})

		if baseIsMap && overrideIsMap {
			// Both are maps - recursively merge
			result[key] = m.mergeDeep(baseMap, overrideMap)
		} else {
			// Different types or not maps - override wins
			result[key] = deepCopy(overrideVal)
		}
	}

	return result
}

// mergeArrayAppend merges arrays by appending override elements to base elements.
func (m *DefaultConfigMerger) mergeArrayAppend(base, override map[string]interface{}) map[string]interface{} {
	result := copyMap(base)

	for key, overrideVal := range override {
		baseVal, existsInBase := result[key]

		if !existsInBase {
			// Key doesn't exist in base, just add it
			result[key] = deepCopy(overrideVal)
			continue
		}

		// Check if both are arrays
		baseArray, baseIsArray := baseVal.([]interface{})
		overrideArray, overrideIsArray := overrideVal.([]interface{})

		if baseIsArray && overrideIsArray {
			// Both are arrays - append override to base
			merged := make([]interface{}, 0, len(baseArray)+len(overrideArray))
			merged = append(merged, baseArray...)
			merged = append(merged, overrideArray...)
			result[key] = merged
		} else {
			// Not both arrays - override wins
			result[key] = deepCopy(overrideVal)
		}
	}

	return result
}

// expandEnvVars recursively expands environment variables in a configuration map.
// Supports ${VAR} and ${VAR:-default} syntax.
func (m *DefaultConfigMerger) expandEnvVars(config map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, val := range config {
		result[key] = m.expandValue(val)
	}

	return result
}

// expandValue expands environment variables in a single value.
func (m *DefaultConfigMerger) expandValue(val interface{}) interface{} {
	switch v := val.(type) {
	case string:
		return m.expandString(v)
	case map[string]interface{}:
		return m.expandEnvVars(v)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = m.expandValue(item)
		}
		return result
	default:
		// Other types (int, bool, etc.) are returned as-is
		return v
	}
}

// expandString expands environment variables in a string.
// Supports ${VAR} and ${VAR:-default} syntax.
func (m *DefaultConfigMerger) expandString(s string) string {
	// Regular expression to match ${VAR} or ${VAR:-default}
	re := regexp.MustCompile(`\$\{([^}:]+)(?::(-?)([^}]*))?\}`)

	return re.ReplaceAllStringFunc(s, func(match string) string {
		// Extract variable name and default value
		matches := re.FindStringSubmatch(match)
		if len(matches) < 2 {
			return match
		}

		varName := matches[1]
		hasDefault := len(matches) > 3 && matches[2] == "-"
		defaultVal := ""
		if hasDefault && len(matches) > 3 {
			defaultVal = matches[3]
		}

		// Look up environment variable
		envVal, exists := os.LookupEnv(varName)
		if exists {
			return envVal
		}

		// Use default if provided
		if hasDefault {
			return defaultVal
		}

		// No default and variable not found
		if m.AllowMissingEnvVars {
			// Return original placeholder
			return match
		}

		// Return empty string if not allowing missing vars
		return ""
	})
}

// copyMap creates a shallow copy of a map.
func copyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}

	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// deepCopy creates a deep copy of a value.
func deepCopy(val interface{}) interface{} {
	switch v := val.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, val := range v {
			result[key] = deepCopy(val)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = deepCopy(item)
		}
		return result
	default:
		// Primitive types can be copied directly
		return v
	}
}

// MergeConfigs is a convenience function for merging configurations with default strategy.
func MergeConfigs(base, override map[string]interface{}) map[string]interface{} {
	merger := NewConfigMerger()
	return merger.Merge(base, override, MergeStrategyDeepMerge)
}

// MergeConfigsWithEnv is a convenience function for merging and expanding env vars.
func MergeConfigsWithEnv(base, override map[string]interface{}) map[string]interface{} {
	merger := NewConfigMerger()
	return merger.MergeWithEnvExpansion(base, override, MergeStrategyDeepMerge)
}

// ValidateMergeStrategy checks if a merge strategy string is valid.
func ValidateMergeStrategy(strategy string) error {
	switch MergeStrategy(strategy) {
	case MergeStrategyReplace, MergeStrategyDeepMerge, MergeStrategyArrayAppend:
		return nil
	default:
		return fmt.Errorf("invalid merge strategy: %s (must be 'replace', 'deep_merge', or 'array_append')", strategy)
	}
}

// ArrayMergeMode defines how arrays should be merged within deep merge strategy.
type ArrayMergeMode string

const (
	// ArrayMergeReplace replaces the entire array
	ArrayMergeReplace ArrayMergeMode = "replace"

	// ArrayMergeAppend appends new elements to existing array
	ArrayMergeAppend ArrayMergeMode = "append"

	// ArrayMergeMergeByKey merges array elements by a key field
	ArrayMergeMergeByKey ArrayMergeMode = "merge_by_key"
)

// AdvancedConfigMerger extends DefaultConfigMerger with more options.
type AdvancedConfigMerger struct {
	DefaultConfigMerger
	ArrayMode ArrayMergeMode
	MergeKey  string // Key field for ArrayMergeMergeByKey mode
}

// NewAdvancedConfigMerger creates a merger with advanced array handling.
func NewAdvancedConfigMerger(arrayMode ArrayMergeMode, mergeKey string) ConfigMerger {
	return &AdvancedConfigMerger{
		DefaultConfigMerger: DefaultConfigMerger{
			AllowMissingEnvVars: true,
		},
		ArrayMode: arrayMode,
		MergeKey:  mergeKey,
	}
}

// mergeDeep overrides the default deep merge to handle arrays specially.
func (m *AdvancedConfigMerger) mergeDeep(base, override map[string]interface{}) map[string]interface{} {
	result := copyMap(base)

	for key, overrideVal := range override {
		baseVal, existsInBase := result[key]

		if !existsInBase {
			result[key] = deepCopy(overrideVal)
			continue
		}

		// Check type combinations
		baseMap, baseIsMap := baseVal.(map[string]interface{})
		overrideMap, overrideIsMap := overrideVal.(map[string]interface{})
		baseArray, baseIsArray := baseVal.([]interface{})
		overrideArray, overrideIsArray := overrideVal.([]interface{})

		if baseIsMap && overrideIsMap {
			// Both maps - recursive merge
			result[key] = m.mergeDeep(baseMap, overrideMap)
		} else if baseIsArray && overrideIsArray {
			// Both arrays - use configured array merge mode
			result[key] = m.mergeArrays(baseArray, overrideArray)
		} else {
			// Different types - override wins
			result[key] = deepCopy(overrideVal)
		}
	}

	return result
}

// mergeArrays merges two arrays based on the configured mode.
func (m *AdvancedConfigMerger) mergeArrays(base, override []interface{}) []interface{} {
	switch m.ArrayMode {
	case ArrayMergeReplace:
		return deepCopy(override).([]interface{})

	case ArrayMergeAppend:
		result := make([]interface{}, 0, len(base)+len(override))
		result = append(result, base...)
		result = append(result, override...)
		return result

	case ArrayMergeMergeByKey:
		return m.mergeArraysByKey(base, override, m.MergeKey)

	default:
		// Default to replace
		return deepCopy(override).([]interface{})
	}
}

// mergeArraysByKey merges arrays by matching elements on a key field.
func (m *AdvancedConfigMerger) mergeArraysByKey(base, override []interface{}, keyField string) []interface{} {
	if keyField == "" {
		// No key specified, fall back to append
		return m.mergeArrays(base, override)
	}

	// Build a map of base elements by key
	baseMap := make(map[interface{}]map[string]interface{})
	for _, item := range base {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if keyVal, hasKey := itemMap[keyField]; hasKey {
				baseMap[keyVal] = itemMap
			}
		}
	}

	// Merge override elements
	result := make([]interface{}, 0, len(base)+len(override))
	merged := make(map[interface{}]bool)

	// First, add all base elements (possibly merged with override)
	for _, item := range base {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if keyVal, hasKey := itemMap[keyField]; hasKey {
				// Check if override has this key
				for _, overrideItem := range override {
					if overrideMap, ok := overrideItem.(map[string]interface{}); ok {
						if overrideKey, hasKey := overrideMap[keyField]; hasKey && overrideKey == keyVal {
							// Merge the two elements
							itemMap = m.mergeDeep(itemMap, overrideMap)
							merged[keyVal] = true
							break
						}
					}
				}
				result = append(result, itemMap)
			} else {
				result = append(result, item)
			}
		} else {
			result = append(result, item)
		}
	}

	// Add override elements that weren't merged
	for _, item := range override {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if keyVal, hasKey := itemMap[keyField]; hasKey {
				if !merged[keyVal] {
					result = append(result, deepCopy(itemMap))
				}
			} else {
				result = append(result, deepCopy(item))
			}
		} else {
			result = append(result, deepCopy(item))
		}
	}

	return result
}
