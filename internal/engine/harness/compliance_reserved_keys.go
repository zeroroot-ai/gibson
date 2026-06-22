package harness

// ReservedKeyValidator enforces the closed vocabularies for reserved tag
// keys declared in the taxonomy foundation spec (core/sdk/taxonomy/core.yaml
// § reserved_keys). Currently 4 reserved keys: env, data_class, residency,
// legal_hold.
//
// The vocabulary lists are hardcoded here because the taxonomy generator
// does not yet emit a reserved-keys module. When it does, this file should
// be replaced with a shim that delegates to the generated constants.
//
// Design: O(1) lookup via maps. No hot reload — changing a vocabulary
// requires a daemon restart.
type ReservedKeyValidator struct {
	vocabularies map[string]map[string]bool
}

// NewReservedKeyValidator returns a validator populated with the v1
// vocabularies from the foundation spec.
func NewReservedKeyValidator() *ReservedKeyValidator {
	return &ReservedKeyValidator{
		vocabularies: map[string]map[string]bool{
			"env": {
				"prod":    true,
				"staging": true,
				"dev":     true,
				"test":    true,
			},
			"data_class": {
				"pii":      true,
				"phi":      true,
				"pci":      true,
				"secret":   true,
				"internal": true,
				"public":   true,
			},
			"residency": {
				"us":     true,
				"eu":     true,
				"apac":   true,
				"global": true,
			},
			"legal_hold": {
				"true":  true,
				"false": true,
			},
		},
	}
}

// IsReserved reports whether the given key has a closed vocabulary.
func (v *ReservedKeyValidator) IsReserved(key string) bool {
	_, ok := v.vocabularies[key]
	return ok
}

// IsValid reports whether the (key, value) pair is valid. Non-reserved
// keys are always valid (they have no closed vocabulary). Reserved keys
// must have a value in their vocabulary.
func (v *ReservedKeyValidator) IsValid(key, value string) bool {
	vocab, ok := v.vocabularies[key]
	if !ok {
		return true
	}
	return vocab[value]
}

// ReservedKeys returns the set of reserved key names.
func (v *ReservedKeyValidator) ReservedKeys() []string {
	out := make([]string, 0, len(v.vocabularies))
	for k := range v.vocabularies {
		out = append(out, k)
	}
	return out
}
