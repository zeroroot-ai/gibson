// Package admin — helpers.go
//
// Small private utilities shared across the admin handlers in this package.
package admin

import "encoding/json"

// jsonUnmarshalToStringMap decodes raw into out, copying each top-level
// scalar field as a string. Nested objects/arrays are stringified via their
// raw JSON encoding to keep the helper allocation-light.
//
// Returns an error only when raw is not parseable JSON. Empty raw yields an
// empty map and no error.
func jsonUnmarshalToStringMap(raw []byte, out map[string]string) error {
	if len(raw) == 0 {
		return nil
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	for k, v := range generic {
		// Try to unmarshal as a string first; if it isn't a string, keep
		// the raw JSON encoding (without enclosing quotes when it was a
		// scalar).
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			out[k] = s
			continue
		}
		out[k] = string(v)
	}
	return nil
}
