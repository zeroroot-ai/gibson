// Package checkpoint — secret_redact.go
//
// Walks a JSON-decoded checkpoint payload (working memory, mission memory)
// and replaces secret-bearing values with the literal string
// "<redacted:secret>". Spec 4 R14.5, R15.6.
//
// A "secret-bearing field" is any whose key matches one of the patterns
// below, OR whose stored value carries a vault-resolved hint
// (`"source": "vault"` or string prefixed with `vault:`).
//
//   - *[Pp]assword*
//   - *[Tt]oken*
//   - *[Ss]ecret*
//   - *[Cc]redential*
//   - *[Aa]piKey* / *[Aa]pi_key*
//
// Walker is allocation-light: rewrites the input map in place. If the input
// shape is unrecognised (nil, non-map JSON), the walker returns the bytes
// untouched so non-redactable payloads still serialize cleanly.
//
// The handler-side decision of whether to redact (caller is platform_operator
// or not) lives in the daemon API package. This file is policy-only.
package checkpoint

import (
	"encoding/json"
	"strings"
)

// RedactedPlaceholder is the literal string substituted in for any
// secret-bearing field's value.
const RedactedPlaceholder = "<redacted:secret>"

// RedactSecretsInJSONBytes walks the JSON-encoded `data`, replacing every
// secret-bearing field's value with RedactedPlaceholder, then re-marshals.
// Returns the original bytes if `data` is empty or fails to parse — the
// caller should never assume bytes are JSON; non-JSON payloads pass through.
//
// This is the canonical entry point for working_memory + mission_memory
// redaction in GetCheckpoint and DiffCheckpoints.
func RedactSecretsInJSONBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		// Not JSON — return as-is. The handler still wraps the value in a
		// MemoryKeyDelta `before/after`; non-JSON payloads (e.g., msgpack
		// bytes) are not rewriteable by name and ship as opaque blobs.
		return data
	}
	walked := redactValue(v, "")
	out, err := json.Marshal(walked)
	if err != nil {
		// Should not happen — Marshal of a value we just Unmarshalled.
		// Fail open to the original bytes rather than corrupt the response.
		return data
	}
	return out
}

// RedactSecretsInMap is the in-place variant for callers that already hold
// a parsed map[string]any. Returns the same map for convenience.
func RedactSecretsInMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	for k, v := range m {
		m[k] = redactValue(v, k)
	}
	return m
}

// IsSecretKey reports whether a field name matches the secret-bearing
// pattern set. Exported so that callers can pre-filter delta keys.
func IsSecretKey(key string) bool {
	if key == "" {
		return false
	}
	low := strings.ToLower(key)
	switch {
	case strings.Contains(low, "password"):
		return true
	case strings.Contains(low, "token"):
		return true
	case strings.Contains(low, "secret"):
		return true
	case strings.Contains(low, "credential"):
		return true
	case strings.Contains(low, "apikey"):
		return true
	case strings.Contains(low, "api_key"):
		return true
	case strings.Contains(low, "private_key"):
		return true
	case strings.Contains(low, "privatekey"):
		return true
	}
	return false
}

// redactValue recursively walks an interface{} produced by json.Unmarshal,
// substituting RedactedPlaceholder when (a) the parent key matches the
// secret pattern, or (b) the value is itself a vault-resolved hint
// (string prefixed with "vault:" or a map carrying `"source": "vault"`).
func redactValue(v any, parentKey string) any {
	switch x := v.(type) {
	case map[string]any:
		// "source: vault" annotation marks the entire object as vault-resolved.
		if src, ok := x["source"].(string); ok && strings.EqualFold(src, "vault") {
			return RedactedPlaceholder
		}
		for k, child := range x {
			x[k] = redactValue(child, k)
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = redactValue(child, parentKey)
		}
		return x
	case string:
		if IsSecretKey(parentKey) {
			return RedactedPlaceholder
		}
		if strings.HasPrefix(x, "vault:") {
			return RedactedPlaceholder
		}
		return x
	default:
		// Numbers, bools, nil — only redact when the parent key flagged it.
		if IsSecretKey(parentKey) {
			return RedactedPlaceholder
		}
		return v
	}
}
