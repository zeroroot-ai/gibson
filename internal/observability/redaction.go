// Package observability provides logging, metrics, and tracing capabilities for Gibson.
package observability

import "strings"

// SensitiveFields defines the set of field names that should be redacted in logs.
// Keys are lowercase with underscores removed for case-insensitive matching.
var SensitiveFields = map[string]struct{}{
	"password":      {},
	"secret":        {},
	"token":         {},
	"apikey":        {},
	"api_key":       {},
	"credential":    {},
	"authorization": {},
	"bearer":        {},
	"privatekey":    {},
	"private_key":   {},
	"secretkey":     {},
	"prompt":        {},
	"prompts":       {},

	// LLM provider credential keys (cfg.Extra map keys from each provider's
	// CredentialSchema). Each entry is the post-normalisation form
	// (lowercased, underscores removed) of the canonical key the resolver
	// reads. Adding a new provider with Extra credentials? Append here AND
	// to providers.redactCredentialKeys().
	"awsaccesskeyid":      {}, // Bedrock
	"awssecretaccesskey":  {}, // Bedrock
	"awssessiontoken":     {}, // Bedrock
	"cloudflareaccountid": {}, // Cloudflare (identifier — redact defensively)
	"cloudflareapitoken":  {}, // Cloudflare
	"cohereapikey":        {}, // Cohere (typed alias)
	"ernieaccesskey":      {}, // ERNIE
	"erniesecretkey":      {}, // ERNIE
	"huggingfaceapitoken": {}, // HuggingFace
	"mistralapikey":       {}, // Mistral (typed alias)
	"maritacaapikey":      {}, // Maritaca (typed alias)
	"watsonxapikey":       {}, // WatsonX
	"watsonxprojectid":    {}, // WatsonX (project identifier — redact defensively)
}

// Redact takes slog-style key-value pairs and redacts sensitive values.
// It expects args to contain alternating keys (strings) and values.
// If a key matches a sensitive field name (case-insensitive, ignoring underscores),
// the corresponding value is replaced with "[REDACTED]".
//
// Example:
//
//	args := []any{"user", "alice", "password", "secret123", "count", 42}
//	redacted := Redact(args)
//	// Returns: []any{"user", "alice", "password", "[REDACTED]", "count", 42}
//
// Handles edge cases:
//   - Odd-length args (missing value for last key): returns args unchanged
//   - Non-string keys: skips redaction for that pair
//   - Nil args: returns nil
//   - Empty args: returns empty slice
func Redact(args []any) []any {
	if args == nil {
		return nil
	}

	if len(args) == 0 {
		return args
	}

	// If args has odd length, return as-is (malformed key-value pairs)
	if len(args)%2 != 0 {
		return args
	}

	// Create a copy to avoid modifying the original
	result := make([]any, len(args))
	copy(result, args)

	// Process pairs
	for i := 0; i < len(result); i += 2 {
		key, ok := result[i].(string)
		if !ok {
			// Not a string key, skip this pair
			continue
		}

		// Normalize key: lowercase and remove underscores
		normalizedKey := normalizeFieldName(key)

		// Check if this is a sensitive field
		if _, isSensitive := SensitiveFields[normalizedKey]; isSensitive {
			result[i+1] = "[REDACTED]"
		}
	}

	return result
}

// TruncateString truncates a string to maxLen characters, adding "..." if truncated.
// If the string is already shorter than or equal to maxLen, it's returned unchanged.
// For maxLen < 4, truncation happens without ellipsis to avoid overflow.
//
// Example:
//
//	TruncateString("very long string here", 10)  // Returns: "very lo..."
//	TruncateString("short", 10)                   // Returns: "short"
//	TruncateString("test", 2)                     // Returns: "te"
//	TruncateString("", 10)                        // Returns: ""
func TruncateString(s string, maxLen int) string {
	if s == "" {
		return ""
	}

	if len(s) <= maxLen {
		return s
	}

	// For very short maxLen, just truncate without ellipsis
	if maxLen < 4 {
		return s[:maxLen]
	}

	// Truncate and add ellipsis
	return s[:maxLen-3] + "..."
}

// RedactToken partially redacts a token by showing only the first and last 4 characters.
// This allows for token identification while keeping the sensitive parts hidden.
//
// Example:
//
//	RedactToken("sk_live_abc123def456ghi789jkl")  // Returns: "sk_l***l789"
//	RedactToken("short")                           // Returns: "[REDACTED]"
//	RedactToken("")                                // Returns: "[REDACTED]"
//
// Tokens shorter than 10 characters are completely redacted to avoid exposing
// too much of the original value.
func RedactToken(token string) string {
	if token == "" {
		return "[REDACTED]"
	}

	if len(token) < 10 {
		return "[REDACTED]"
	}

	// Show first 4 and last 4 characters
	return token[:4] + "***" + token[len(token)-4:]
}

// normalizeFieldName converts a field name to lowercase and removes underscores
// for case-insensitive comparison with sensitive field names.
func normalizeFieldName(field string) string {
	normalized := strings.ToLower(field)
	normalized = strings.ReplaceAll(normalized, "_", "")
	return normalized
}
