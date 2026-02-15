package report

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Redactor handles sensitive data redaction in reports with consistent replacement,
// audit logging, and optional reversible redaction.
type Redactor interface {
	// Redact removes sensitive data from content
	Redact(content []byte) []byte

	// RedactString removes sensitive data from string content
	RedactString(content string) string

	// RedactJSON redacts sensitive fields from JSON data
	RedactJSON(data map[string]any) map[string]any

	// AddPattern adds a custom redaction pattern
	AddPattern(name string, pattern *regexp.Regexp, replacement string)

	// RemovePattern removes a custom redaction pattern
	RemovePattern(name string)

	// AuditLog returns what was redacted (without original values by default)
	AuditLog() []RedactionEntry

	// SetAuditMode controls whether original values are stored in audit log
	SetAuditMode(includeOriginals bool)

	// Reset clears the redaction state and audit log
	Reset()
}

// RedactionEntry represents a single redaction operation
type RedactionEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Location    string    `json:"location"`     // Field or pattern name
	Pattern     string    `json:"pattern"`      // Pattern name that matched
	Original    string    `json:"original"`     // Only populated in audit mode
	Replacement string    `json:"replacement"`  // What it was replaced with
	Hash        string    `json:"hash"`         // SHA256 hash of original
}

// DefaultRedactor implements the Redactor interface with pattern-based redaction
type DefaultRedactor struct {
	patterns        map[string]*redactionPattern
	patternsMu      sync.RWMutex
	auditLog        []RedactionEntry
	auditMu         sync.Mutex
	includeOriginal bool
	// consistentRedaction ensures same value gets same replacement
	replacementCache   map[string]string
	replacementCacheMu sync.RWMutex
	// Optional encryption key for reversible redaction
	encryptionKey []byte
}

// redactionPattern holds a compiled pattern and its replacement strategy
type redactionPattern struct {
	name        string
	pattern     *regexp.Regexp
	replacement string
	maskStyle   MaskStyle
}

// MaskStyle defines how redacted values should be displayed
type MaskStyle int

const (
	// MaskStyleFixed replaces with a fixed string like "[REDACTED]"
	MaskStyleFixed MaskStyle = iota
	// MaskStyleConsistent replaces with consistent hash-based replacement
	MaskStyleConsistent
	// MaskStylePartial shows first/last chars with middle masked
	MaskStylePartial
)

// NewDefaultRedactor creates a new redactor with default sensitive data patterns
func NewDefaultRedactor() *DefaultRedactor {
	r := &DefaultRedactor{
		patterns:         make(map[string]*redactionPattern),
		auditLog:         make([]RedactionEntry, 0),
		includeOriginal:  false,
		replacementCache: make(map[string]string),
	}

	// Add default patterns (optimized to avoid catastrophic backtracking)
	r.addDefaultPatterns()

	return r
}

// NewRedactorWithKey creates a redactor with encryption key for reversible redaction
func NewRedactorWithKey(key []byte) *DefaultRedactor {
	r := NewDefaultRedactor()
	r.encryptionKey = key
	return r
}

// addDefaultPatterns adds built-in sensitive data patterns
func (r *DefaultRedactor) addDefaultPatterns() {
	// API Keys - various common formats
	r.patterns["api_key_openai"] = &redactionPattern{
		name:        "api_key_openai",
		pattern:     regexp.MustCompile(`\bsk-[a-zA-Z0-9]{40,60}\b`),
		replacement: "[REDACTED-API-KEY]",
		maskStyle:   MaskStyleConsistent,
	}

	r.patterns["api_key_aws"] = &redactionPattern{
		name:        "api_key_aws",
		pattern:     regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
		replacement: "[REDACTED-AWS-KEY]",
		maskStyle:   MaskStyleConsistent,
	}

	r.patterns["api_key_generic"] = &redactionPattern{
		name:    "api_key_generic",
		pattern: regexp.MustCompile(`(?i)(['"]?)(api[_-]?key|apikey)(['"]?\s*[:=]\s*)(['"]?)([a-zA-Z0-9\-_]{20,})(['"]?)`),
		replacement: "${1}${2}${3}${4}[REDACTED-API-KEY]${6}",
		maskStyle:   MaskStyleFixed,
	}

	// Bearer Tokens (limit length to avoid backtracking)
	r.patterns["bearer_token"] = &redactionPattern{
		name:        "bearer_token",
		pattern:     regexp.MustCompile(`(?i)\bbearer\s+([a-zA-Z0-9\-_\.=]{20,500})\b`),
		replacement: "Bearer [REDACTED-TOKEN]",
		maskStyle:   MaskStyleConsistent,
	}

	// JWT Tokens (matches standard JWT structure)
	r.patterns["jwt"] = &redactionPattern{
		name:        "jwt",
		pattern:     regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b`),
		replacement: "[REDACTED-JWT]",
		maskStyle:   MaskStyleConsistent,
	}

	// Passwords in config/JSON
	r.patterns["password_field"] = &redactionPattern{
		name:    "password_field",
		pattern: regexp.MustCompile(`(?i)(['"]?)(password|passwd|pwd)(['"]?\s*[:=]\s*)(['"]?)([^\s"']{4,50})(['"]?)`),
		replacement: "${1}${2}${3}${4}[REDACTED-PASSWORD]${6}",
		maskStyle:   MaskStyleFixed,
	}

	// Secrets
	r.patterns["secret_field"] = &redactionPattern{
		name:    "secret_field",
		pattern: regexp.MustCompile(`(?i)(['"]?)(secret|private[_-]?key|client[_-]?secret)(['"]?\s*[:=]\s*)(['"]?)([^\s"']{8,100})(['"]?)`),
		replacement: "${1}${2}${3}${4}[REDACTED-SECRET]${6}",
		maskStyle:   MaskStyleFixed,
	}

	// AWS Secret Access Key
	r.patterns["aws_secret"] = &redactionPattern{
		name:        "aws_secret",
		pattern:     regexp.MustCompile(`\b([a-zA-Z0-9/+=]{40})\b`),
		replacement: "[REDACTED-AWS-SECRET]",
		maskStyle:   MaskStyleConsistent,
	}

	// Credit Card Numbers (Luhn-friendly pattern)
	r.patterns["credit_card"] = &redactionPattern{
		name:        "credit_card",
		pattern:     regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`),
		replacement: "[REDACTED-CC]",
		maskStyle:   MaskStylePartial,
	}

	// Social Security Numbers
	r.patterns["ssn"] = &redactionPattern{
		name:        "ssn",
		pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		replacement: "[REDACTED-SSN]",
		maskStyle:   MaskStyleFixed,
	}

	// Private Keys (PEM format) - limited length to avoid backtracking
	r.patterns["private_key"] = &redactionPattern{
		name:        "private_key",
		pattern:     regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]{20,}?-----END[A-Z ]*PRIVATE KEY-----`),
		replacement: "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----",
		maskStyle:   MaskStyleFixed,
	}

	// GitHub Tokens
	r.patterns["github_token"] = &redactionPattern{
		name:        "github_token",
		pattern:     regexp.MustCompile(`\b(gh[pousr]_[a-zA-Z0-9]{36,})\b`),
		replacement: "[REDACTED-GITHUB-TOKEN]",
		maskStyle:   MaskStyleConsistent,
	}

	// Google API Keys
	r.patterns["google_api_key"] = &redactionPattern{
		name:        "google_api_key",
		pattern:     regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		replacement: "[REDACTED-GOOGLE-KEY]",
		maskStyle:   MaskStyleConsistent,
	}

	// Slack Tokens
	r.patterns["slack_token"] = &redactionPattern{
		name:        "slack_token",
		pattern:     regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b`),
		replacement: "[REDACTED-SLACK-TOKEN]",
		maskStyle:   MaskStyleConsistent,
	}

	// Database Connection Strings (limited to avoid backtracking)
	r.patterns["db_connection"] = &redactionPattern{
		name:        "db_connection",
		pattern:     regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s'"]{5,200}`),
		replacement: "${1}://[REDACTED-DB-URL]",
		maskStyle:   MaskStyleFixed,
	}
}

// Redact removes sensitive data from byte content
func (r *DefaultRedactor) Redact(content []byte) []byte {
	return []byte(r.RedactString(string(content)))
}

// RedactString removes sensitive data from string content
func (r *DefaultRedactor) RedactString(content string) string {
	r.patternsMu.RLock()
	defer r.patternsMu.RUnlock()

	result := content

	// Apply each pattern
	for _, pattern := range r.patterns {
		matches := pattern.pattern.FindAllStringSubmatchIndex(result, -1)

		// Process matches in reverse to maintain index positions
		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			if len(match) < 2 {
				continue
			}

			// Extract the full match
			start, end := match[0], match[1]
			original := result[start:end]

			// Generate replacement based on mask style
			replacement := r.generateReplacement(original, pattern)

			// Log the redaction
			r.logRedaction(pattern.name, pattern.name, original, replacement)

			// Replace in result
			result = result[:start] + replacement + result[end:]
		}
	}

	return result
}

// RedactJSON redacts sensitive fields from JSON data
func (r *DefaultRedactor) RedactJSON(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}

	result := make(map[string]any, len(data))

	for key, value := range data {
		if r.isSensitiveKey(key) {
			// Redact the entire value
			result[key] = "[REDACTED]"
			r.logRedaction("json_field", key, fmt.Sprintf("%v", value), "[REDACTED]")
		} else {
			// Recursively process nested structures
			switch v := value.(type) {
			case map[string]any:
				result[key] = r.RedactJSON(v)
			case []any:
				result[key] = r.redactJSONArray(v)
			case string:
				// Apply string redaction patterns
				result[key] = r.RedactString(v)
			default:
				result[key] = value
			}
		}
	}

	return result
}

// redactJSONArray processes arrays recursively
func (r *DefaultRedactor) redactJSONArray(arr []any) []any {
	result := make([]any, len(arr))

	for i, item := range arr {
		switch v := item.(type) {
		case map[string]any:
			result[i] = r.RedactJSON(v)
		case []any:
			result[i] = r.redactJSONArray(v)
		case string:
			result[i] = r.RedactString(v)
		default:
			result[i] = item
		}
	}

	return result
}

// isSensitiveKey checks if a JSON key contains sensitive information
func (r *DefaultRedactor) isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "passwd", "pwd",
		"secret", "api_key", "apikey", "api-key",
		"token", "auth", "authorization", "bearer",
		"credential", "credentials",
		"private_key", "privatekey", "private-key",
		"session", "cookie",
		"access_token", "refresh_token",
		"client_secret", "client-secret",
		"encryption_key", "encryption-key",
	}

	lowerKey := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}

	return false
}

// generateReplacement creates a replacement based on mask style
func (r *DefaultRedactor) generateReplacement(original string, pattern *redactionPattern) string {
	switch pattern.maskStyle {
	case MaskStyleConsistent:
		return r.getConsistentReplacement(original, pattern.replacement)

	case MaskStylePartial:
		return r.partialMask(original)

	case MaskStyleFixed:
		fallthrough
	default:
		return pattern.replacement
	}
}

// getConsistentReplacement ensures the same value always gets the same replacement
func (r *DefaultRedactor) getConsistentReplacement(original string, baseReplacement string) string {
	// Check cache first
	r.replacementCacheMu.RLock()
	if cached, exists := r.replacementCache[original]; exists {
		r.replacementCacheMu.RUnlock()
		return cached
	}
	r.replacementCacheMu.RUnlock()

	// Generate consistent replacement using hash
	hash := sha256.Sum256([]byte(original))
	shortHash := hex.EncodeToString(hash[:4]) // First 8 chars of hex

	replacement := fmt.Sprintf("%s-%s", baseReplacement, shortHash)

	// Cache it
	r.replacementCacheMu.Lock()
	r.replacementCache[original] = replacement
	r.replacementCacheMu.Unlock()

	return replacement
}

// partialMask shows first and last characters with middle masked
func (r *DefaultRedactor) partialMask(original string) string {
	if len(original) <= 8 {
		return "[REDACTED]"
	}

	// Show first 4 and last 4 characters
	return fmt.Sprintf("%s****%s", original[:4], original[len(original)-4:])
}

// AddPattern adds a custom redaction pattern
func (r *DefaultRedactor) AddPattern(name string, pattern *regexp.Regexp, replacement string) {
	r.patternsMu.Lock()
	defer r.patternsMu.Unlock()

	r.patterns[name] = &redactionPattern{
		name:        name,
		pattern:     pattern,
		replacement: replacement,
		maskStyle:   MaskStyleFixed,
	}
}

// RemovePattern removes a custom redaction pattern
func (r *DefaultRedactor) RemovePattern(name string) {
	r.patternsMu.Lock()
	defer r.patternsMu.Unlock()

	delete(r.patterns, name)
}

// logRedaction adds an entry to the audit log
func (r *DefaultRedactor) logRedaction(location, pattern, original, replacement string) {
	r.auditMu.Lock()
	defer r.auditMu.Unlock()

	// Calculate hash of original value
	hash := sha256.Sum256([]byte(original))
	hashStr := hex.EncodeToString(hash[:])

	entry := RedactionEntry{
		Timestamp:   time.Now(),
		Location:    location,
		Pattern:     pattern,
		Replacement: replacement,
		Hash:        hashStr,
	}

	// Only include original if in audit mode
	if r.includeOriginal {
		entry.Original = original
	}

	r.auditLog = append(r.auditLog, entry)
}

// AuditLog returns what was redacted
func (r *DefaultRedactor) AuditLog() []RedactionEntry {
	r.auditMu.Lock()
	defer r.auditMu.Unlock()

	// Return a copy to prevent external modifications
	log := make([]RedactionEntry, len(r.auditLog))
	copy(log, r.auditLog)
	return log
}

// SetAuditMode controls whether original values are stored in audit log
func (r *DefaultRedactor) SetAuditMode(includeOriginals bool) {
	r.auditMu.Lock()
	defer r.auditMu.Unlock()

	r.includeOriginal = includeOriginals
}

// Reset clears the redaction state and audit log
func (r *DefaultRedactor) Reset() {
	r.auditMu.Lock()
	r.auditLog = make([]RedactionEntry, 0)
	r.auditMu.Unlock()

	r.replacementCacheMu.Lock()
	r.replacementCache = make(map[string]string)
	r.replacementCacheMu.Unlock()
}

// ExportAuditLog exports the audit log as JSON
func (r *DefaultRedactor) ExportAuditLog() ([]byte, error) {
	log := r.AuditLog()
	return json.MarshalIndent(log, "", "  ")
}

// GetRedactionStats returns statistics about redactions performed
func (r *DefaultRedactor) GetRedactionStats() RedactionStats {
	r.auditMu.Lock()
	defer r.auditMu.Unlock()

	stats := RedactionStats{
		TotalRedactions: len(r.auditLog),
		ByPattern:       make(map[string]int),
	}

	for _, entry := range r.auditLog {
		stats.ByPattern[entry.Pattern]++
	}

	return stats
}

// RedactionStats contains statistics about redaction operations
type RedactionStats struct {
	TotalRedactions int            `json:"total_redactions"`
	ByPattern       map[string]int `json:"by_pattern"`
}

// EncryptValue encrypts a value for reversible redaction (if encryption key is set)
func (r *DefaultRedactor) EncryptValue(value string) (string, error) {
	if r.encryptionKey == nil {
		return "", fmt.Errorf("encryption key not set")
	}

	// For simplicity, using base64 encoding with a marker
	// In production, use proper AES encryption
	encrypted := base64.StdEncoding.EncodeToString([]byte(value))
	return fmt.Sprintf("[ENCRYPTED:%s]", encrypted), nil
}

// DecryptValue decrypts a reversibly redacted value (if encryption key is set)
func (r *DefaultRedactor) DecryptValue(encrypted string) (string, error) {
	if r.encryptionKey == nil {
		return "", fmt.Errorf("encryption key not set")
	}

	// Extract the encrypted payload
	if !strings.HasPrefix(encrypted, "[ENCRYPTED:") || !strings.HasSuffix(encrypted, "]") {
		return "", fmt.Errorf("invalid encrypted format")
	}

	payload := encrypted[11 : len(encrypted)-1]
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to decode: %w", err)
	}

	return string(decoded), nil
}
