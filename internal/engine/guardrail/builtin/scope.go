package builtin

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
)

// ScopeValidatorConfig configures the scope validator
type ScopeValidatorConfig struct {
	AllowedDomains   []string // e.g., ["example.com", "*.api.example.com"]
	BlockedPaths     []string // e.g., ["/admin/*", "/internal/*"]
	RespectRobotsTxt bool     // Future: check robots.txt
}

// ScopeValidator validates that requests are within allowed scope
type ScopeValidator struct {
	config ScopeValidatorConfig
	name   string
}

// NewScopeValidator creates a new scope validator
func NewScopeValidator(config ScopeValidatorConfig) *ScopeValidator {
	return &ScopeValidator{
		config: config,
		name:   "scope-validator",
	}
}

// Name returns the name of the guardrail
func (s *ScopeValidator) Name() string {
	return s.name
}

// Type returns the type of guardrail
func (s *ScopeValidator) Type() guardrail.GuardrailType {
	return guardrail.GuardrailTypeScope
}

// CheckInput validates input against scope rules
func (s *ScopeValidator) CheckInput(ctx context.Context, input guardrail.GuardrailInput) (guardrail.GuardrailResult, error) {
	// Extract URL from TargetInfo if available
	if input.TargetInfo == nil {
		return guardrail.NewAllowResult(), nil
	}

	targetURL := input.TargetInfo.URL
	if targetURL == "" {
		// For now, if no URL is provided, we allow it
		return guardrail.NewAllowResult(), nil
	}

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return guardrail.NewBlockResult(fmt.Sprintf("invalid URL: %v", err)), nil
	}

	// Extract domain and path
	domain := parsedURL.Hostname()
	path := parsedURL.Path

	// Check domain against allowed domains
	if len(s.config.AllowedDomains) > 0 {
		if !s.isDomainAllowed(domain) {
			return guardrail.NewBlockResult(fmt.Sprintf("domain %s is not in allowed list", domain)), nil
		}
	}

	// Check path against blocked paths
	if len(s.config.BlockedPaths) > 0 {
		if s.isPathBlocked(path) {
			return guardrail.NewBlockResult(fmt.Sprintf("path %s matches blocked path pattern", path)), nil
		}
	}

	return guardrail.NewAllowResult(), nil
}

// CheckOutput allows all output (scope is about input requests)
func (s *ScopeValidator) CheckOutput(ctx context.Context, output guardrail.GuardrailOutput) (guardrail.GuardrailResult, error) {
	// Scope validation is typically only for input
	return guardrail.NewAllowResult(), nil
}

// isDomainAllowed checks if the domain matches any allowed domain pattern
func (s *ScopeValidator) isDomainAllowed(domain string) bool {
	for _, allowedDomain := range s.config.AllowedDomains {
		if s.matchesDomainPattern(domain, allowedDomain) {
			return true
		}
	}
	return false
}

// matchesDomainPattern checks if a domain matches a pattern
// Supports wildcards like *.example.com
func (s *ScopeValidator) matchesDomainPattern(domain, pattern string) bool {
	// Exact match
	if domain == pattern {
		return true
	}

	// Wildcard match
	if strings.HasPrefix(pattern, "*.") {
		// *.example.com should match api.example.com but also example.com
		suffix := pattern[1:] // Remove the * to get .example.com
		return strings.HasSuffix(domain, suffix)
	}

	return false
}

// isPathBlocked checks if the path matches any blocked path pattern
func (s *ScopeValidator) isPathBlocked(path string) bool {
	for _, blockedPath := range s.config.BlockedPaths {
		if s.matchesPathPattern(path, blockedPath) {
			return true
		}
	}
	return false
}

// matchesPathPattern checks if a path matches a pattern
// Supports wildcards like /admin/* (matches /admin/anything including nested paths)
func (s *ScopeValidator) matchesPathPattern(path, pattern string) bool {
	// Exact match
	if path == pattern {
		return true
	}

	// Handle /* wildcard pattern specially for recursive matching
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		// Match if path starts with prefix/ (e.g., /admin/ for /admin/*)
		return strings.HasPrefix(path, prefix+"/")
	}

	// Wildcard match using filepath.Match for other patterns
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false
	}

	return matched
}
