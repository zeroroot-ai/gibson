package transformers

import (
	"strings"

	"github.com/zeroroot-ai/gibson/internal/prompt"
)

// ScopeNarrower filters prompts to task-relevant content.
// It applies position filtering, ID exclusion, and keyword matching
// to reduce the prompt set to only what's relevant for the delegated task.
type ScopeNarrower struct {
	// AllowedPositions restricts prompts to these positions.
	// If empty, all positions are allowed.
	AllowedPositions []prompt.Position

	// ExcludeIDs removes prompts with these IDs from the result.
	ExcludeIDs []string

	// KeywordFilter only includes prompts whose content contains any of these keywords.
	// If empty, all prompts pass the keyword filter.
	// Keywords are matched case-insensitively.
	KeywordFilter []string
}

// NewScopeNarrower creates a new ScopeNarrower with default settings.
func NewScopeNarrower() *ScopeNarrower {
	return &ScopeNarrower{
		AllowedPositions: []prompt.Position{},
		ExcludeIDs:       []string{},
		KeywordFilter:    []string{},
	}
}

// Name returns the transformer name for logging.
func (s *ScopeNarrower) Name() string {
	return "ScopeNarrower"
}

// Transform filters prompts based on configured criteria.
func (s *ScopeNarrower) Transform(ctx *prompt.RelayContext, prompts []prompt.Prompt) ([]prompt.Prompt, error) {
	result := make([]prompt.Prompt, 0, len(prompts))

	for _, p := range prompts {
		// Apply filters
		if !s.passesPositionFilter(p) {
			continue
		}
		if !s.passesIDFilter(p) {
			continue
		}
		if !s.passesKeywordFilter(p) {
			continue
		}

		// Include this prompt
		result = append(result, p)
	}

	return result, nil
}

// passesPositionFilter checks if the prompt's position is allowed.
func (s *ScopeNarrower) passesPositionFilter(p prompt.Prompt) bool {
	// If no positions specified, allow all
	if len(s.AllowedPositions) == 0 {
		return true
	}

	// Check if prompt's position is in allowed list
	for _, allowed := range s.AllowedPositions {
		if p.Position == allowed {
			return true
		}
	}

	return false
}

// passesIDFilter checks if the prompt's ID is not excluded.
func (s *ScopeNarrower) passesIDFilter(p prompt.Prompt) bool {
	// If no IDs excluded, allow all
	if len(s.ExcludeIDs) == 0 {
		return true
	}

	// Check if prompt's ID is in excluded list
	for _, excluded := range s.ExcludeIDs {
		if p.ID == excluded {
			return false
		}
	}

	return true
}

// passesKeywordFilter checks if the prompt's content contains any keyword.
func (s *ScopeNarrower) passesKeywordFilter(p prompt.Prompt) bool {
	// If no keywords specified, allow all
	if len(s.KeywordFilter) == 0 {
		return true
	}

	// Convert content to lowercase for case-insensitive matching
	contentLower := strings.ToLower(p.Content)

	// Check if any keyword is present
	for _, keyword := range s.KeywordFilter {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(contentLower, keywordLower) {
			return true
		}
	}

	return false
}
