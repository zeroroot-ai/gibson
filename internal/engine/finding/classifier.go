package finding

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// FindingClassifier classifies security findings into categories with confidence scores.
// Classifiers analyze finding metadata (title, description, evidence) to determine
// the type of security issue and map it to MITRE ATT&CK techniques.
//
// Implementations must be safe for concurrent use from multiple goroutines.
type FindingClassifier interface {
	// Classify analyzes a single finding and returns its classification.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - finding: The base finding to classify
	//
	// Returns:
	//   - *Classification: The classification result with category and confidence
	//   - error: Non-nil if classification fails
	//
	// The classifier analyzes the finding's title, description, and evidence
	// to determine the most appropriate category and subcategory.
	//
	// Example:
	//   finding := agent.NewFinding(
	//       "Jailbreak Attempt",
	//       "User attempted to override system instructions",
	//       agent.SeverityHigh,
	//   )
	//   classification, err := classifier.Classify(ctx, finding)
	Classify(ctx context.Context, finding agent.Finding) (*Classification, error)

	// BulkClassify classifies multiple findings efficiently.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - findings: Slice of findings to classify
	//
	// Returns:
	//   - []*Classification: Classifications in the same order as input findings
	//   - error: Non-nil if bulk classification fails
	//
	// Implementations may optimize bulk classification by:
	//   - Batching LLM requests
	//   - Parallel processing with goroutines
	//   - Shared pattern matching across findings
	//
	// If any individual classification fails, the implementation should decide
	// whether to fail the entire operation or return partial results with errors.
	//
	// Example:
	//   findings := []agent.Finding{finding1, finding2, finding3}
	//   classifications, err := classifier.BulkClassify(ctx, findings)
	BulkClassify(ctx context.Context, findings []agent.Finding) ([]*Classification, error)
}

// ClassifierOption is a functional option for configuring classifiers
type ClassifierOption func(*classifierConfig)

// classifierConfig holds configuration for classifiers
type classifierConfig struct {
	confidenceThreshold float64
	mitreDB             *MitreDatabase
}

// WithConfidenceThreshold sets the minimum confidence threshold for classifications.
// Classifications below this threshold may trigger fallback to another classifier
// or be marked as low confidence.
//
// Default: 0.7 (70%)
// Valid range: 0.0 to 1.0
func WithConfidenceThreshold(threshold float64) ClassifierOption {
	return func(cfg *classifierConfig) {
		cfg.confidenceThreshold = threshold
	}
}

// WithMitreDatabase configures the MITRE ATT&CK database for technique mapping.
// If not provided, classifications will not include MITRE technique mappings.
func WithMitreDatabase(db *MitreDatabase) ClassifierOption {
	return func(cfg *classifierConfig) {
		cfg.mitreDB = db
	}
}

// applyOptions applies functional options to a config with defaults
func applyOptions(opts ...ClassifierOption) *classifierConfig {
	cfg := &classifierConfig{
		confidenceThreshold: 0.7, // Default 70% confidence threshold
		mitreDB:             nil, // No MITRE DB by default
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}
