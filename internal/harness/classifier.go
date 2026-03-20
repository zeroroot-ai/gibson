package harness

import "context"

// CategoryClassifier provides semantic category classification and normalization
// for findings. This interface mirrors the SDK's finding/classifier.CategoryClassifier
// to allow use of VectorClassifier implementation.
//
// The harness uses this interface to normalize finding categories during SubmitFinding,
// enabling LLM agents to use natural language category names while maintaining
// consistency across findings.
//
// Implementations must be thread-safe for concurrent use.
type CategoryClassifier interface {
	// Classify normalizes a category via semantic matching.
	//
	// It embeds the proposed category and description, searches for similar
	// existing categories, and either returns a matching category (if similarity
	// exceeds the threshold) or registers the proposed category as new.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - proposed: The proposed category name (e.g., "jailbreaking")
	//   - description: Additional context about the category
	//
	// Returns the normalized category name (either matched or newly registered)
	// and an error if classification fails.
	Classify(ctx context.Context, proposed, description string) (string, error)
}
