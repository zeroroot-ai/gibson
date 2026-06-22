package finding

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// CompositeClassifier implements FindingClassifier using a two-stage approach:
// 1. Fast heuristic classification for known patterns
// 2. LLM classification fallback for low-confidence or unmatched findings
//
// This provides the best of both worlds:
//   - Fast classification for common patterns (heuristic)
//   - Accurate classification for complex cases (LLM)
//   - Cost optimization by using LLM only when needed
//
// Thread-safety: All methods are safe for concurrent use.
type CompositeClassifier struct {
	heuristic *HeuristicClassifier
	llm       *LLMFindingClassifier
	threshold float64
	mu        sync.RWMutex

	// Atomic classification counters — updated on every Classify call.
	totalClassifications atomic.Int64
	heuristicOnly        atomic.Int64
	llmFallback          atomic.Int64

	// Optional metrics hook; called after each classification with (category, path).
	// "path" is either "heuristic" or "llm". Set via WithClassificationRecorder.
	classificationRecorder func(ctx context.Context, category, path string)
}

// NewCompositeClassifier creates a new composite classifier.
//
// Parameters:
//   - heuristic: Heuristic classifier for fast pattern matching
//   - llm: LLM classifier for semantic analysis
//   - opts: Optional configuration (threshold, MITRE DB)
//
// The threshold determines when to fall back to LLM:
//   - If heuristic confidence >= threshold, use heuristic result
//   - Otherwise, fall back to LLM classification
func NewCompositeClassifier(heuristic *HeuristicClassifier, llm *LLMFindingClassifier, opts ...ClassifierOption) *CompositeClassifier {
	cfg := applyOptions(opts...)

	return &CompositeClassifier{
		heuristic: heuristic,
		llm:       llm,
		threshold: cfg.confidenceThreshold,
	}
}

// WithClassificationRecorder attaches a metrics callback invoked after each
// Classify call. The function receives (ctx, category, path) where path is
// either "heuristic" or "llm". Callers typically wire this to
// OTelMetricsRecorder.RecordClassification to avoid an import cycle.
// Passing nil is safe (no-op).
func (cc *CompositeClassifier) WithClassificationRecorder(fn func(ctx context.Context, category, path string)) *CompositeClassifier {
	cc.mu.Lock()
	cc.classificationRecorder = fn
	cc.mu.Unlock()
	return cc
}

// WithHeuristicThreshold sets a custom threshold for heuristic confidence.
// This is separate from the general confidence threshold and specifically
// controls when to fall back from heuristic to LLM classification.
func WithHeuristicThreshold(threshold float64) ClassifierOption {
	return func(cfg *classifierConfig) {
		cfg.confidenceThreshold = threshold
	}
}

// Classify analyzes a finding using a two-stage approach.
//
// Algorithm:
//  1. Try heuristic classification first (fast)
//  2. If confidence >= threshold, return heuristic result
//  3. Otherwise, fall back to LLM classification (slower but more accurate)
//  4. Mark result as composite classification
//
// This approach optimizes for both speed and accuracy:
//   - Common patterns are classified instantly
//   - Edge cases benefit from LLM analysis
//   - Token costs are minimized
func (cc *CompositeClassifier) Classify(ctx context.Context, finding agent.Finding) (*Classification, error) {
	cc.mu.RLock()
	threshold := cc.threshold
	cc.mu.RUnlock()

	// Check context before processing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Stage 1: Try heuristic classification
	heuristicResult, err := cc.heuristic.Classify(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("heuristic classification failed: %w", err)
	}

	cc.totalClassifications.Add(1)

	// Warn when confidence is below the threshold to assist operators in tuning.
	if heuristicResult.Confidence < threshold {
		slog.WarnContext(ctx, "heuristic classification below confidence threshold",
			slog.String("finding_id", finding.ID.String()),
			slog.String("finding_title", finding.Title),
			slog.Float64("confidence", heuristicResult.Confidence),
			slog.Float64("threshold", threshold),
		)
	}

	// If heuristic is confident, use its result
	if heuristicResult.Confidence >= threshold {
		cc.heuristicOnly.Add(1)
		cc.recordClassificationMetric(ctx, string(finding.Category), "heuristic")

		heuristicResult.Method = MethodComposite
		heuristicResult.Rationale = fmt.Sprintf("Heuristic (%.2f confidence): %s",
			heuristicResult.Confidence, heuristicResult.Rationale)
		return heuristicResult, nil
	}

	// Stage 2: Fall back to LLM for better accuracy
	llmResult, err := cc.llm.Classify(ctx, finding)
	if err != nil {
		// If LLM fails, return heuristic result with warning
		cc.heuristicOnly.Add(1)
		cc.recordClassificationMetric(ctx, string(finding.Category), "heuristic")

		heuristicResult.Method = MethodComposite
		heuristicResult.Rationale = fmt.Sprintf("Heuristic fallback (LLM failed): %s",
			heuristicResult.Rationale)
		return heuristicResult, nil
	}

	cc.llmFallback.Add(1)
	cc.recordClassificationMetric(ctx, string(finding.Category), "llm")

	// Use LLM result but mark as composite
	llmResult.Method = MethodComposite
	llmResult.Rationale = fmt.Sprintf("LLM analysis (heuristic: %.2f, llm: %.2f): %s",
		heuristicResult.Confidence, llmResult.Confidence, llmResult.Rationale)

	return llmResult, nil
}

// recordClassificationMetric calls the optional metrics hook if set.
func (cc *CompositeClassifier) recordClassificationMetric(ctx context.Context, category, path string) {
	cc.mu.RLock()
	fn := cc.classificationRecorder
	cc.mu.RUnlock()
	if fn != nil {
		fn(ctx, category, path)
	}
}

// BulkClassify classifies multiple findings using the composite approach.
// Each finding is processed independently with the same two-stage algorithm.
//
// Optimization opportunities:
//   - Group high-confidence heuristic matches (no LLM needed)
//   - Batch low-confidence findings for LLM analysis
//   - Process in parallel with controlled concurrency
func (cc *CompositeClassifier) BulkClassify(ctx context.Context, findings []agent.Finding) ([]*Classification, error) {
	if len(findings) == 0 {
		return []*Classification{}, nil
	}

	// Check context before processing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	cc.mu.RLock()
	threshold := cc.threshold
	cc.mu.RUnlock()

	// Phase 1: Classify all findings with heuristics
	heuristicResults, err := cc.heuristic.BulkClassify(ctx, findings)
	if err != nil {
		return nil, fmt.Errorf("heuristic bulk classification failed: %w", err)
	}

	// Phase 2: Identify findings that need LLM analysis
	needLLM := make([]int, 0)
	for i, result := range heuristicResults {
		if result.Confidence < threshold {
			needLLM = append(needLLM, i)
		}
	}

	// Phase 3: Process low-confidence findings with LLM
	if len(needLLM) > 0 {
		llmFindings := make([]agent.Finding, len(needLLM))
		for i, idx := range needLLM {
			llmFindings[i] = findings[idx]
		}

		llmResults, err := cc.llm.BulkClassify(ctx, llmFindings)
		if err != nil {
			// On LLM failure, keep heuristic results but mark them
			for _, idx := range needLLM {
				heuristicResults[idx].Method = MethodComposite
				heuristicResults[idx].Rationale = fmt.Sprintf("Heuristic fallback (LLM failed): %s",
					heuristicResults[idx].Rationale)
			}
		} else {
			// Replace low-confidence heuristic results with LLM results
			for i, idx := range needLLM {
				llmResults[i].Method = MethodComposite
				llmResults[i].Rationale = fmt.Sprintf("LLM analysis (heuristic: %.2f, llm: %.2f): %s",
					heuristicResults[idx].Confidence, llmResults[i].Confidence, llmResults[i].Rationale)
				heuristicResults[idx] = llmResults[i]
			}
		}
	}

	// Phase 4: Mark high-confidence heuristic results as composite
	for i, result := range heuristicResults {
		if result.Confidence >= threshold {
			result.Method = MethodComposite
			result.Rationale = fmt.Sprintf("Heuristic (%.2f confidence): %s",
				result.Confidence, result.Rationale)
			heuristicResults[i] = result
		}
	}

	return heuristicResults, nil
}

// SetThreshold updates the confidence threshold for heuristic fallback.
// This allows dynamic adjustment based on accuracy requirements or cost constraints.
//
// Thread-safe: Safe to call concurrently with Classify operations.
func (cc *CompositeClassifier) SetThreshold(threshold float64) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if threshold < 0.0 {
		threshold = 0.0
	} else if threshold > 1.0 {
		threshold = 1.0
	}

	cc.threshold = threshold
}

// GetThreshold returns the current confidence threshold
func (cc *CompositeClassifier) GetThreshold() float64 {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.threshold
}

// GetStats returns classification statistics for monitoring and optimization.
// This helps track the balance between heuristic and LLM usage.
type ClassificationStats struct {
	TotalClassifications int
	HeuristicOnly        int
	LLMFallback          int
	HeuristicRate        float64 // Percentage of classifications handled by heuristic
}

// Stats returns current classification statistics read from atomic counters.
// Safe to call concurrently with Classify.
func (cc *CompositeClassifier) Stats() ClassificationStats {
	total := cc.totalClassifications.Load()
	heuristic := cc.heuristicOnly.Load()
	llm := cc.llmFallback.Load()

	var rate float64
	if total > 0 {
		rate = float64(heuristic) / float64(total)
	}

	return ClassificationStats{
		TotalClassifications: int(total),
		HeuristicOnly:        int(heuristic),
		LLMFallback:          int(llm),
		HeuristicRate:        rate,
	}
}

// Ensure CompositeClassifier implements FindingClassifier
var _ FindingClassifier = (*CompositeClassifier)(nil)
