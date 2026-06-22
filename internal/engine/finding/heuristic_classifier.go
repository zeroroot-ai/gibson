package finding

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// PatternRule defines a regex pattern and its associated classification
type PatternRule struct {
	// Pattern is the compiled regex to match against finding text
	Pattern *regexp.Regexp

	// Category is the finding category this pattern indicates
	Category FindingCategory

	// Subcategory provides more specific classification
	Subcategory string

	// Confidence is the base confidence score for this pattern (0.0-1.0)
	Confidence float64

	// Weight is used when multiple patterns match (higher weight = higher priority)
	Weight int
}

// HeuristicClassifier implements FindingClassifier using regex pattern matching.
// It performs fast, deterministic classification based on keywords and patterns
// in the finding title and description.
//
// This classifier is suitable for:
//   - High-throughput classification where speed is critical
//   - Known attack patterns with clear indicators
//   - Initial triage before LLM-based classification
//   - Baseline classification in composite classifiers
//
// Thread-safety: All methods are safe for concurrent use.
type HeuristicClassifier struct {
	mu       sync.RWMutex
	patterns map[FindingCategory][]PatternRule
	config   *classifierConfig
}

// NewHeuristicClassifier creates a new heuristic classifier with default patterns.
// The classifier includes comprehensive patterns for common LLM security issues.
func NewHeuristicClassifier(opts ...ClassifierOption) *HeuristicClassifier {
	cfg := applyOptions(opts...)

	hc := &HeuristicClassifier{
		patterns: make(map[FindingCategory][]PatternRule),
		config:   cfg,
	}

	// Initialize with default patterns
	hc.initializeDefaultPatterns()

	return hc
}

// initializeDefaultPatterns sets up the default pattern rules for classification
func (hc *HeuristicClassifier) initializeDefaultPatterns() {
	// Jailbreak patterns
	hc.addPattern(CategoryJailbreak, "jailbreak", `\b(?i)(jailbreak|jail\s*break)\b`, 0.95, 100)
	hc.addPattern(CategoryJailbreak, "guardrail_bypass", `\b(?i)(guardrail\s*bypass|bypass.*guardrail|ignore.*safety)\b`, 0.90, 90)
	hc.addPattern(CategoryJailbreak, "instruction_override", `\b(?i)(override.*instruction|instruction.*override|ignore.*instruction)\b`, 0.90, 90)
	hc.addPattern(CategoryJailbreak, "safety_bypass", `\b(?i)(safety\s*bypass|bypass.*safety|disable.*safety)\b`, 0.88, 85)
	hc.addPattern(CategoryJailbreak, "role_manipulation", `\b(?i)(role\s*play|pretend\s*you\s*are|act\s*as)\b`, 0.75, 70)
	hc.addPattern(CategoryJailbreak, "constraint_removal", `\b(?i)(remove.*constraint|ignore.*constraint|no\s*restrictions)\b`, 0.85, 80)

	// Prompt injection patterns
	hc.addPattern(CategoryPromptInjection, "prompt_injection", `\b(?i)(prompt\s*injection|inject.*prompt)\b`, 0.95, 100)
	hc.addPattern(CategoryPromptInjection, "prompt_manipulation", `\b(?i)(prompt\s*manipulation|manipulate.*prompt)\b`, 0.92, 95)
	hc.addPattern(CategoryPromptInjection, "indirect_injection", `\b(?i)(indirect\s*injection|indirect.*prompt)\b`, 0.90, 90)
	hc.addPattern(CategoryPromptInjection, "context_poisoning", `\b(?i)(context\s*poison|poisoned.*context)\b`, 0.88, 85)
	hc.addPattern(CategoryPromptInjection, "instruction_injection", `\b(?i)(inject.*instruction|malicious.*instruction)\b`, 0.85, 80)
	hc.addPattern(CategoryPromptInjection, "command_injection", `\b(?i)(command\s*injection|inject.*command)\b`, 0.87, 82)

	// Data extraction patterns
	hc.addPattern(CategoryDataExtraction, "data_leak", `\b(?i)(data\s*leak|leak.*data|leaking\s*data)\b`, 0.90, 95)
	hc.addPattern(CategoryDataExtraction, "data_extraction", `\b(?i)(data\s*extraction|extract.*data|exfiltrat)\b`, 0.92, 95)
	hc.addPattern(CategoryDataExtraction, "pii_disclosure", `\b(?i)(PII|personal.*identifiable|personally.*identifiable)\b`, 0.88, 90)
	hc.addPattern(CategoryDataExtraction, "sensitive_disclosure", `\b(?i)(sensitive.*disclosure|disclose.*sensitive|leak.*sensitive)\b`, 0.87, 88)
	hc.addPattern(CategoryDataExtraction, "credential_leak", `\b(?i)(credential.*leak|leak.*credential|password.*disclosure)\b`, 0.93, 95)
	hc.addPattern(CategoryDataExtraction, "api_key_leak", `\b(?i)(api\s*key.*leak|leak.*api.*key)\b`, 0.93, 95)

	// Information disclosure patterns
	hc.addPattern(CategoryInformationDisclosure, "system_prompt", `\b(?i)(system\s*prompt|reveal.*system|expose.*system)\b`, 0.90, 92)
	hc.addPattern(CategoryInformationDisclosure, "config_disclosure", `\b(?i)(config.*disclosure|configuration.*leak|settings.*exposure)\b`, 0.88, 88)
	hc.addPattern(CategoryInformationDisclosure, "internal_disclosure", `\b(?i)(internal.*disclosure|internal.*information|internal.*details)\b`, 0.85, 85)
	hc.addPattern(CategoryInformationDisclosure, "model_disclosure", `\b(?i)(model.*name|model.*version|architecture.*disclosure)\b`, 0.83, 82)
	hc.addPattern(CategoryInformationDisclosure, "capability_disclosure", `\b(?i)(capability.*disclosure|reveal.*capability|expose.*capability)\b`, 0.82, 80)
	hc.addPattern(CategoryInformationDisclosure, "metadata_leak", `\b(?i)(metadata.*leak|leak.*metadata)\b`, 0.85, 83)
}

// addPattern is a helper to add a pattern rule
func (hc *HeuristicClassifier) addPattern(category FindingCategory, subcategory, pattern string, confidence float64, weight int) {
	compiled := regexp.MustCompile(pattern)
	rule := PatternRule{
		Pattern:     compiled,
		Category:    category,
		Subcategory: subcategory,
		Confidence:  confidence,
		Weight:      weight,
	}

	hc.patterns[category] = append(hc.patterns[category], rule)
}

// Classify analyzes a finding using pattern matching and returns its classification.
//
// The classifier:
//  1. Concatenates finding title and description
//  2. Tests all patterns against the text
//  3. Selects the highest-weighted match
//  4. Returns CategoryUncategorized if no patterns match
func (hc *HeuristicClassifier) Classify(ctx context.Context, finding agent.Finding) (*Classification, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Combine title and description for matching
	text := strings.ToLower(finding.Title + " " + finding.Description)

	// Track best match
	var bestMatch *PatternRule
	bestScore := 0

	// Test all patterns
	for _, rules := range hc.patterns {
		for i := range rules {
			rule := &rules[i]
			if rule.Pattern.MatchString(text) {
				score := rule.Weight
				if bestMatch == nil || score > bestScore {
					bestMatch = rule
					bestScore = score
				}
			}
		}
	}

	// Build classification result
	var classification *Classification
	if bestMatch != nil {
		classification = &Classification{
			Category:    bestMatch.Category,
			Subcategory: bestMatch.Subcategory,
			Severity:    finding.Severity,
			Confidence:  bestMatch.Confidence,
			Method:      MethodHeuristic,
			Rationale:   "Pattern matched: " + bestMatch.Subcategory,
		}

		// Add MITRE mapping if database is available
		if hc.config.mitreDB != nil {
			mappings := hc.config.mitreDB.FindForCategory(bestMatch.Category)
			classification.MitreAttack = convertMitreMappings(mappings)
		}
	} else {
		// No pattern matched
		classification = &Classification{
			Category:    CategoryUncategorized,
			Subcategory: "unknown",
			Severity:    finding.Severity,
			Confidence:  0.5, // Low confidence for uncategorized
			Method:      MethodHeuristic,
			Rationale:   "No matching patterns found",
		}
	}

	return classification, nil
}

// BulkClassify classifies multiple findings concurrently using goroutines.
// This method processes findings in parallel for improved throughput.
func (hc *HeuristicClassifier) BulkClassify(ctx context.Context, findings []agent.Finding) ([]*Classification, error) {
	if len(findings) == 0 {
		return []*Classification{}, nil
	}

	// Check context before starting
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	results := make([]*Classification, len(findings))
	errors := make([]error, len(findings))

	// Use worker pool pattern for concurrent classification
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent workers

	for i, finding := range findings {
		wg.Add(1)
		go func(idx int, f agent.Finding) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Classify the finding
			classification, err := hc.Classify(ctx, f)
			results[idx] = classification
			errors[idx] = err
		}(i, finding)
	}

	wg.Wait()

	// Check if any errors occurred
	for _, err := range errors {
		if err != nil {
			return results, err // Return first error
		}
	}

	return results, nil
}

// AddCustomPattern allows adding custom patterns at runtime.
// This enables dynamic pattern extension for specialized use cases.
func (hc *HeuristicClassifier) AddCustomPattern(category FindingCategory, subcategory, pattern string, confidence float64, weight int) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	rule := PatternRule{
		Pattern:     compiled,
		Category:    category,
		Subcategory: subcategory,
		Confidence:  confidence,
		Weight:      weight,
	}

	hc.patterns[category] = append(hc.patterns[category], rule)
	return nil
}

// GetPatternCount returns the total number of patterns configured
func (hc *HeuristicClassifier) GetPatternCount() int {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	count := 0
	for _, rules := range hc.patterns {
		count += len(rules)
	}
	return count
}

// convertMitreMappings converts internal MitreMapping to SimpleMitreMapping for Classification
func convertMitreMappings(mappings []MitreMapping) []SimpleMitreMapping {
	result := make([]SimpleMitreMapping, len(mappings))
	for i, m := range mappings {
		result[i] = SimpleMitreMapping{
			TechniqueID:   m.TechniqueID,
			TechniqueName: m.TechniqueName,
			Tactic:        m.TacticName,
		}
	}
	return result
}

// Ensure HeuristicClassifier implements FindingClassifier
var _ FindingClassifier = (*HeuristicClassifier)(nil)
