package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// codeBlockPattern matches markdown code blocks with optional language tag
// Captures: (1) optional language, (2) content
var codeBlockPattern = regexp.MustCompile(`(?s)` + "```" + `(\w*)\s*\n(.+?)\n` + "```")

// ExtractJSON extracts JSON from an LLM response that may be wrapped in markdown.
// Priority:
// 1. JSON inside ```json ... ``` or ``` ... ``` code blocks
// 2. Raw JSON object {...} or array [...] in the response
//
// Returns the extracted JSON string and any error.
func ExtractJSON(response string) (string, error) {
	// Step 1: Try to find JSON in markdown code blocks
	if jsonStr, found := extractFromCodeBlock(response); found {
		// Validate it's actually JSON
		if isValidJSON(jsonStr) {
			return jsonStr, nil
		}
	}

	// Step 2: Try to extract raw JSON
	if jsonStr, found := extractRawJSON(response); found {
		return jsonStr, nil
	}

	return "", fmt.Errorf("no valid JSON object found in response")
}

// extractFromCodeBlock finds JSON in markdown code blocks.
// Returns the content and true if found, empty string and false otherwise.
func extractFromCodeBlock(response string) (string, bool) {
	matches := codeBlockPattern.FindAllStringSubmatch(response, -1)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		lang := strings.ToLower(match[1])
		content := strings.TrimSpace(match[2])

		// Accept json, JSON, or no language tag
		// Skip blocks explicitly tagged as other languages
		if lang != "" && lang != "json" {
			continue
		}

		// Check if content looks like JSON
		if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
			if isValidJSON(content) {
				return content, true
			}
		}
	}

	return "", false
}

// extractRawJSON finds JSON object or array in response text.
// Handles JSON that's not wrapped in code blocks.
func extractRawJSON(response string) (string, bool) {
	// Find first { or [
	startObj := strings.Index(response, "{")
	startArr := strings.Index(response, "[")

	// Determine which comes first
	start := -1
	endChar := byte('}')
	if startObj >= 0 && (startArr < 0 || startObj < startArr) {
		start = startObj
		endChar = '}'
	} else if startArr >= 0 {
		start = startArr
		endChar = ']'
	}

	if start < 0 {
		return "", false
	}

	// Find matching closing bracket (handles nesting)
	content := response[start:]
	jsonStr := findMatchingBracket(content, endChar)

	if jsonStr != "" && isValidJSON(jsonStr) {
		return jsonStr, true
	}

	return "", false
}

// findMatchingBracket finds the complete JSON by matching brackets.
func findMatchingBracket(s string, closeChar byte) string {
	if len(s) == 0 {
		return ""
	}

	openChar := s[0]
	depth := 0
	inString := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]

		if escaped {
			escaped = false
			continue
		}

		if c == '\\' && inString {
			escaped = true
			continue
		}

		if c == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		if c == openChar {
			depth++
		} else if c == closeChar {
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		}
	}

	return "" // Unmatched brackets
}

// isValidJSON checks if a string is valid JSON.
func isValidJSON(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

// ExtractJSONAs extracts JSON and unmarshals into the provided type.
// Convenience wrapper around ExtractJSON.
func ExtractJSONAs[T any](response string) (T, error) {
	var result T

	jsonStr, err := ExtractJSON(response)
	if err != nil {
		return result, err
	}

	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return result, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return result, nil
}
