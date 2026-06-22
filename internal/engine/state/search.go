package state

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SearchOptions configures search query behavior for FT.SEARCH operations.
// This provides fine-grained control over result pagination, sorting, and metadata.
type SearchOptions struct {
	// Limit is the maximum number of results to return (default: 10)
	Limit int

	// Offset is the number of results to skip for pagination (default: 0)
	Offset int

	// SortBy specifies the field name to sort results by
	// Leave empty for relevance-based ordering
	SortBy string

	// SortAsc controls sort direction when SortBy is set
	// true = ascending, false = descending (default)
	SortAsc bool

	// WithScores includes relevance scores in the results
	WithScores bool

	// WithPayloads includes document payloads in the results
	// (if payloads were stored during indexing)
	WithPayloads bool
}

// SearchResult represents the result of a FT.SEARCH query.
// It contains the total number of matches and the actual document results.
type SearchResult struct {
	// Total is the total number of matching documents (before pagination)
	Total int64

	// Documents contains the actual search results after pagination
	Documents []Document
}

// Document represents a single search result document.
// It includes the document ID, optional relevance score, and the JSON data.
type Document struct {
	// ID is the Redis key of the document
	ID string

	// Score is the relevance score (only populated if WithScores is true)
	Score float64

	// JSON is the raw JSON document data
	// Use json.Unmarshal to decode into your struct
	JSON json.RawMessage
}

// Search executes a RediSearch FT.SEARCH query and returns matching documents.
// This provides full-text search capabilities across indexed JSON documents.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - index: Name of the search index to query
//   - query: RediSearch query string (supports full-text, numeric, tag, geo queries)
//   - opts: Optional search options for pagination, sorting, and metadata
//
// Returns SearchResult with total count and matching documents.
// Returns an error if the search fails or index doesn't exist.
//
// Example:
//
//	// Simple text search
//	result, err := client.Search(ctx, "users_idx", "alice", nil)
//
//	// Tag search with pagination
//	opts := &SearchOptions{
//	    Limit:  20,
//	    Offset: 0,
//	    SortBy: "created_at",
//	    SortAsc: false,
//	}
//	result, err := client.Search(ctx, "articles_idx", "@status:{published}", opts)
//
//	// Process results
//	for _, doc := range result.Documents {
//	    var article Article
//	    json.Unmarshal(doc.JSON, &article)
//	    fmt.Printf("Found: %s (score: %.2f)\n", article.Title, doc.Score)
//	}
func (c *StateClient) Search(ctx context.Context, index, query string, opts *SearchOptions) (*SearchResult, error) {
	// Apply default options if not provided
	if opts == nil {
		opts = &SearchOptions{
			Limit:  10,
			Offset: 0,
		}
	}

	// Build FT.SEARCH command arguments
	args := []interface{}{"FT.SEARCH", index, query}

	// Add LIMIT clause
	if opts.Limit > 0 || opts.Offset > 0 {
		args = append(args, "LIMIT", opts.Offset, opts.Limit)
	}

	// Add SORTBY clause
	if opts.SortBy != "" {
		args = append(args, "SORTBY", opts.SortBy)
		if opts.SortAsc {
			args = append(args, "ASC")
		} else {
			args = append(args, "DESC")
		}
	}

	// Add WITHSCORES flag
	if opts.WithScores {
		args = append(args, "WITHSCORES")
	}

	// Add WITHPAYLOADS flag
	if opts.WithPayloads {
		args = append(args, "WITHPAYLOADS")
	}

	// Execute FT.SEARCH command
	result := c.client.Do(ctx, args...)
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("FT.SEARCH failed for index %q: %w", index, err)
	}

	// Get raw result to handle both RESP2 and RESP3 formats
	rawResult, err := result.Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get FT.SEARCH result: %w", err)
	}

	// Try RESP3 format first (map[interface{}]interface{})
	if resultMap, ok := rawResult.(map[interface{}]interface{}); ok {
		return parseRESP3SearchResult(resultMap, opts)
	}

	// Fall back to RESP2 format ([]interface{})
	vals, ok := rawResult.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected FT.SEARCH result type: %T", rawResult)
	}

	if len(vals) == 0 {
		return &SearchResult{Total: 0, Documents: []Document{}}, nil
	}

	// First element is total count
	total, err := parseInteger(vals[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse total count: %w", err)
	}

	// Parse documents from remaining elements
	documents, err := parseSearchDocuments(vals[1:], opts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse search documents: %w", err)
	}

	return &SearchResult{
		Total:     total,
		Documents: documents,
	}, nil
}

// parseRESP3SearchResult parses FT.SEARCH result in RESP3 map format.
// RESP3 format returns a map with keys: "total_results", "results", "warning", etc.
// Each result is a map with keys: "id", "extra_attributes", "score" (if WITHSCORES).
func parseRESP3SearchResult(resultMap map[interface{}]interface{}, opts *SearchOptions) (*SearchResult, error) {
	// Extract total_results
	var total int64
	if totalVal, exists := resultMap["total_results"]; exists {
		var err error
		total, err = parseInteger(totalVal)
		if err != nil {
			return nil, fmt.Errorf("failed to parse total_results: %w", err)
		}
	}

	// Extract results array
	resultsVal, exists := resultMap["results"]
	if !exists {
		return &SearchResult{Total: total, Documents: []Document{}}, nil
	}

	results, ok := resultsVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected array for results, got %T", resultsVal)
	}

	documents := make([]Document, 0, len(results))
	for _, r := range results {
		docMap, ok := r.(map[interface{}]interface{})
		if !ok {
			continue
		}

		doc := Document{}

		// Extract document ID
		if idVal, exists := docMap["id"]; exists {
			if id, ok := idVal.(string); ok {
				doc.ID = id
			}
		}

		// Extract score if present
		if opts.WithScores {
			if scoreVal, exists := docMap["score"]; exists {
				score, err := parseFloat(scoreVal)
				if err == nil {
					doc.Score = score
				}
			}
		}

		// Extract extra_attributes (contains the document fields)
		if attrsVal, exists := docMap["extra_attributes"]; exists {
			jsonData, err := extractRESP3JSONField(attrsVal)
			if err == nil {
				doc.JSON = jsonData
			}
		}

		documents = append(documents, doc)
	}

	return &SearchResult{
		Total:     total,
		Documents: documents,
	}, nil
}

// extractRESP3JSONField extracts JSON data from RESP3 extra_attributes.
// In RESP3 format, extra_attributes is a map with field names as keys.
func extractRESP3JSONField(attrs interface{}) (json.RawMessage, error) {
	// Try map format first (RESP3)
	if attrMap, ok := attrs.(map[interface{}]interface{}); ok {
		// Look for "$" or "json" field
		for k, v := range attrMap {
			keyStr, ok := k.(string)
			if !ok {
				continue
			}
			if keyStr == "$" || keyStr == "json" {
				if jsonStr, ok := v.(string); ok {
					return json.RawMessage(jsonStr), nil
				}
			}
		}
		return json.RawMessage("{}"), nil
	}

	// Try array format (field-value pairs)
	if attrList, ok := attrs.([]interface{}); ok {
		return extractJSONField(attrList)
	}

	return json.RawMessage("{}"), nil
}

// parseSearchDocuments parses the document array from FT.SEARCH response.
// The format depends on WITHSCORES and WITHPAYLOADS flags:
//   - Basic: [id, [field1, value1, field2, value2, ...], ...]
//   - WITHSCORES: [id, score, [field1, value1, ...], ...]
//   - WITHPAYLOADS: [id, payload, [field1, value1, ...], ...]
//   - WITHSCORES + WITHPAYLOADS: [id, score, payload, [field1, value1, ...], ...]
func parseSearchDocuments(vals []interface{}, opts *SearchOptions) ([]Document, error) {
	if len(vals) == 0 {
		return []Document{}, nil
	}

	documents := make([]Document, 0)
	i := 0

	for i < len(vals) {
		doc := Document{}

		// Parse document ID (always present)
		if i >= len(vals) {
			break
		}
		id, ok := vals[i].(string)
		if !ok {
			return nil, fmt.Errorf("expected string for document ID at index %d", i)
		}
		doc.ID = id
		i++

		// Parse score if WITHSCORES is enabled
		if opts.WithScores {
			if i >= len(vals) {
				return nil, fmt.Errorf("expected score at index %d", i)
			}
			score, err := parseFloat(vals[i])
			if err != nil {
				return nil, fmt.Errorf("failed to parse score: %w", err)
			}
			doc.Score = score
			i++
		}

		// Skip payload if WITHPAYLOADS is enabled (we don't use it for JSON docs)
		if opts.WithPayloads {
			i++ // Skip payload field
		}

		// Parse field-value pairs
		if i >= len(vals) {
			return nil, fmt.Errorf("expected field array at index %d", i)
		}

		fields, ok := vals[i].([]interface{})
		if !ok {
			return nil, fmt.Errorf("expected array for fields at index %d", i)
		}

		// Extract JSON field (assuming "$" is used as the field name for JSON documents)
		jsonData, err := extractJSONField(fields)
		if err != nil {
			return nil, fmt.Errorf("failed to extract JSON field: %w", err)
		}
		doc.JSON = jsonData
		i++

		documents = append(documents, doc)
	}

	return documents, nil
}

// extractJSONField extracts the JSON document from field-value pairs.
// RediSearch returns fields as: [field1, value1, field2, value2, ...]
// For JSON documents, we look for the "$" field which contains the full document.
func extractJSONField(fields []interface{}) (json.RawMessage, error) {
	for i := 0; i < len(fields)-1; i += 2 {
		fieldName, ok := fields[i].(string)
		if !ok {
			continue
		}

		// Look for "$" field (root JSON document)
		if fieldName == "$" || fieldName == "json" {
			jsonStr, ok := fields[i+1].(string)
			if !ok {
				return nil, fmt.Errorf("expected string for JSON field value")
			}
			return json.RawMessage(jsonStr), nil
		}
	}

	// If no "$" field found, return empty JSON object
	return json.RawMessage("{}"), nil
}

// EscapeTag escapes special characters in TAG field values for RediSearch queries.
// TAG fields require escaping of: , . < > { } [ ] " ' : ; ! @ # $ % ^ & * ( ) - + = ~
//
// Example:
//
//	// Search for status tag with special characters
//	tag := state.EscapeTag("in-progress")
//	query := fmt.Sprintf("@status:{%s}", tag)
//	result, err := client.Search(ctx, "tasks_idx", query, nil)
func EscapeTag(s string) string {
	// Characters that need escaping in TAG fields
	specialChars := []string{
		",", ".", "<", ">", "{", "}", "[", "]", "\"", "'",
		":", ";", "!", "@", "#", "$", "%", "^", "&", "*",
		"(", ")", "-", "+", "=", "~", " ",
	}

	result := s
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}
	return result
}

// EscapeQuery escapes special characters in full-text query strings for RediSearch.
// Full-text queries require escaping of: , . < > { } [ ] " ' : ; ! @ # $ % ^ & * ( ) - + = ~ |
//
// Example:
//
//	// Search for text containing special characters
//	userInput := "alice@example.com"
//	query := state.EscapeQuery(userInput)
//	result, err := client.Search(ctx, "users_idx", query, nil)
func EscapeQuery(s string) string {
	// Characters that need escaping in full-text queries
	specialChars := []string{
		",", ".", "<", ">", "{", "}", "[", "]", "\"", "'",
		":", ";", "!", "@", "#", "$", "%", "^", "&", "*",
		"(", ")", "-", "+", "=", "~", "|",
	}

	result := s
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}
	return result
}

// QueryBuilder provides a fluent API for building RediSearch queries safely.
// It handles proper escaping and formatting of query components.
//
// Example:
//
//	query := NewQueryBuilder().
//	    Text("security vulnerability").
//	    Tag("severity", "critical").
//	    Tag("status", "open").
//	    NumericRange("cvss_score", 7.0, 10.0).
//	    Build()
//
//	result, err := client.Search(ctx, "findings_idx", query, nil)
type QueryBuilder struct {
	parts []string
}

// NewQueryBuilder creates a new QueryBuilder instance.
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		parts: make([]string, 0),
	}
}

// Text adds a full-text search term to the query.
// The text is automatically escaped for safe query construction.
func (qb *QueryBuilder) Text(text string) *QueryBuilder {
	if text != "" {
		escaped := EscapeQuery(text)
		qb.parts = append(qb.parts, escaped)
	}
	return qb
}

// Tag adds a TAG field filter to the query.
// Multiple values can be provided for OR matching within the same tag.
//
// Example:
//
//	qb.Tag("status", "open", "in-progress")  // matches status:open OR status:in-progress
func (qb *QueryBuilder) Tag(field string, values ...string) *QueryBuilder {
	if len(values) == 0 {
		return qb
	}

	escapedValues := make([]string, len(values))
	for i, v := range values {
		escapedValues[i] = EscapeTag(v)
	}

	tagQuery := fmt.Sprintf("@%s:{%s}", field, strings.Join(escapedValues, "|"))
	qb.parts = append(qb.parts, tagQuery)
	return qb
}

// NumericRange adds a numeric range filter to the query.
// Use math.Inf(-1) for -inf and math.Inf(1) for +inf.
//
// Example:
//
//	qb.NumericRange("price", 10.0, 100.0)  // price between 10 and 100
//	qb.NumericRange("age", 18.0, math.Inf(1))  // age >= 18
func (qb *QueryBuilder) NumericRange(field string, min, max float64) *QueryBuilder {
	minStr := formatNumericBound(min)
	maxStr := formatNumericBound(max)
	numQuery := fmt.Sprintf("@%s:[%s %s]", field, minStr, maxStr)
	qb.parts = append(qb.parts, numQuery)
	return qb
}

// NumericEquals adds an exact numeric match filter to the query.
func (qb *QueryBuilder) NumericEquals(field string, value float64) *QueryBuilder {
	return qb.NumericRange(field, value, value)
}

// And adds an AND operator between query parts.
// This is the default behavior, so it's optional.
func (qb *QueryBuilder) And() *QueryBuilder {
	if len(qb.parts) > 0 {
		// AND is implicit in RediSearch, but we can make it explicit
		// by wrapping the last part in parentheses if needed
	}
	return qb
}

// Or adds an OR operator to combine the last two query parts.
// Note: This modifies the last two parts to create an OR relationship.
func (qb *QueryBuilder) Or() *QueryBuilder {
	if len(qb.parts) >= 2 {
		last := qb.parts[len(qb.parts)-1]
		secondLast := qb.parts[len(qb.parts)-2]
		combined := fmt.Sprintf("(%s | %s)", secondLast, last)
		qb.parts = qb.parts[:len(qb.parts)-2]
		qb.parts = append(qb.parts, combined)
	}
	return qb
}

// Not negates the last query part.
func (qb *QueryBuilder) Not() *QueryBuilder {
	if len(qb.parts) > 0 {
		last := qb.parts[len(qb.parts)-1]
		qb.parts[len(qb.parts)-1] = fmt.Sprintf("-(%s)", last)
	}
	return qb
}

// Group wraps the last N parts in parentheses for grouping.
func (qb *QueryBuilder) Group(n int) *QueryBuilder {
	if n <= 0 || n > len(qb.parts) {
		return qb
	}

	startIdx := len(qb.parts) - n
	grouped := strings.Join(qb.parts[startIdx:], " ")
	qb.parts = qb.parts[:startIdx]
	qb.parts = append(qb.parts, fmt.Sprintf("(%s)", grouped))
	return qb
}

// Raw adds a raw query string without escaping.
// Use this for advanced queries that require special syntax.
//
// Warning: This bypasses safety checks. Ensure the query is properly formatted.
func (qb *QueryBuilder) Raw(query string) *QueryBuilder {
	if query != "" {
		qb.parts = append(qb.parts, query)
	}
	return qb
}

// Prefix adds a prefix search for a TEXT field.
//
// Example:
//
//	qb.Prefix("name", "john")  // matches "john*"
func (qb *QueryBuilder) Prefix(field, prefix string) *QueryBuilder {
	if prefix != "" {
		escaped := EscapeQuery(prefix)
		prefixQuery := fmt.Sprintf("@%s:%s*", field, escaped)
		qb.parts = append(qb.parts, prefixQuery)
	}
	return qb
}

// Build constructs the final query string.
// Returns "*" if no query parts were added.
func (qb *QueryBuilder) Build() string {
	if len(qb.parts) == 0 {
		return "*"
	}
	return strings.Join(qb.parts, " ")
}

// formatNumericBound formats a float64 value for RediSearch numeric queries.
// Handles infinity values properly.
func formatNumericBound(value float64) string {
	// Check for infinity using the standard library approach
	switch {
	case value > 1e307: // Effectively positive infinity
		return "+inf"
	case value < -1e307: // Effectively negative infinity
		return "-inf"
	default:
		// Format without scientific notation
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
}
