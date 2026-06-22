package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractJSON_MarkdownJsonBlock(t *testing.T) {
	response := `Here's the summary:

` + "```json" + `
{
  "summary": "Mission completed",
  "findings": ["port 22 open", "SSH service detected"]
}
` + "```" + `

Let me know if you need more details.`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Contains(t, result, `"summary"`)
	assert.Contains(t, result, `"findings"`)
	assert.Contains(t, result, "Mission completed")
}

func TestExtractJSON_MarkdownJsonBlockUppercase(t *testing.T) {
	// Test that uppercase JSON tag is skipped (we only accept lowercase "json" or no tag)
	response := "```JSON\n{\"key\": \"value\"}\n```"

	// Should still work since we convert to lowercase
	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"key": "value"}`, result)
}

func TestExtractJSON_MarkdownNoLang(t *testing.T) {
	response := "```\n{\"key\": \"value\", \"number\": 42}\n```"

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"key": "value", "number": 42}`, result)
}

func TestExtractJSON_RawJSONObject(t *testing.T) {
	response := `{"summary": "test", "status": "complete"}`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"summary": "test", "status": "complete"}`, result)
}

func TestExtractJSON_RawJSONArray(t *testing.T) {
	response := `[{"item": 1}, {"item": 2}, {"item": 3}]`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, response, result)
}

func TestExtractJSON_SkipBashBlock(t *testing.T) {
	response := "Here's a command:\n```bash\necho hello\n```\n\nAnd here's the data:\n```json\n{\"key\": \"value\"}\n```"

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"key": "value"}`, result)
}

func TestExtractJSON_SkipPythonBlock(t *testing.T) {
	response := "```python\nprint('hello')\n```\n\n```json\n{\"result\": true}\n```"

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"result": true}`, result)
}

func TestExtractJSON_MultipleCodeBlocks(t *testing.T) {
	// Should extract first valid JSON block
	response := "```\ninvalid json\n```\n\n```json\n{\"first\": 1}\n```\n\n```json\n{\"second\": 2}\n```"

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"first": 1}`, result)
}

func TestExtractJSON_NestedJSON(t *testing.T) {
	response := `{
  "outer": {
    "inner": {
      "deep": "value"
    }
  },
  "array": [1, 2, {"nested": true}]
}`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Contains(t, result, `"outer"`)
	assert.Contains(t, result, `"inner"`)
	assert.Contains(t, result, `"deep"`)
}

func TestExtractJSON_JSONWithEscapedQuotes(t *testing.T) {
	response := `{"message": "He said \"hello\" to me", "status": "ok"}`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, response, result)
}

func TestExtractJSON_LeadingTrailingText(t *testing.T) {
	response := `Here's your data:

{
  "result": "success",
  "count": 42
}

That's all the information I have.`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Contains(t, result, `"result"`)
	assert.Contains(t, result, `"count"`)
}

func TestExtractJSON_NoJSON(t *testing.T) {
	response := "This is just plain text with no JSON at all."

	_, err := ExtractJSON(response)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid JSON")
}

func TestExtractJSON_InvalidJSON(t *testing.T) {
	response := "```json\n{invalid json syntax\n```"

	_, err := ExtractJSON(response)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid JSON")
}

func TestExtractJSON_IncompleteJSON(t *testing.T) {
	response := `{"key": "value", "incomplete":`

	_, err := ExtractJSON(response)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid JSON")
}

func TestExtractJSON_EmptyString(t *testing.T) {
	response := ""

	_, err := ExtractJSON(response)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid JSON")
}

func TestExtractJSON_OnlyCodeBlock(t *testing.T) {
	response := "```json\n{\"key\": \"value\"}\n```"

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Equal(t, `{"key": "value"}`, result)
}

func TestExtractJSON_CodeBlockWithBracketsInString(t *testing.T) {
	// Test that brackets inside strings don't confuse the parser
	response := `{
  "message": "Use brackets like {this} or [that]",
  "valid": true
}`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Contains(t, result, `"message"`)
	assert.Contains(t, result, `"valid"`)
}

func TestExtractJSON_ArrayOfObjects(t *testing.T) {
	response := `[
  {"id": 1, "name": "first"},
  {"id": 2, "name": "second"}
]`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Contains(t, result, `"id"`)
	assert.Contains(t, result, `"name"`)
}

func TestExtractJSON_RealWorldMissionSummary(t *testing.T) {
	// Real-world example from mission summary generation
	response := `Based on the mission results, here's the intelligence summary:

` + "```json" + `
{
  "summary": "Network reconnaissance completed successfully. Discovered 5 open ports on target system.",
  "key_findings": [
    "Port 22 (SSH) - OpenSSH 8.2",
    "Port 80 (HTTP) - nginx 1.18.0",
    "Port 443 (HTTPS) - nginx 1.18.0"
  ],
  "risk_level": "medium",
  "recommendations": [
    "Review SSH configuration for hardening",
    "Check for unpatched vulnerabilities in nginx"
  ]
}
` + "```" + `

This completes the reconnaissance phase.`

	result, err := ExtractJSON(response)
	require.NoError(t, err)
	assert.Contains(t, result, `"summary"`)
	assert.Contains(t, result, `"key_findings"`)
	assert.Contains(t, result, `"risk_level"`)
	assert.Contains(t, result, "Network reconnaissance")
}

// Test the generic ExtractJSONAs helper
func TestExtractJSONAs_Success(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	response := `{"name": "test", "count": 42}`

	result, err := ExtractJSONAs[TestStruct](response)
	require.NoError(t, err)
	assert.Equal(t, "test", result.Name)
	assert.Equal(t, 42, result.Count)
}

func TestExtractJSONAs_WithMarkdown(t *testing.T) {
	type Decision struct {
		Action     string  `json:"action"`
		Reasoning  string  `json:"reasoning"`
		Confidence float64 `json:"confidence"`
	}

	response := "Here's my decision:\n```json\n{\"action\": \"complete\", \"reasoning\": \"All tasks done\", \"confidence\": 0.95}\n```"

	result, err := ExtractJSONAs[Decision](response)
	require.NoError(t, err)
	assert.Equal(t, "complete", result.Action)
	assert.Equal(t, "All tasks done", result.Reasoning)
	assert.Equal(t, 0.95, result.Confidence)
}

func TestExtractJSONAs_NoJSON(t *testing.T) {
	type TestStruct struct {
		Name string `json:"name"`
	}

	response := "No JSON here"

	_, err := ExtractJSONAs[TestStruct](response)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid JSON")
}

func TestExtractJSONAs_InvalidType(t *testing.T) {
	type TestStruct struct {
		Count int `json:"count"`
	}

	// JSON has count as string, but struct expects int
	response := `{"count": "not a number"}`

	_, err := ExtractJSONAs[TestStruct](response)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

func TestExtractJSONAs_NestedStruct(t *testing.T) {
	type Inner struct {
		Value string `json:"value"`
	}
	type Outer struct {
		Name  string `json:"name"`
		Inner Inner  `json:"inner"`
	}

	response := `{"name": "outer", "inner": {"value": "nested"}}`

	result, err := ExtractJSONAs[Outer](response)
	require.NoError(t, err)
	assert.Equal(t, "outer", result.Name)
	assert.Equal(t, "nested", result.Inner.Value)
}

// Benchmark tests
func BenchmarkExtractJSON_RawJSON(b *testing.B) {
	response := `{"key": "value", "number": 42, "nested": {"inner": "data"}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractJSON(response)
	}
}

func BenchmarkExtractJSON_Markdown(b *testing.B) {
	response := "Here's the data:\n```json\n{\"key\": \"value\", \"number\": 42}\n```\nEnd"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractJSON(response)
	}
}

func BenchmarkExtractJSON_LargeJSON(b *testing.B) {
	// Simulate a larger JSON response
	response := `{
		"summary": "Long mission summary text here",
		"findings": ["finding1", "finding2", "finding3", "finding4", "finding5"],
		"data": {
			"host": "192.168.1.1",
			"ports": [22, 80, 443, 8080],
			"services": {
				"ssh": {"version": "OpenSSH 8.2", "status": "open"},
				"http": {"version": "nginx 1.18.0", "status": "open"}
			}
		}
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractJSON(response)
	}
}
