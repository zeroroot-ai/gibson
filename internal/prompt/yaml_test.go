package prompt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestLoadPromptsFromFile_ValidSinglePrompt(t *testing.T) {
	// Create temporary YAML file with single prompt
	yamlContent := `id: "single-prompt"
name: "Single Prompt"
position: "user"
priority: 5
content: "This is a single prompt content."
description: "A test prompt"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	// Load prompts
	prompts, err := LoadPromptsFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, prompts, 1)

	// Verify prompt fields
	p := prompts[0]
	assert.Equal(t, "single-prompt", p.ID)
	assert.Equal(t, "Single Prompt", p.Name)
	assert.Equal(t, PositionUser, p.Position)
	assert.Equal(t, 5, p.Priority)
	assert.Equal(t, "This is a single prompt content.", p.Content)
	assert.Equal(t, "A test prompt", p.Description)
}

func TestLoadPromptsFromFile_ValidPromptsArray(t *testing.T) {
	// Create temporary YAML file with multiple prompts
	yamlContent := `prompts:
  - id: "prompt-1"
    name: "First Prompt"
    position: "system"
    priority: 10
    content: |
      This is the first prompt.
      It has multiple lines.
  - id: "prompt-2"
    name: "Second Prompt"
    position: "user"
    priority: 5
    content: "This is the second prompt."
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	// Load prompts
	prompts, err := LoadPromptsFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, prompts, 2)

	// Verify first prompt
	p1 := prompts[0]
	assert.Equal(t, "prompt-1", p1.ID)
	assert.Equal(t, "First Prompt", p1.Name)
	assert.Equal(t, PositionSystem, p1.Position)
	assert.Equal(t, 10, p1.Priority)
	assert.Contains(t, p1.Content, "This is the first prompt.")
	assert.Contains(t, p1.Content, "It has multiple lines.")

	// Verify second prompt
	p2 := prompts[1]
	assert.Equal(t, "prompt-2", p2.ID)
	assert.Equal(t, "Second Prompt", p2.Name)
	assert.Equal(t, PositionUser, p2.Position)
	assert.Equal(t, 5, p2.Priority)
	assert.Equal(t, "This is the second prompt.", p2.Content)
}

func TestLoadPromptsFromFile_WithVariablesAndConditions(t *testing.T) {
	yamlContent := `id: "complex-prompt"
name: "Complex Prompt"
position: "context"
content: "Target: {{target_url}}"
variables:
  - name: "target_url"
    description: "The target URL"
    required: true
    source: "mission.target.url"
conditions:
  - field: "mission.active"
    operator: "eq"
    value: true
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, prompts, 1)

	p := prompts[0]
	assert.Equal(t, "complex-prompt", p.ID)
	require.Len(t, p.Variables, 1)
	assert.Equal(t, "target_url", p.Variables[0].Name)
	assert.True(t, p.Variables[0].Required)
	assert.Equal(t, "mission.target.url", p.Variables[0].Source)

	require.Len(t, p.Conditions, 1)
	assert.Equal(t, "mission.active", p.Conditions[0].Field)
	assert.Equal(t, "eq", p.Conditions[0].Operator)
	assert.Equal(t, true, p.Conditions[0].Value)
}

func TestLoadPromptsFromFile_WithExamples(t *testing.T) {
	yamlContent := `id: "example-prompt"
name: "Prompt with Examples"
position: "examples"
content: "Generate a response"
examples:
  - description: "Simple greeting"
    input: "Hello"
    output: "Hi there!"
  - input: "Goodbye"
    output: "See you later!"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, prompts, 1)

	p := prompts[0]
	require.Len(t, p.Examples, 2)
	assert.Equal(t, "Simple greeting", p.Examples[0].Description)
	assert.Equal(t, "Hello", p.Examples[0].Input)
	assert.Equal(t, "Hi there!", p.Examples[0].Output)
	assert.Equal(t, "Goodbye", p.Examples[1].Input)
	assert.Equal(t, "See you later!", p.Examples[1].Output)
}

func TestLoadPromptsFromFile_SyntaxError(t *testing.T) {
	// Create YAML with syntax error (invalid indentation)
	yamlContent := `id: "test"
name: "Test"
  position: "user"
content: "Content"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.Error(t, err)
	assert.Nil(t, prompts)

	// Verify error type
	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLParse, gibsonErr.Code)
	assert.Contains(t, err.Error(), tmpFile)
}

func TestLoadPromptsFromFile_MissingID(t *testing.T) {
	yamlContent := `name: "No ID Prompt"
position: "user"
content: "Content without ID"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.Error(t, err)
	assert.Nil(t, prompts)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLValidation, gibsonErr.Code)
	assert.Contains(t, err.Error(), "validation")
}

func TestLoadPromptsFromFile_MissingContent(t *testing.T) {
	yamlContent := `id: "no-content"
name: "No Content Prompt"
position: "user"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.Error(t, err)
	assert.Nil(t, prompts)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLValidation, gibsonErr.Code)
}

func TestLoadPromptsFromFile_InvalidPosition(t *testing.T) {
	yamlContent := `id: "invalid-position"
name: "Invalid Position"
position: "invalid_position_name"
content: "Some content"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.Error(t, err)
	assert.Nil(t, prompts)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLValidation, gibsonErr.Code)
}

func TestLoadPromptsFromFile_FileNotFound(t *testing.T) {
	prompts, err := LoadPromptsFromFile("/nonexistent/path/to/file.yaml")
	require.Error(t, err)
	assert.Nil(t, prompts)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLParse, gibsonErr.Code)
	assert.Contains(t, err.Error(), "failed to read file")
}

func TestLoadPromptsFromDirectory_ValidFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple YAML files
	file1 := `id: "prompt-1"
name: "First"
position: "system"
content: "First prompt"
`
	file2 := `prompts:
  - id: "prompt-2"
    name: "Second"
    position: "user"
    content: "Second prompt"
  - id: "prompt-3"
    name: "Third"
    position: "context"
    content: "Third prompt"
`
	file3 := `id: "prompt-4"
name: "Fourth"
position: "tools"
content: "Fourth prompt"
`

	createTempYAMLFileInDir(t, tmpDir, "file1.yaml", file1)
	createTempYAMLFileInDir(t, tmpDir, "file2.yml", file2)
	createTempYAMLFileInDir(t, tmpDir, "file3.yaml", file3)

	// Create a non-YAML file that should be ignored
	createTempYAMLFileInDir(t, tmpDir, "readme.txt", "This should be ignored")

	// Load all prompts
	prompts, err := LoadPromptsFromDirectory(tmpDir)
	require.NoError(t, err)
	require.Len(t, prompts, 4)

	// Verify we got all prompts
	ids := make([]string, len(prompts))
	for i, p := range prompts {
		ids[i] = p.ID
	}
	assert.Contains(t, ids, "prompt-1")
	assert.Contains(t, ids, "prompt-2")
	assert.Contains(t, ids, "prompt-3")
	assert.Contains(t, ids, "prompt-4")
}

func TestLoadPromptsFromDirectory_MixedValidAndInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid file
	validFile := `id: "valid-prompt"
name: "Valid"
position: "user"
content: "Valid content"
`
	// Create invalid file (missing ID)
	invalidFile := `name: "Invalid"
position: "user"
content: "No ID"
`

	createTempYAMLFileInDir(t, tmpDir, "valid.yaml", validFile)
	createTempYAMLFileInDir(t, tmpDir, "invalid.yaml", invalidFile)

	// Load prompts - should return valid ones and first error
	prompts, err := LoadPromptsFromDirectory(tmpDir)
	require.Error(t, err)      // Should have error from invalid file
	require.Len(t, prompts, 1) // Should still load valid prompt

	assert.Equal(t, "valid-prompt", prompts[0].ID)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLValidation, gibsonErr.Code)
}

func TestLoadPromptsFromDirectory_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	prompts, err := LoadPromptsFromDirectory(tmpDir)
	require.NoError(t, err)
	assert.Empty(t, prompts)
}

func TestLoadPromptsFromDirectory_DirectoryNotFound(t *testing.T) {
	prompts, err := LoadPromptsFromDirectory("/nonexistent/directory")
	require.Error(t, err)
	assert.Nil(t, prompts)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeYAMLParse, gibsonErr.Code)
}

func TestLoadPromptsFromDirectory_WithSubdirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file in root
	rootFile := `id: "root-prompt"
name: "Root"
position: "user"
content: "Root content"
`
	createTempYAMLFileInDir(t, tmpDir, "root.yaml", rootFile)

	// Create a subdirectory with a file (should be ignored)
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))
	subFile := `id: "sub-prompt"
name: "Sub"
position: "user"
content: "Sub content"
`
	createTempYAMLFileInDir(t, subDir, "sub.yaml", subFile)

	// Load prompts - should only get root file
	prompts, err := LoadPromptsFromDirectory(tmpDir)
	require.NoError(t, err)
	require.Len(t, prompts, 1)
	assert.Equal(t, "root-prompt", prompts[0].ID)
}

func TestLoadPromptsFromFile_MultilineContent(t *testing.T) {
	yamlContent := `id: "multiline"
name: "Multiline Prompt"
position: "system"
content: |
  This is line 1
  This is line 2
  This is line 3
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, prompts, 1)

	content := prompts[0].Content
	assert.Contains(t, content, "This is line 1")
	assert.Contains(t, content, "This is line 2")
	assert.Contains(t, content, "This is line 3")
	// YAML "|" preserves newlines
	assert.True(t, strings.Contains(content, "\n"))
}

func TestLoadPromptsFromFile_WithMetadata(t *testing.T) {
	yamlContent := `id: "meta-prompt"
name: "Prompt with Metadata"
position: "user"
content: "Content"
metadata:
  author: "test-user"
  version: "1.0"
  tags:
    - "test"
    - "example"
`

	tmpFile := createTempYAMLFile(t, yamlContent)
	defer os.Remove(tmpFile)

	prompts, err := LoadPromptsFromFile(tmpFile)
	require.NoError(t, err)
	require.Len(t, prompts, 1)

	p := prompts[0]
	require.NotNil(t, p.Metadata)
	assert.Equal(t, "test-user", p.Metadata["author"])
	assert.Equal(t, "1.0", p.Metadata["version"])

	tags, ok := p.Metadata["tags"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tags, 2)
}

func TestLoadPromptsFromFile_AllPositions(t *testing.T) {
	// Test that all valid positions are accepted
	positions := []Position{
		PositionSystemPrefix,
		PositionSystem,
		PositionSystemSuffix,
		PositionContext,
		PositionTools,
		PositionPlugins,
		PositionAgents,
		PositionConstraints,
		PositionExamples,
		PositionUserPrefix,
		PositionUser,
		PositionUserSuffix,
	}

	for _, pos := range positions {
		t.Run(string(pos), func(t *testing.T) {
			yamlContent := fmt.Sprintf(`id: "test-%s"
name: "Test"
position: "%s"
content: "Test content"
`, pos, pos)

			tmpFile := createTempYAMLFile(t, yamlContent)
			defer os.Remove(tmpFile)

			prompts, err := LoadPromptsFromFile(tmpFile)
			require.NoError(t, err)
			require.Len(t, prompts, 1)
			assert.Equal(t, pos, prompts[0].Position)
		})
	}
}

// Helper functions

func createTempYAMLFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "prompt-*.yaml")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

func createTempYAMLFileInDir(t *testing.T, dir, filename, content string) {
	t.Helper()
	filePath := filepath.Join(dir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)
}
