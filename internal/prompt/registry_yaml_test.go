package prompt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestRegisterFromYAML tests loading prompts from a YAML file
func TestRegisterFromYAML(t *testing.T) {
	registry := NewPromptRegistry()

	// Create temporary YAML file with multiple prompts
	yamlContent := `prompts:
  - id: "yaml-prompt-1"
    name: "First YAML Prompt"
    position: "system"
    priority: 10
    content: "Content from YAML file 1"
  - id: "yaml-prompt-2"
    name: "Second YAML Prompt"
    position: "user"
    priority: 5
    content: "Content from YAML file 2"
`
	tmpFile := createTempYAMLFileForTest(t, yamlContent)
	defer os.Remove(tmpFile)

	// Register from YAML
	err := registry.RegisterFromYAML(tmpFile)
	if err != nil {
		t.Fatalf("RegisterFromYAML failed: %v", err)
	}

	// Verify both prompts were registered
	prompt1, err := registry.Get("yaml-prompt-1")
	if err != nil {
		t.Errorf("Failed to get yaml-prompt-1: %v", err)
	}
	if prompt1.Name != "First YAML Prompt" {
		t.Errorf("Expected name 'First YAML Prompt', got '%s'", prompt1.Name)
	}

	prompt2, err := registry.Get("yaml-prompt-2")
	if err != nil {
		t.Errorf("Failed to get yaml-prompt-2: %v", err)
	}
	if prompt2.Position != PositionUser {
		t.Errorf("Expected position 'user', got '%s'", prompt2.Position)
	}
}

// TestRegisterFromYAML_SinglePrompt tests loading a single prompt format
func TestRegisterFromYAML_SinglePrompt(t *testing.T) {
	registry := NewPromptRegistry()

	yamlContent := `id: "single-yaml-prompt"
name: "Single YAML Prompt"
position: "context"
content: "Single prompt content"
`
	tmpFile := createTempYAMLFileForTest(t, yamlContent)
	defer os.Remove(tmpFile)

	err := registry.RegisterFromYAML(tmpFile)
	if err != nil {
		t.Fatalf("RegisterFromYAML failed: %v", err)
	}

	prompt, err := registry.Get("single-yaml-prompt")
	if err != nil {
		t.Errorf("Failed to get single-yaml-prompt: %v", err)
	}
	if prompt.Position != PositionContext {
		t.Errorf("Expected position 'context', got '%s'", prompt.Position)
	}
}

// TestRegisterFromYAML_FileNotFound tests error handling for missing file
func TestRegisterFromYAML_FileNotFound(t *testing.T) {
	registry := NewPromptRegistry()

	err := registry.RegisterFromYAML("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("Expected error for nonexistent file, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrCodeYAMLParse {
		t.Errorf("Expected error code %s, got %s", ErrCodeYAMLParse, gibsonErr.Code)
	}
}

// TestRegisterFromYAML_InvalidYAML tests error handling for syntax errors
func TestRegisterFromYAML_InvalidYAML(t *testing.T) {
	registry := NewPromptRegistry()

	yamlContent := `id: "test"
name: "Test"
  position: "user"
content: "Content"
`
	tmpFile := createTempYAMLFileForTest(t, yamlContent)
	defer os.Remove(tmpFile)

	err := registry.RegisterFromYAML(tmpFile)
	if err == nil {
		t.Fatal("Expected error for invalid YAML, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrCodeYAMLParse {
		t.Errorf("Expected error code %s, got %s", ErrCodeYAMLParse, gibsonErr.Code)
	}
}

// TestRegisterFromYAML_ValidationError tests validation during registration
func TestRegisterFromYAML_ValidationError(t *testing.T) {
	registry := NewPromptRegistry()

	// Missing required ID field
	yamlContent := `name: "No ID"
position: "user"
content: "Content"
`
	tmpFile := createTempYAMLFileForTest(t, yamlContent)
	defer os.Remove(tmpFile)

	err := registry.RegisterFromYAML(tmpFile)
	if err == nil {
		t.Fatal("Expected validation error, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrCodeYAMLValidation {
		t.Errorf("Expected error code %s, got %s", ErrCodeYAMLValidation, gibsonErr.Code)
	}
}

// TestRegisterFromYAML_DuplicateID tests duplicate ID detection
func TestRegisterFromYAML_DuplicateID(t *testing.T) {
	registry := NewPromptRegistry()

	// Register first prompt manually
	prompt1 := Prompt{
		ID:       "duplicate-id",
		Position: PositionSystem,
		Content:  "First prompt",
	}
	registry.Register(prompt1)

	// Try to register YAML with same ID
	yamlContent := `id: "duplicate-id"
name: "Duplicate"
position: "user"
content: "Second prompt"
`
	tmpFile := createTempYAMLFileForTest(t, yamlContent)
	defer os.Remove(tmpFile)

	err := registry.RegisterFromYAML(tmpFile)
	if err == nil {
		t.Fatal("Expected duplicate ID error, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrCodePromptAlreadyExists {
		t.Errorf("Expected error code %s, got %s", ErrCodePromptAlreadyExists, gibsonErr.Code)
	}
}

// TestRegisterFromDirectory_Success tests loading prompts from a directory
func TestRegisterFromDirectory_Success(t *testing.T) {
	registry := NewPromptRegistry()
	tmpDir := t.TempDir()

	// Create multiple YAML files
	file1Content := `id: "dir-prompt-1"
name: "Directory Prompt 1"
position: "system"
content: "Content 1"
`
	file2Content := `prompts:
  - id: "dir-prompt-2"
    name: "Directory Prompt 2"
    position: "user"
    content: "Content 2"
  - id: "dir-prompt-3"
    name: "Directory Prompt 3"
    position: "context"
    content: "Content 3"
`
	file3Content := `id: "dir-prompt-4"
name: "Directory Prompt 4"
position: "tools"
content: "Content 4"
`

	createTempFileInDir(t, tmpDir, "file1.yaml", file1Content)
	createTempFileInDir(t, tmpDir, "file2.yml", file2Content)
	createTempFileInDir(t, tmpDir, "file3.yaml", file3Content)

	// Create a non-YAML file that should be ignored
	createTempFileInDir(t, tmpDir, "readme.txt", "This should be ignored")

	// Register from directory
	err := registry.RegisterFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("RegisterFromDirectory failed: %v", err)
	}

	// Verify all prompts were registered
	expectedIDs := []string{"dir-prompt-1", "dir-prompt-2", "dir-prompt-3", "dir-prompt-4"}
	for _, id := range expectedIDs {
		_, err := registry.Get(id)
		if err != nil {
			t.Errorf("Failed to get %s: %v", id, err)
		}
	}

	// Verify count
	allPrompts := registry.List()
	if len(allPrompts) != 4 {
		t.Errorf("Expected 4 prompts, got %d", len(allPrompts))
	}
}

// TestRegisterFromDirectory_EmptyDirectory tests empty directory handling
func TestRegisterFromDirectory_EmptyDirectory(t *testing.T) {
	registry := NewPromptRegistry()
	tmpDir := t.TempDir()

	err := registry.RegisterFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("RegisterFromDirectory failed on empty directory: %v", err)
	}

	// Verify no prompts were registered
	prompts := registry.List()
	if len(prompts) != 0 {
		t.Errorf("Expected 0 prompts, got %d", len(prompts))
	}
}

// TestRegisterFromDirectory_DirectoryNotFound tests error handling
func TestRegisterFromDirectory_DirectoryNotFound(t *testing.T) {
	registry := NewPromptRegistry()

	err := registry.RegisterFromDirectory("/nonexistent/directory")
	if err == nil {
		t.Fatal("Expected error for nonexistent directory, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrCodeYAMLParse {
		t.Errorf("Expected error code %s, got %s", ErrCodeYAMLParse, gibsonErr.Code)
	}
}

// TestRegisterFromDirectory_WithInvalidFile tests partial success
func TestRegisterFromDirectory_WithInvalidFile(t *testing.T) {
	registry := NewPromptRegistry()
	tmpDir := t.TempDir()

	validContent := `id: "valid-prompt"
name: "Valid"
position: "user"
content: "Valid content"
`
	invalidContent := `name: "Invalid"
position: "user"
content: "Missing ID"
`

	// Use filenames to ensure valid.yaml is processed before invalid.yaml
	// (alphabetical order: a_valid.yaml comes before z_invalid.yaml)
	createTempFileInDir(t, tmpDir, "a_valid.yaml", validContent)
	createTempFileInDir(t, tmpDir, "z_invalid.yaml", invalidContent)

	err := registry.RegisterFromDirectory(tmpDir)
	if err == nil {
		t.Fatal("Expected error for invalid file in directory")
	}

	// Valid prompt should still be registered
	_, err = registry.Get("valid-prompt")
	if err != nil {
		t.Error("Valid prompt should have been registered despite error")
	}
}

// Helper function for creating temp YAML files in tests
func createTempYAMLFileForTest(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "prompt-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	err = tmpFile.Close()
	if err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}

// Helper function for creating files in a directory
func createTempFileInDir(t *testing.T, dir, filename, content string) {
	t.Helper()
	filePath := filepath.Join(dir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create file %s: %v", filePath, err)
	}
}
