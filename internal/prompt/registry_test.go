package prompt

import (
	"fmt"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestNewPromptRegistry tests that the constructor creates a valid registry
func TestNewPromptRegistry(t *testing.T) {
	registry := NewPromptRegistry()

	if registry == nil {
		t.Fatal("NewPromptRegistry() returned nil")
	}

	// Verify registry starts empty
	prompts := registry.List()
	if len(prompts) != 0 {
		t.Errorf("New registry should be empty, got %d prompts", len(prompts))
	}
}

// TestRegister tests basic prompt registration
func TestRegister(t *testing.T) {
	registry := NewPromptRegistry()

	prompt := Prompt{
		ID:       "test-prompt",
		Name:     "Test Prompt",
		Position: PositionSystem,
		Content:  "This is a test prompt",
		Priority: 100,
	}

	// Register the prompt
	err := registry.Register(prompt)
	if err != nil {
		t.Fatalf("Failed to register prompt: %v", err)
	}

	// Verify it was registered
	retrieved, err := registry.Get("test-prompt")
	if err != nil {
		t.Fatalf("Failed to retrieve registered prompt: %v", err)
	}

	if retrieved.ID != prompt.ID {
		t.Errorf("Expected ID %s, got %s", prompt.ID, retrieved.ID)
	}
	if retrieved.Name != prompt.Name {
		t.Errorf("Expected Name %s, got %s", prompt.Name, retrieved.Name)
	}
	if retrieved.Position != prompt.Position {
		t.Errorf("Expected Position %s, got %s", prompt.Position, retrieved.Position)
	}
	if retrieved.Content != prompt.Content {
		t.Errorf("Expected Content %s, got %s", prompt.Content, retrieved.Content)
	}
	if retrieved.Priority != prompt.Priority {
		t.Errorf("Expected Priority %d, got %d", prompt.Priority, retrieved.Priority)
	}
}

// TestRegisterValidation tests that registration validates prompts
func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name        string
		prompt      Prompt
		expectError bool
		errorCode   types.ErrorCode
	}{
		{
			name: "valid prompt",
			prompt: Prompt{
				ID:       "valid",
				Position: PositionSystem,
				Content:  "Valid content",
			},
			expectError: false,
		},
		{
			name: "missing ID",
			prompt: Prompt{
				Position: PositionSystem,
				Content:  "Content without ID",
			},
			expectError: true,
			errorCode:   PROMPT_EMPTY_ID,
		},
		{
			name: "invalid position",
			prompt: Prompt{
				ID:       "invalid-pos",
				Position: Position("invalid"),
				Content:  "Content with invalid position",
			},
			expectError: true,
			errorCode:   PROMPT_INVALID_POSITION,
		},
		{
			name: "missing content",
			prompt: Prompt{
				ID:       "no-content",
				Position: PositionSystem,
				Content:  "",
			},
			expectError: true,
			errorCode:   PROMPT_EMPTY_CONTENT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewPromptRegistry()
			err := registry.Register(tt.prompt)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
					return
				}

				gibsonErr, ok := err.(*types.GibsonError)
				if !ok {
					t.Errorf("Expected GibsonError, got %T", err)
					return
				}

				if gibsonErr.Code != tt.errorCode {
					t.Errorf("Expected error code %s, got %s", tt.errorCode, gibsonErr.Code)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

// TestRegisterAlreadyExists tests duplicate ID detection
func TestRegisterAlreadyExists(t *testing.T) {
	registry := NewPromptRegistry()

	prompt := Prompt{
		ID:       "duplicate",
		Position: PositionSystem,
		Content:  "First registration",
	}

	// First registration should succeed
	err := registry.Register(prompt)
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	// Second registration with same ID should fail
	prompt2 := Prompt{
		ID:       "duplicate",
		Position: PositionUser,
		Content:  "Second registration",
	}

	err = registry.Register(prompt2)
	if err == nil {
		t.Fatal("Expected error for duplicate ID, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodePromptAlreadyExists {
		t.Errorf("Expected error code %s, got %s", ErrCodePromptAlreadyExists, gibsonErr.Code)
	}

	// Verify the original prompt is still there
	retrieved, _ := registry.Get("duplicate")
	if retrieved.Content != "First registration" {
		t.Error("Original prompt was modified")
	}
}

// TestGet tests prompt retrieval
func TestGet(t *testing.T) {
	registry := NewPromptRegistry()

	prompt := Prompt{
		ID:       "test",
		Position: PositionSystem,
		Content:  "Test content",
	}

	registry.Register(prompt)

	// Test successful retrieval
	retrieved, err := registry.Get("test")
	if err != nil {
		t.Fatalf("Failed to get prompt: %v", err)
	}

	if retrieved.ID != prompt.ID {
		t.Errorf("Retrieved wrong prompt")
	}

	// Test not found error
	_, err = registry.Get("nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent prompt, got nil")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodePromptNotFound {
		t.Errorf("Expected error code %s, got %s", ErrCodePromptNotFound, gibsonErr.Code)
	}
}

// TestGetByPosition tests filtering and sorting by position
func TestGetByPosition(t *testing.T) {
	registry := NewPromptRegistry()

	// Register prompts with different positions and priorities
	prompts := []Prompt{
		{ID: "sys1", Position: PositionSystem, Content: "System 1", Priority: 100},
		{ID: "sys2", Position: PositionSystem, Content: "System 2", Priority: 200},
		{ID: "sys3", Position: PositionSystem, Content: "System 3", Priority: 50},
		{ID: "user1", Position: PositionUser, Content: "User 1", Priority: 100},
		{ID: "ctx1", Position: PositionContext, Content: "Context 1", Priority: 150},
	}

	for _, p := range prompts {
		if err := registry.Register(p); err != nil {
			t.Fatalf("Failed to register prompt %s: %v", p.ID, err)
		}
	}

	// Test getting system prompts
	systemPrompts := registry.GetByPosition(PositionSystem)
	if len(systemPrompts) != 3 {
		t.Errorf("Expected 3 system prompts, got %d", len(systemPrompts))
	}

	// Verify sorting by priority (higher priority first)
	expectedOrder := []string{"sys2", "sys1", "sys3"}
	for i, expected := range expectedOrder {
		if systemPrompts[i].ID != expected {
			t.Errorf("Expected prompt %s at index %d, got %s", expected, i, systemPrompts[i].ID)
		}
	}

	// Test getting user prompts
	userPrompts := registry.GetByPosition(PositionUser)
	if len(userPrompts) != 1 {
		t.Errorf("Expected 1 user prompt, got %d", len(userPrompts))
	}
	if userPrompts[0].ID != "user1" {
		t.Errorf("Expected user1, got %s", userPrompts[0].ID)
	}

	// Test empty position
	pluginPrompts := registry.GetByPosition(PositionPlugins)
	if len(pluginPrompts) != 0 {
		t.Errorf("Expected 0 plugin prompts, got %d", len(pluginPrompts))
	}
}

// TestGetByPositionPrioritySorting tests detailed priority sorting
func TestGetByPositionPrioritySorting(t *testing.T) {
	registry := NewPromptRegistry()

	// Register prompts with same position but different priorities
	priorities := []int{5, 10, 1, 8, 3, 12, 7}
	for i, priority := range priorities {
		prompt := Prompt{
			ID:       fmt.Sprintf("p%d", i),
			Position: PositionSystem,
			Content:  fmt.Sprintf("Priority %d", priority),
			Priority: priority,
		}
		registry.Register(prompt)
	}

	results := registry.GetByPosition(PositionSystem)

	// Verify descending order
	for i := 1; i < len(results); i++ {
		if results[i-1].Priority < results[i].Priority {
			t.Errorf("Priorities not in descending order: %d came before %d",
				results[i-1].Priority, results[i].Priority)
		}
	}
}

// TestList tests listing all prompts
func TestList(t *testing.T) {
	registry := NewPromptRegistry()

	// Empty registry
	prompts := registry.List()
	if len(prompts) != 0 {
		t.Errorf("Expected empty list, got %d prompts", len(prompts))
	}

	// Add some prompts
	for i := 0; i < 5; i++ {
		prompt := Prompt{
			ID:       fmt.Sprintf("p%d", i),
			Position: PositionSystem,
			Content:  fmt.Sprintf("Content %d", i),
		}
		registry.Register(prompt)
	}

	prompts = registry.List()
	if len(prompts) != 5 {
		t.Errorf("Expected 5 prompts, got %d", len(prompts))
	}

	// Verify all prompts are present
	ids := make(map[string]bool)
	for _, p := range prompts {
		ids[p.ID] = true
	}

	for i := 0; i < 5; i++ {
		expectedID := fmt.Sprintf("p%d", i)
		if !ids[expectedID] {
			t.Errorf("Missing prompt %s in list", expectedID)
		}
	}
}

// TestUnregister tests prompt removal
func TestUnregister(t *testing.T) {
	registry := NewPromptRegistry()

	prompt := Prompt{
		ID:       "to-remove",
		Position: PositionSystem,
		Content:  "Will be removed",
	}

	registry.Register(prompt)

	// Verify it exists
	_, err := registry.Get("to-remove")
	if err != nil {
		t.Fatal("Prompt should exist before unregistering")
	}

	// Unregister it
	err = registry.Unregister("to-remove")
	if err != nil {
		t.Fatalf("Failed to unregister: %v", err)
	}

	// Verify it's gone
	_, err = registry.Get("to-remove")
	if err == nil {
		t.Fatal("Prompt should not exist after unregistering")
	}

	// Unregistering again should fail
	err = registry.Unregister("to-remove")
	if err == nil {
		t.Fatal("Expected error when unregistering nonexistent prompt")
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodePromptNotFound {
		t.Errorf("Expected error code %s, got %s", ErrCodePromptNotFound, gibsonErr.Code)
	}
}

// TestClear tests clearing all prompts
func TestClear(t *testing.T) {
	registry := NewPromptRegistry()

	// Add several prompts
	for i := 0; i < 10; i++ {
		prompt := Prompt{
			ID:       fmt.Sprintf("p%d", i),
			Position: PositionSystem,
			Content:  fmt.Sprintf("Content %d", i),
		}
		registry.Register(prompt)
	}

	// Verify they exist
	if len(registry.List()) != 10 {
		t.Fatal("Expected 10 prompts before clear")
	}

	// Clear the registry
	registry.Clear()

	// Verify it's empty
	prompts := registry.List()
	if len(prompts) != 0 {
		t.Errorf("Expected 0 prompts after clear, got %d", len(prompts))
	}

	// Verify we can add new prompts after clear
	newPrompt := Prompt{
		ID:       "after-clear",
		Position: PositionSystem,
		Content:  "After clear",
	}

	err := registry.Register(newPrompt)
	if err != nil {
		t.Errorf("Failed to register after clear: %v", err)
	}
}

// TestConcurrentAccess tests thread safety with concurrent operations
func TestConcurrentAccess(t *testing.T) {
	registry := NewPromptRegistry()
	const numGoroutines = 100
	const numOperations = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // readers, writers, and unregisters

	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				prompt := Prompt{
					ID:       fmt.Sprintf("writer-%d-%d", id, j),
					Position: PositionSystem,
					Content:  fmt.Sprintf("Content from writer %d op %d", id, j),
					Priority: id*numOperations + j,
				}
				registry.Register(prompt)
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				// Try to read various prompts
				targetID := fmt.Sprintf("writer-%d-%d", id%10, j%10)
				registry.Get(targetID)
				registry.GetByPosition(PositionSystem)
				registry.List()
			}
		}(i)
	}

	// Concurrent unregisters (some will fail, that's okay)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				targetID := fmt.Sprintf("writer-%d-%d", id%50, j%5)
				registry.Unregister(targetID)
			}
		}(i)
	}

	// Wait for all operations to complete
	wg.Wait()

	// Verify the registry is still functional
	testPrompt := Prompt{
		ID:       "final-test",
		Position: PositionSystem,
		Content:  "Final test after concurrent access",
	}

	err := registry.Register(testPrompt)
	if err != nil {
		t.Errorf("Registry not functional after concurrent access: %v", err)
	}

	retrieved, err := registry.Get("final-test")
	if err != nil {
		t.Errorf("Failed to retrieve after concurrent access: %v", err)
	}
	if retrieved.ID != "final-test" {
		t.Error("Retrieved wrong prompt after concurrent access")
	}
}

// TestConcurrentGetByPosition tests concurrent access to GetByPosition
func TestConcurrentGetByPosition(t *testing.T) {
	registry := NewPromptRegistry()

	// Register prompts across different positions
	positions := AllPositions()
	for i, pos := range positions {
		for j := 0; j < 5; j++ {
			prompt := Prompt{
				ID:       fmt.Sprintf("%s-%d", pos, j),
				Position: pos,
				Content:  fmt.Sprintf("Content for %s #%d", pos, j),
				Priority: j * 10,
			}
			registry.Register(prompt)
		}
		_ = i // avoid unused variable
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent readers of different positions
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			pos := positions[id%len(positions)]
			prompts := registry.GetByPosition(pos)

			// Verify sorting
			for i := 1; i < len(prompts); i++ {
				if prompts[i-1].Priority < prompts[i].Priority {
					t.Errorf("Position %s not properly sorted", pos)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestGetReturnsCopy tests that Get returns a copy, not a reference
func TestGetReturnsCopy(t *testing.T) {
	registry := NewPromptRegistry()

	original := Prompt{
		ID:       "test",
		Position: PositionSystem,
		Content:  "Original content",
		Priority: 100,
	}

	registry.Register(original)

	// Get the prompt
	retrieved, _ := registry.Get("test")

	// Modify the retrieved prompt
	retrieved.Content = "Modified content"
	retrieved.Priority = 999

	// Get it again and verify it wasn't affected
	retrieved2, _ := registry.Get("test")

	if retrieved2.Content != "Original content" {
		t.Error("Modifying returned prompt affected the registry")
	}
	if retrieved2.Priority != 100 {
		t.Error("Modifying returned prompt priority affected the registry")
	}
}

// TestListReturnsCopy tests that List returns a new slice
func TestListReturnsCopy(t *testing.T) {
	registry := NewPromptRegistry()

	original := Prompt{
		ID:       "test",
		Position: PositionSystem,
		Content:  "Original",
	}

	registry.Register(original)

	// Get the list
	list1 := registry.List()

	// Modify the slice
	if len(list1) > 0 {
		list1[0].Content = "Modified"
	}

	// Get the list again
	list2 := registry.List()

	if list2[0].Content != "Original" {
		t.Error("Modifying returned list affected the registry")
	}
}

// TestGetByPositionReturnsCopy tests that GetByPosition returns a new slice
func TestGetByPositionReturnsCopy(t *testing.T) {
	registry := NewPromptRegistry()

	original := Prompt{
		ID:       "test",
		Position: PositionSystem,
		Content:  "Original",
	}

	registry.Register(original)

	// Get the prompts
	prompts1 := registry.GetByPosition(PositionSystem)

	// Modify the slice
	if len(prompts1) > 0 {
		prompts1[0].Content = "Modified"
	}

	// Get the prompts again
	prompts2 := registry.GetByPosition(PositionSystem)

	if prompts2[0].Content != "Original" {
		t.Error("Modifying returned slice affected the registry")
	}
}

// BenchmarkRegister benchmarks prompt registration
func BenchmarkRegister(b *testing.B) {
	registry := NewPromptRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prompt := Prompt{
			ID:       fmt.Sprintf("bench-%d", i),
			Position: PositionSystem,
			Content:  "Benchmark content",
		}
		registry.Register(prompt)
	}
}

// BenchmarkGet benchmarks prompt retrieval
func BenchmarkGet(b *testing.B) {
	registry := NewPromptRegistry()

	// Pre-populate with 1000 prompts
	for i := 0; i < 1000; i++ {
		prompt := Prompt{
			ID:       fmt.Sprintf("bench-%d", i),
			Position: PositionSystem,
			Content:  fmt.Sprintf("Content %d", i),
		}
		registry.Register(prompt)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.Get(fmt.Sprintf("bench-%d", i%1000))
	}
}

// BenchmarkGetByPosition benchmarks filtering by position
func BenchmarkGetByPosition(b *testing.B) {
	registry := NewPromptRegistry()

	// Pre-populate with prompts across all positions
	positions := AllPositions()
	for i := 0; i < 1000; i++ {
		prompt := Prompt{
			ID:       fmt.Sprintf("bench-%d", i),
			Position: positions[i%len(positions)],
			Content:  fmt.Sprintf("Content %d", i),
			Priority: i,
		}
		registry.Register(prompt)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.GetByPosition(positions[i%len(positions)])
	}
}

// BenchmarkConcurrentReads benchmarks concurrent read operations
func BenchmarkConcurrentReads(b *testing.B) {
	registry := NewPromptRegistry()

	// Pre-populate
	for i := 0; i < 100; i++ {
		prompt := Prompt{
			ID:       fmt.Sprintf("bench-%d", i),
			Position: PositionSystem,
			Content:  fmt.Sprintf("Content %d", i),
		}
		registry.Register(prompt)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			registry.Get(fmt.Sprintf("bench-%d", i%100))
			i++
		}
	})
}
