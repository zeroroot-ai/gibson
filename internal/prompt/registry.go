package prompt

import (
	"sort"
	"sync"
)

// PromptRegistry manages prompt registration and retrieval.
// It provides thread-safe operations for storing, retrieving, and managing prompts
// in a centralized registry. The registry is optimized for read-heavy workloads
// using sync.RWMutex.
type PromptRegistry interface {
	// Register adds a prompt to the registry.
	// Returns ErrPromptAlreadyExists if a prompt with the same ID is already registered.
	// Returns a validation error if the prompt is invalid.
	Register(prompt Prompt) error

	// RegisterFromYAML loads prompts from a YAML file and registers them.
	RegisterFromYAML(path string) error

	// RegisterFromDirectory loads all YAML files from a directory and registers them.
	RegisterFromDirectory(dir string) error

	// Get retrieves a prompt by ID.
	// Returns ErrPromptNotFound if the prompt doesn't exist.
	Get(id string) (*Prompt, error)

	// GetByPosition returns prompts at a position, sorted by priority.
	// Prompts are sorted by priority in descending order (higher priority first).
	// Returns an empty slice if no prompts exist at the given position.
	GetByPosition(position Position) []Prompt

	// List returns all registered prompts.
	// The returned slice is a copy and can be safely modified.
	// Returns an empty slice if no prompts are registered.
	List() []Prompt

	// Unregister removes a prompt by ID.
	// Returns ErrPromptNotFound if the prompt doesn't exist.
	Unregister(id string) error

	// Clear removes all prompts from the registry.
	Clear()
}

// DefaultPromptRegistry is the default implementation of PromptRegistry.
// It uses a map for O(1) lookups and sync.RWMutex for thread-safe concurrent access.
// The registry is optimized for read-heavy workloads, allowing multiple concurrent readers.
type DefaultPromptRegistry struct {
	mu      sync.RWMutex
	prompts map[string]Prompt
}

// NewPromptRegistry creates and returns a new DefaultPromptRegistry instance.
// The registry is ready to use and starts empty.
func NewPromptRegistry() PromptRegistry {
	return &DefaultPromptRegistry{
		prompts: make(map[string]Prompt),
	}
}

// Register adds a prompt to the registry.
// The prompt is validated before registration. If validation fails, the prompt
// is not added and a validation error is returned.
// Returns ErrPromptAlreadyExists if a prompt with the same ID already exists.
func (r *DefaultPromptRegistry) Register(prompt Prompt) error {
	// Validate the prompt first
	if err := prompt.Validate(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if prompt already exists
	if _, exists := r.prompts[prompt.ID]; exists {
		return NewPromptAlreadyExistsError(prompt.ID)
	}

	// Add the prompt to the registry
	r.prompts[prompt.ID] = prompt
	return nil
}

// RegisterFromYAML loads prompts from a YAML file and registers them.
// The file can contain either a single prompt or an array of prompts.
// All prompts are validated before registration.
// If a prompt with the same ID already exists, it returns ErrPromptAlreadyExists.
// Returns the first error encountered during loading or registration.
func (r *DefaultPromptRegistry) RegisterFromYAML(path string) error {
	// Load prompts from file
	prompts, err := LoadPromptsFromFile(path)
	if err != nil {
		return err
	}

	// Register each prompt
	for _, prompt := range prompts {
		if err := r.Register(prompt); err != nil {
			return err
		}
	}

	return nil
}

// RegisterFromDirectory loads all YAML files (.yaml and .yml) from a directory
// and registers the prompts they contain.
// Subdirectories are not processed recursively.
// If a prompt with the same ID already exists, it returns ErrPromptAlreadyExists.
// Returns the first error encountered during loading or registration.
// Note: If LoadPromptsFromDirectory returns an error, successfully loaded prompts
// are still registered before the error is returned.
func (r *DefaultPromptRegistry) RegisterFromDirectory(dir string) error {
	// Load prompts from directory
	prompts, loadErr := LoadPromptsFromDirectory(dir)

	// Register each successfully loaded prompt
	for _, prompt := range prompts {
		if err := r.Register(prompt); err != nil {
			return err
		}
	}

	// Return load error after attempting to register all prompts
	return loadErr
}

// Get retrieves a prompt by ID.
// Returns a pointer to a copy of the prompt to prevent external modification.
// Returns ErrPromptNotFound if the prompt doesn't exist in the registry.
func (r *DefaultPromptRegistry) Get(id string) (*Prompt, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	prompt, exists := r.prompts[id]
	if !exists {
		return nil, NewPromptNotFoundError(id)
	}

	// Return a copy to prevent external modification
	promptCopy := prompt
	return &promptCopy, nil
}

// GetByPosition returns prompts at a position, sorted by priority.
// Prompts with higher priority values appear first in the returned slice.
// Returns an empty slice if no prompts exist at the given position.
// The returned slice is a new slice and can be safely modified.
func (r *DefaultPromptRegistry) GetByPosition(position Position) []Prompt {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect prompts at the specified position
	var matched []Prompt
	for _, p := range r.prompts {
		if p.Position == position {
			matched = append(matched, p)
		}
	}

	// Sort by priority descending (higher priority first)
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Priority > matched[j].Priority
	})

	return matched
}

// List returns all registered prompts.
// The returned slice is a new slice containing copies of all prompts.
// The slice can be safely modified without affecting the registry.
// Returns an empty slice if no prompts are registered.
func (r *DefaultPromptRegistry) List() []Prompt {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.prompts) == 0 {
		return []Prompt{}
	}

	// Create a slice with all prompts
	prompts := make([]Prompt, 0, len(r.prompts))
	for _, p := range r.prompts {
		prompts = append(prompts, p)
	}

	return prompts
}

// Unregister removes a prompt by ID.
// Returns ErrPromptNotFound if the prompt doesn't exist.
func (r *DefaultPromptRegistry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.prompts[id]; !exists {
		return NewPromptNotFoundError(id)
	}

	delete(r.prompts, id)
	return nil
}

// Clear removes all prompts from the registry.
// After calling Clear, the registry is empty and ready for new registrations.
func (r *DefaultPromptRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.prompts = make(map[string]Prompt)
}
