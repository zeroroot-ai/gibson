package prompt_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zeroroot-ai/gibson/internal/prompt"
	"github.com/zeroroot-ai/gibson/internal/state"
)

// ExampleRedisPromptStore_Save demonstrates how to save a prompt to Redis
func ExampleRedisPromptStore_Save() {
	// Create a StateClient connection to Redis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	// Create a RedisPromptStore
	store := prompt.NewRedisPromptStore(client)

	// Create a prompt
	p := &prompt.Prompt{
		ID:          "greeting",
		Name:        "greeting",
		Description: "A friendly greeting prompt",
		Position:    prompt.PositionSystem,
		Content:     "Hello {{.name}}, welcome to Gibson!",
		Variables: []prompt.VariableDef{
			{Name: "name", Required: true},
		},
		Priority: 10,
	}

	// Save the prompt
	ctx := context.Background()
	if err := store.Save(ctx, p); err != nil {
		log.Fatalf("Failed to save prompt: %v", err)
	}

	fmt.Println("Prompt saved successfully")
}

// ExampleRedisPromptStore_Get demonstrates how to retrieve a prompt from Redis
func ExampleRedisPromptStore_Get() {
	// Create a StateClient connection to Redis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	// Create a RedisPromptStore
	store := prompt.NewRedisPromptStore(client)

	// Retrieve a prompt by name
	ctx := context.Background()
	p, err := store.Get(ctx, "greeting")
	if err != nil {
		log.Fatalf("Failed to get prompt: %v", err)
	}

	fmt.Printf("Retrieved prompt: %s\n", p.Name)
	fmt.Printf("Content: %s\n", p.Content)
}

// ExampleRedisPromptStore_List demonstrates how to list all prompts
func ExampleRedisPromptStore_List() {
	// Create a StateClient connection to Redis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	// Create a RedisPromptStore
	store := prompt.NewRedisPromptStore(client)

	// List all prompts
	ctx := context.Background()
	prompts, err := store.List(ctx)
	if err != nil {
		log.Fatalf("Failed to list prompts: %v", err)
	}

	fmt.Printf("Found %d prompts\n", len(prompts))
	for _, p := range prompts {
		fmt.Printf("- %s: %s\n", p.Name, p.Description)
	}
}

// ExampleRedisPromptStore_Watch demonstrates hot-reload with Watch
func ExampleRedisPromptStore_Watch() {
	// Create a StateClient connection to Redis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	// Create a RedisPromptStore
	store := prompt.NewRedisPromptStore(client)

	// Start watching for changes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	eventCh, err := store.Watch(ctx)
	if err != nil {
		log.Fatalf("Failed to watch prompts: %v", err)
	}

	// Handle events in a goroutine
	go func() {
		for event := range eventCh {
			switch event.Type {
			case prompt.ChangeTypeUpdate:
				fmt.Printf("Prompt updated: %s at %s\n", event.Name, event.Timestamp)
				// Reload the prompt here
				p, err := store.Get(context.Background(), event.Name)
				if err == nil {
					fmt.Printf("Reloaded: %s\n", p.Content)
				}
			case prompt.ChangeTypeDelete:
				fmt.Printf("Prompt deleted: %s at %s\n", event.Name, event.Timestamp)
				// Remove from local cache
			}
		}
	}()

	// Simulate some changes
	p := &prompt.Prompt{
		ID:       "dynamic-prompt",
		Name:     "dynamic-prompt",
		Position: prompt.PositionSystem,
		Content:  "This prompt can be hot-reloaded",
	}

	// Save will trigger an update event
	if err := store.Save(context.Background(), p); err != nil {
		log.Fatalf("Failed to save prompt: %v", err)
	}

	// Wait for events to be processed
	time.Sleep(1 * time.Second)
}

// ExampleRedisPromptStore_Delete demonstrates deleting a prompt
func ExampleRedisPromptStore_Delete() {
	// Create a StateClient connection to Redis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	// Create a RedisPromptStore
	store := prompt.NewRedisPromptStore(client)

	// Delete a prompt
	ctx := context.Background()
	if err := store.Delete(ctx, "greeting"); err != nil {
		log.Fatalf("Failed to delete prompt: %v", err)
	}

	fmt.Println("Prompt deleted successfully")
}

// ExampleRedisPromptStore_Exists demonstrates checking if a prompt exists
func ExampleRedisPromptStore_Exists() {
	// Create a StateClient connection to Redis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	// Create a RedisPromptStore
	store := prompt.NewRedisPromptStore(client)

	// Check if a prompt exists
	ctx := context.Background()
	exists, err := store.Exists(ctx, "greeting")
	if err != nil {
		log.Fatalf("Failed to check existence: %v", err)
	}

	if exists {
		fmt.Println("Prompt exists")
	} else {
		fmt.Println("Prompt does not exist")
	}
}
