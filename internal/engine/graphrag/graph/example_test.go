// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph_test

import (
	"context"
	"fmt"
	"log"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
)

// Example demonstrating basic Neo4j client usage.
func ExampleNewNeo4jClient() {
	// Configure the client
	config := graph.DefaultConfig()
	config.URI = "bolt://localhost:7687"
	config.Username = "neo4j"
	config.Password = "password"

	// Create client
	client, err := graph.NewNeo4jClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Connect to database
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close(ctx)

	// Check health
	status := client.Health(ctx)
	fmt.Printf("Health: %s\n", status.State)
}

// Example demonstrating Cypher query execution.
func ExampleGraphClient_Query() {
	// Use mock client for example
	client := graph.NewMockGraphClient()
	ctx := context.Background()

	_ = client.Connect(ctx)
	defer client.Close(ctx)

	// Configure mock response
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"name": "Alice", "age": 30},
			{"name": "Bob", "age": 25},
		},
		Columns: []string{"name", "age"},
	})

	// Execute query
	result, _ := client.Query(ctx,
		"MATCH (n:Person) RETURN n.name as name, n.age as age",
		nil,
	)

	// Process results
	for _, record := range result.Records {
		fmt.Printf("Name: %s, Age: %d\n", record["name"], record["age"])
	}

	// Output:
	// Name: Alice, Age: 30
	// Name: Bob, Age: 25
}

// Example demonstrating configuration validation.
func ExampleGraphClientConfig_Validate() {
	config := graph.GraphClientConfig{
		URI:                     "bolt://localhost:7687",
		Username:                "neo4j",
		Password:                "password",
		ConnectionTimeout:       30,
		MaxTransactionRetryTime: 30,
	}

	if err := config.Validate(); err != nil {
		fmt.Printf("Invalid config: %v\n", err)
	} else {
		fmt.Println("Config is valid")
	}

	// Output: Config is valid
}

// Example demonstrating mock client for testing.
func ExampleMockGraphClient() {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	// Connect
	_ = mock.Connect(ctx)

	// Run some read queries
	_, _ = mock.Query(ctx, "MATCH (p:Person) RETURN p", nil)
	_, _ = mock.Query(ctx, "MATCH (h:Host) RETURN h", nil)

	// Verify calls were recorded
	calls := mock.GetCallsByMethod("Query")
	fmt.Printf("Query called %d times\n", len(calls))

	// Output:
	// Query called 2 times
}
