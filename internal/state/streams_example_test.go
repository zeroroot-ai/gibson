package state_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zero-day-ai/gibson/internal/state"
)

// ExampleStateClient_StreamAdd demonstrates adding entries to a Redis Stream.
func ExampleStateClient_StreamAdd() {
	// Create client
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Add event to stream
	id, err := client.StreamAdd(ctx, "events:user", map[string]any{
		"event":     "user.created",
		"user_id":   "12345",
		"email":     "user@example.com",
		"timestamp": time.Now().Unix(),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Event added with ID: %s\n", id)
}

// ExampleStateClient_StreamRead demonstrates reading entries from a Redis Stream.
func ExampleStateClient_StreamRead() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Read all entries from the beginning
	opts := &state.StreamReadOptions{
		LastID: "0", // Start from beginning
		Count:  100, // Limit to 100 entries
	}

	entries, err := client.StreamRead(ctx, []string{"events:user"}, opts)
	if err != nil {
		log.Fatal(err)
	}

	for stream, streamEntries := range entries {
		fmt.Printf("Stream: %s\n", stream)
		for _, entry := range streamEntries {
			fmt.Printf("  ID: %s, Values: %+v\n", entry.ID, entry.Values)
		}
	}
}

// ExampleStateClient_StreamSubscribe demonstrates real-time subscription to a Redis Stream.
func ExampleStateClient_StreamSubscribe() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Subscribe to new events only
	entryChan, err := client.StreamSubscribe(ctx, "events:user", "$")
	if err != nil {
		log.Fatal(err)
	}

	// Process events as they arrive
	for entry := range entryChan {
		fmt.Printf("New event: %s - %+v\n", entry.ID, entry.Values)

		// Process the event
		if eventType, ok := entry.Values["event"].(string); ok {
			switch eventType {
			case "user.created":
				fmt.Println("Processing user creation...")
			case "user.updated":
				fmt.Println("Processing user update...")
			}
		}
	}
}

// ExampleStateClient_StreamRange demonstrates retrieving historical entries.
func ExampleStateClient_StreamRange() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Get all historical entries
	entries, err := client.StreamRange(ctx, "events:user", "-", "+", 0)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d historical entries\n", len(entries))
	for _, entry := range entries {
		fmt.Printf("  %s: %+v\n", entry.ID, entry.Values)
	}
}

// ExampleStateClient_StreamTrim demonstrates trimming old entries from a stream.
func ExampleStateClient_StreamTrim() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Keep only the latest 1000 entries
	opts := &state.StreamTrimOptions{
		MaxLen:      1000,
		Approximate: true, // More efficient, less precise
	}

	removed, err := client.StreamTrim(ctx, "events:user", opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Trimmed %d old entries\n", removed)
}

// ExampleStateClient_StreamLen demonstrates getting stream length.
func ExampleStateClient_StreamLen() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Get stream length
	length, err := client.StreamLen(ctx, "events:user")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Stream has %d entries\n", length)
}

// Example_streamEventLogger demonstrates a complete event logging system using Redis Streams.
func Example_streamEventLogger() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream := "events:application"

	// Start background event processor
	go func() {
		entryChan, err := client.StreamSubscribe(ctx, stream, "$")
		if err != nil {
			log.Printf("Failed to subscribe: %v", err)
			return
		}

		for entry := range entryChan {
			eventType := entry.Values["type"]
			level := entry.Values["level"]
			message := entry.Values["message"]

			log.Printf("[%s] %s: %s", level, eventType, message)
		}
	}()

	// Log some events
	events := []map[string]any{
		{
			"type":      "app.started",
			"level":     "info",
			"message":   "Application started successfully",
			"timestamp": time.Now().Unix(),
		},
		{
			"type":      "user.login",
			"level":     "info",
			"message":   "User logged in",
			"user_id":   "12345",
			"timestamp": time.Now().Unix(),
		},
		{
			"type":      "error.database",
			"level":     "error",
			"message":   "Database connection timeout",
			"timestamp": time.Now().Unix(),
		},
	}

	for _, event := range events {
		id, err := client.StreamAdd(ctx, stream, event)
		if err != nil {
			log.Printf("Failed to log event: %v", err)
			continue
		}
		fmt.Printf("Logged event: %s\n", id)
		time.Sleep(100 * time.Millisecond)
	}

	// Let the subscriber process events
	time.Sleep(500 * time.Millisecond)

	// Get event statistics
	length, _ := client.StreamLen(ctx, stream)
	fmt.Printf("Total events logged: %d\n", length)
}

// Example_streamMultipleStreams demonstrates reading from multiple streams simultaneously.
func Example_streamMultipleStreams() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Read from multiple streams with blocking
	opts := &state.StreamReadOptions{
		LastID: "$",             // Only new entries
		Block:  5 * time.Second, // Block for up to 5 seconds
		Count:  10,              // Get up to 10 entries per stream
	}

	streams := []string{
		"events:user",
		"events:order",
		"events:payment",
	}

	entries, err := client.StreamRead(ctx, streams, opts)
	if err != nil {
		log.Fatal(err)
	}

	for stream, streamEntries := range entries {
		fmt.Printf("Stream %s: %d new entries\n", stream, len(streamEntries))
		for _, entry := range streamEntries {
			fmt.Printf("  %s: %+v\n", entry.ID, entry.Values)
		}
	}
}

// ExampleStateClient_StreamCreateGroup demonstrates creating a consumer group for exactly-once processing.
func ExampleStateClient_StreamCreateGroup() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Create a consumer group to process all existing messages
	err = client.StreamCreateGroup(ctx, "events:orders", "order-processors", "0", true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Consumer group created successfully")
}

// ExampleStateClient_StreamReadGroup demonstrates reading messages using a consumer group.
func ExampleStateClient_StreamReadGroup() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Create consumer group (if not exists)
	_ = client.StreamCreateGroup(ctx, "events:orders", "processors", "$", true)

	// Consumer options
	opts := &state.ConsumerGroupOptions{
		Group:    "processors",
		Consumer: "worker-1",
		Count:    10,
		Block:    5 * time.Second,
		NoAck:    true, // Require explicit acknowledgment
	}

	// Read new messages
	entries, err := client.StreamReadGroup(ctx, "events:orders", ">", opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Received %d messages\n", len(entries))

	// Process each message
	for _, entry := range entries {
		fmt.Printf("Processing order: %s\n", entry.ID)

		// Process the order...
		if err := processOrder(entry.Values); err != nil {
			log.Printf("Failed to process order: %v", err)
			continue // Will remain pending and can be claimed by another consumer
		}

		// Acknowledge successful processing
		if err := client.StreamAck(ctx, "events:orders", "processors", entry.ID); err != nil {
			log.Printf("Failed to acknowledge: %v", err)
		}
	}
}

// ExampleStateClient_StreamPending demonstrates monitoring pending messages.
func ExampleStateClient_StreamPending() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Get all pending messages
	pending, err := client.StreamPending(ctx, "events:orders", "processors", "-", "+", 100, "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d pending messages\n", len(pending))

	// Check for stuck messages
	for _, msg := range pending {
		if msg.IdleTime > 5*time.Minute {
			fmt.Printf("Message %s stuck for %v (consumer: %s, deliveries: %d)\n",
				msg.ID, msg.IdleTime, msg.Consumer, msg.DeliveryCount)
		}
	}
}

// ExampleStateClient_StreamClaim demonstrates claiming stuck messages for reprocessing.
func ExampleStateClient_StreamClaim() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Find stuck messages (pending for more than 5 minutes)
	pending, err := client.StreamPending(ctx, "events:orders", "processors", "-", "+", 100, "")
	if err != nil {
		log.Fatal(err)
	}

	// Collect IDs of stuck messages
	stuckIDs := []string{}
	for _, msg := range pending {
		if msg.IdleTime > 5*time.Minute {
			stuckIDs = append(stuckIDs, msg.ID)
		}
	}

	if len(stuckIDs) == 0 {
		fmt.Println("No stuck messages found")
		return
	}

	// Claim stuck messages for this worker
	claimed, err := client.StreamClaim(ctx, "events:orders", "processors", "worker-recovery", 5*time.Minute, stuckIDs...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Claimed %d stuck messages for reprocessing\n", len(claimed))

	// Reprocess claimed messages
	for _, entry := range claimed {
		fmt.Printf("Reprocessing order: %s\n", entry.ID)
		// Process and acknowledge...
	}
}

// Example_consumerGroupExactlyOnce demonstrates exactly-once message processing with consumer groups.
func Example_consumerGroupExactlyOnce() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream := "events:orders"
	group := "order-processors"

	// Step 1: Create consumer group
	err = client.StreamCreateGroup(ctx, stream, group, "$", true)
	if err != nil {
		log.Fatal(err)
	}

	// Step 2: Add some orders to process
	for i := 1; i <= 5; i++ {
		_, err := client.StreamAdd(ctx, stream, map[string]any{
			"order_id": fmt.Sprintf("ORD-%d", i),
			"amount":   100 * i,
			"status":   "pending",
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("Added 5 orders to process")

	// Step 3: Multiple workers process messages concurrently
	// Each message is delivered to exactly one consumer
	workers := []string{"worker-1", "worker-2", "worker-3"}

	for _, worker := range workers {
		go func(workerName string) {
			opts := &state.ConsumerGroupOptions{
				Group:    group,
				Consumer: workerName,
				Count:    10,
				Block:    2 * time.Second,
				NoAck:    true,
			}

			entries, err := client.StreamReadGroup(ctx, stream, ">", opts)
			if err != nil {
				log.Printf("[%s] Error reading: %v", workerName, err)
				return
			}

			for _, entry := range entries {
				orderID := entry.Values["order_id"]
				fmt.Printf("[%s] Processing order: %s\n", workerName, orderID)

				// Simulate processing
				time.Sleep(100 * time.Millisecond)

				// Acknowledge successful processing
				if err := client.StreamAck(ctx, stream, group, entry.ID); err != nil {
					log.Printf("[%s] Failed to ack: %v", workerName, err)
				} else {
					fmt.Printf("[%s] Completed order: %s\n", workerName, orderID)
				}
			}
		}(worker)
	}

	// Wait for processing to complete
	time.Sleep(5 * time.Second)

	// Verify all messages were processed
	pending, err := client.StreamPending(ctx, stream, group, "-", "+", 100, "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Pending messages: %d (should be 0)\n", len(pending))
}

// Example_consumerGroupFailureRecovery demonstrates handling failures with consumer groups.
func Example_consumerGroupFailureRecovery() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	stream := "events:critical"
	group := "critical-processors"

	// Create consumer group
	_ = client.StreamCreateGroup(ctx, stream, group, "$", true)

	// Add some critical events
	for i := 1; i <= 3; i++ {
		_, _ = client.StreamAdd(ctx, stream, map[string]any{
			"event_id": fmt.Sprintf("EVT-%d", i),
			"priority": "high",
		})
	}

	// Worker processes messages but crashes before acknowledging
	opts := &state.ConsumerGroupOptions{
		Group:    group,
		Consumer: "worker-1",
		Count:    10,
		NoAck:    true,
	}

	entries, _ := client.StreamReadGroup(ctx, stream, ">", opts)
	fmt.Printf("Worker-1 received %d messages\n", len(entries))

	// Simulate crash - messages not acknowledged
	fmt.Println("Worker-1 crashed without acknowledging!")

	// Recovery worker checks for pending messages
	time.Sleep(1 * time.Second)

	pending, _ := client.StreamPending(ctx, stream, group, "-", "+", 100, "")
	fmt.Printf("Found %d pending messages from crashed worker\n", len(pending))

	// Claim stuck messages
	stuckIDs := make([]string, len(pending))
	for i, msg := range pending {
		stuckIDs[i] = msg.ID
	}

	claimed, _ := client.StreamClaim(ctx, stream, group, "worker-recovery", 0, stuckIDs...)
	fmt.Printf("Recovery worker claimed %d messages\n", len(claimed))

	// Reprocess and acknowledge
	for _, entry := range claimed {
		eventID := entry.Values["event_id"]
		fmt.Printf("Recovery worker processing: %s\n", eventID)
		_ = client.StreamAck(ctx, stream, group, entry.ID)
	}

	// Verify all processed
	pending, _ = client.StreamPending(ctx, stream, group, "-", "+", 100, "")
	fmt.Printf("Remaining pending: %d (should be 0)\n", len(pending))
}

// processOrder is a helper function for examples
func processOrder(values map[string]any) error {
	// Simulate order processing
	return nil
}
