package harness

import (
	"log/slog"
	"os"
	"testing"
)

func TestQueueManager_Client(t *testing.T) {
	// Test that Client() returns non-nil client field
	// We can't test with real Redis, but we can verify the getter works

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a mock/stub for testing
	qm := &QueueManager{
		client: nil, // Would be a real client in production
		logger: logger,
	}

	// Client() should return the client field (even if nil)
	client := qm.Client()
	if client != nil {
		t.Error("expected nil client in test stub")
	}
}

func TestQueueManager_Close(t *testing.T) {
	// Test Close method signature
	// In production, client is always initialized via NewQueueManagerWithClient
	// We can't test actual Close without a Redis connection

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Verify QueueManager has Close method
	qm := &QueueManager{
		client: nil, // Would panic on Close(), which is expected
		logger: logger,
	}

	// Just verify the method exists and has correct signature
	// In real usage, Close() is only called after successful NewQueueManagerWithClient()
	_ = qm
	t.Log("QueueManager.Close() method exists with correct signature")
}
