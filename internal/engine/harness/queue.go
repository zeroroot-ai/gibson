package harness

import (
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/infra/queue"
)

// QueueManager manages the Redis queue client for the Gibson daemon.
// It provides centralized queue client lifecycle management and access.
type QueueManager struct {
	client queue.Client
	logger *slog.Logger
}

// NewQueueManagerWithClient creates a new QueueManager with an existing queue client.
// This is useful when a Redis client has already been initialized elsewhere (e.g., daemon infrastructure).
//
// Parameters:
//   - client: An existing queue.Client (e.g., from daemon infrastructure)
//   - logger: Structured logger for queue operations
//
// Returns:
//   - *QueueManager: Queue manager wrapping the provided client
func NewQueueManagerWithClient(client queue.Client, logger *slog.Logger) *QueueManager {
	if logger == nil {
		logger = slog.Default().With("component", "queue-manager")
	}
	return &QueueManager{
		client: client,
		logger: logger,
	}
}

// Client returns the underlying queue client for queue operations.
// Use this to access Push, Pop, Publish, Subscribe, and tool registration methods.
//
// Returns:
//   - queue.Client: The Redis queue client
func (m *QueueManager) Client() queue.Client {
	return m.client
}

// Close gracefully closes the Redis connection.
// This should be called during daemon shutdown to ensure clean connection closure.
//
// Returns:
//   - error: Non-nil if connection closure fails
func (m *QueueManager) Close() error {
	m.logger.Info("closing queue manager")
	if err := m.client.Close(); err != nil {
		m.logger.Error("failed to close queue client", "error", err)
		return fmt.Errorf("failed to close queue client: %w", err)
	}
	m.logger.Info("queue manager closed successfully")
	return nil
}
