package harness

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/zero-day-ai/sdk/queue"
)

// QueueManager manages the Redis queue client for the Gibson daemon.
// It provides centralized queue client lifecycle management and access.
type QueueManager struct {
	client queue.Client
	logger *slog.Logger
}

// NewQueueManager creates a new QueueManager with a Redis client.
// It initializes the queue client using the provided Redis URL and establishes
// a connection to the Redis server.
//
// Parameters:
//   - redisURL: Redis connection URL (e.g., "redis://localhost:6379")
//     If empty, uses REDIS_URL environment variable or defaults to "redis://localhost:6379"
//   - logger: Structured logger for queue operations
//
// Returns:
//   - *QueueManager: Initialized queue manager ready for use
//   - error: Non-nil if Redis connection fails
//
// Example:
//
//	queueMgr, err := NewQueueManager("", logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer queueMgr.Close()
func NewQueueManager(redisURL string, logger *slog.Logger) (*QueueManager, error) {
	if logger == nil {
		logger = slog.Default().With("component", "queue-manager")
	}

	// Determine Redis URL with fallback priority:
	// 1. Provided redisURL parameter
	// 2. REDIS_URL environment variable
	// 3. Default localhost:6379
	if redisURL == "" {
		redisURL = os.Getenv("REDIS_URL")
	}
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	logger.Info("initializing queue manager", "redis_url", redisURL)

	// Create Redis client options
	opts := queue.RedisOptions{
		URL: redisURL,
		// TLS, timeouts use SDK defaults
	}

	// Create Redis queue client
	client, err := queue.NewRedisClient(opts)
	if err != nil {
		logger.Error("failed to connect to Redis", "error", err, "redis_url", redisURL)
		return nil, fmt.Errorf("failed to create Redis queue client: %w", err)
	}

	logger.Info("queue manager initialized successfully", "redis_url", redisURL)

	return &QueueManager{
		client: client,
		logger: logger,
	}, nil
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
