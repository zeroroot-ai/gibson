package queue

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client defines the interface for interacting with Redis-based work queues.
type Client interface {
	// Push adds a work item to the end of a queue (LPUSH).
	Push(ctx context.Context, queue string, item WorkItem) error

	// Pop removes and returns a work item from the front of a queue (BRPOP).
	// Blocks until an item is available or context is cancelled.
	Pop(ctx context.Context, queue string) (*WorkItem, error)

	// Publish sends a result to a pub/sub channel.
	Publish(ctx context.Context, channel string, result Result) error

	// Subscribe creates a subscription to a pub/sub channel.
	// Returns a channel that receives results until the subscription is closed.
	Subscribe(ctx context.Context, channel string) (<-chan Result, error)

	// RegisterTool writes tool metadata to Redis and adds to available set.
	RegisterTool(ctx context.Context, meta ToolMeta) error

	// ListTools returns metadata for all registered tools.
	ListTools(ctx context.Context) ([]ToolMeta, error)

	// Heartbeat updates the health key for a tool with a 30s TTL.
	Heartbeat(ctx context.Context, toolName string) error

	// GetWorkerCount returns the current worker count for a tool.
	GetWorkerCount(ctx context.Context, toolName string) (int, error)

	// IncrementWorkerCount increments the worker count for a tool.
	IncrementWorkerCount(ctx context.Context, toolName string) error

	// DecrementWorkerCount decrements the worker count for a tool.
	DecrementWorkerCount(ctx context.Context, toolName string) error

	// Close closes the Redis connection.
	Close() error
}

// RedisOptions configures the Redis connection.
type RedisOptions struct {
	// URL is the Redis connection string (e.g., "redis://localhost:6379")
	URL string

	// TLS configuration for secure connections
	TLS *tls.Config

	// ConnectTimeout is the maximum time to wait for connection establishment
	ConnectTimeout time.Duration

	// ReadTimeout is the maximum time to wait for read operations
	ReadTimeout time.Duration

	// WriteTimeout is the maximum time to wait for write operations
	WriteTimeout time.Duration
}

// RedisClient implements the Client interface using go-redis/v9.
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis queue client with the given options.
func NewRedisClient(opts RedisOptions) (*RedisClient, error) {
	if opts.URL == "" {
		opts.URL = "redis://localhost:6379"
	}

	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = 5 * time.Second
	}

	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 30 * time.Second
	}

	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 5 * time.Second
	}

	redisOpts, err := redis.ParseURL(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	redisOpts.TLSConfig = opts.TLS
	redisOpts.DialTimeout = opts.ConnectTimeout
	redisOpts.ReadTimeout = opts.ReadTimeout
	redisOpts.WriteTimeout = opts.WriteTimeout

	client := redis.NewClient(redisOpts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClient{client: client}, nil
}

// Push adds a work item to the end of a queue.
func (c *RedisClient) Push(ctx context.Context, queue string, item WorkItem) error {
	data, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal work item: %w", err)
	}

	if err := c.client.LPush(ctx, queue, data).Err(); err != nil {
		return fmt.Errorf("failed to push to queue %s: %w", queue, err)
	}

	return nil
}

// Pop removes and returns a work item from the front of a queue.
// Blocks until an item is available or context is cancelled.
func (c *RedisClient) Pop(ctx context.Context, queue string) (*WorkItem, error) {
	// BRPOP returns [queue_name, value] or empty if timeout
	result, err := c.client.BRPop(ctx, 0, queue).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to pop from queue %s: %w", queue, err)
	}

	if len(result) != 2 {
		return nil, fmt.Errorf("unexpected BRPOP result length: %d", len(result))
	}

	var item WorkItem
	if err := json.Unmarshal([]byte(result[1]), &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal work item: %w", err)
	}

	return &item, nil
}

// Publish sends a result to a pub/sub channel.
func (c *RedisClient) Publish(ctx context.Context, channel string, result Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := c.client.Publish(ctx, channel, data).Err(); err != nil {
		return fmt.Errorf("failed to publish to channel %s: %w", channel, err)
	}

	return nil
}

// Subscribe creates a subscription to a pub/sub channel.
func (c *RedisClient) Subscribe(ctx context.Context, channel string) (<-chan Result, error) {
	pubsub := c.client.Subscribe(ctx, channel)

	// Wait for subscription confirmation
	if _, err := pubsub.Receive(ctx); err != nil {
		return nil, fmt.Errorf("failed to subscribe to channel %s: %w", channel, err)
	}

	resultChan := make(chan Result)

	go func() {
		defer close(resultChan)
		defer pubsub.Close()

		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}

				var result Result
				if err := json.Unmarshal([]byte(msg.Payload), &result); err != nil {
					// Log error but continue processing
					continue
				}

				select {
				case resultChan <- result:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return resultChan, nil
}

// RegisterTool writes tool metadata to Redis and adds to available set.
func (c *RedisClient) RegisterTool(ctx context.Context, meta ToolMeta) error {
	// Convert tags slice to JSON string for Redis storage
	tagsJSON, err := json.Marshal(meta.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	// Build a flat map for HSET - all values must be strings for go-redis
	metaMap := map[string]string{
		"name":         meta.Name,
		"version":      meta.Version,
		"description":  meta.Description,
		"input_type":   meta.InputMessageType,
		"output_type":  meta.OutputMessageType,
		"schema":       meta.Schema,
		"tags":         string(tagsJSON),
		"worker_count": strconv.Itoa(meta.WorkerCount),
	}
	// Add file_descriptor_set only if it's non-empty
	if meta.FileDescriptorSet != "" {
		metaMap["file_descriptor_set"] = meta.FileDescriptorSet
	}

	// Write metadata to hash using individual field-value pairs
	metaKey := fmt.Sprintf("tool:%s:meta", meta.Name)
	args := make([]interface{}, 0, len(metaMap)*2)
	for k, v := range metaMap {
		args = append(args, k, v)
	}
	if err := c.client.HSet(ctx, metaKey, args...).Err(); err != nil {
		return fmt.Errorf("failed to set tool metadata: %w", err)
	}

	// Add to available tools set
	if err := c.client.SAdd(ctx, "tools:available", meta.Name).Err(); err != nil {
		return fmt.Errorf("failed to add tool to available set: %w", err)
	}

	return nil
}

// ListTools returns metadata for all registered tools.
func (c *RedisClient) ListTools(ctx context.Context) ([]ToolMeta, error) {
	// Get all tool names from the set
	toolNames, err := c.client.SMembers(ctx, "tools:available").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get available tools: %w", err)
	}

	tools := make([]ToolMeta, 0, len(toolNames))

	for _, name := range toolNames {
		metaKey := fmt.Sprintf("tool:%s:meta", name)
		metaMap, err := c.client.HGetAll(ctx, metaKey).Result()
		if err != nil {
			// Skip tools with missing metadata
			continue
		}

		if len(metaMap) == 0 {
			// Skip empty metadata
			continue
		}

		// Build ToolMeta manually from the map to handle type mismatches.
		// Redis stores all hash values as strings, including tags which is
		// stored as a JSON-encoded array string, not a native []string.
		meta := ToolMeta{
			Name:              metaMap["name"],
			Version:           metaMap["version"],
			Description:       metaMap["description"],
			InputMessageType:  metaMap["input_type"],
			OutputMessageType: metaMap["output_type"],
			Schema:            metaMap["schema"],
		}

		// Handle tags - stored as JSON string in Redis
		if tagsStr, ok := metaMap["tags"]; ok {
			var tags []string
			if err := json.Unmarshal([]byte(tagsStr), &tags); err == nil {
				meta.Tags = tags
			}
		}

		// Handle worker_count - stored as string in Redis
		if countStr, ok := metaMap["worker_count"]; ok {
			if count, err := strconv.Atoi(countStr); err == nil {
				meta.WorkerCount = count
			}
		}

		// Handle file_descriptor_set - stored as base64 string in Redis
		if fdsStr, ok := metaMap["file_descriptor_set"]; ok {
			meta.FileDescriptorSet = fdsStr
		}

		tools = append(tools, meta)
	}

	return tools, nil
}

// Heartbeat updates the health key for a tool with a 30s TTL.
func (c *RedisClient) Heartbeat(ctx context.Context, toolName string) error {
	healthKey := fmt.Sprintf("tool:%s:health", toolName)
	if err := c.client.Set(ctx, healthKey, "ok", 30*time.Second).Err(); err != nil {
		return fmt.Errorf("failed to set heartbeat for tool %s: %w", toolName, err)
	}
	return nil
}

// GetWorkerCount returns the current worker count for a tool.
func (c *RedisClient) GetWorkerCount(ctx context.Context, toolName string) (int, error) {
	workerKey := fmt.Sprintf("tool:%s:workers", toolName)
	countStr, err := c.client.Get(ctx, workerKey).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get worker count for tool %s: %w", toolName, err)
	}

	count, err := strconv.Atoi(countStr)
	if err != nil {
		return 0, fmt.Errorf("invalid worker count value: %w", err)
	}

	return count, nil
}

// IncrementWorkerCount increments the worker count for a tool.
func (c *RedisClient) IncrementWorkerCount(ctx context.Context, toolName string) error {
	workerKey := fmt.Sprintf("tool:%s:workers", toolName)
	if err := c.client.Incr(ctx, workerKey).Err(); err != nil {
		return fmt.Errorf("failed to increment worker count for tool %s: %w", toolName, err)
	}
	return nil
}

// DecrementWorkerCount decrements the worker count for a tool.
func (c *RedisClient) DecrementWorkerCount(ctx context.Context, toolName string) error {
	workerKey := fmt.Sprintf("tool:%s:workers", toolName)
	if err := c.client.Decr(ctx, workerKey).Err(); err != nil {
		return fmt.Errorf("failed to decrement worker count for tool %s: %w", toolName, err)
	}
	return nil
}

// Close closes the Redis connection.
func (c *RedisClient) Close() error {
	return c.client.Close()
}

// formatKeyName ensures consistent key naming with tool:<name>:* pattern.
func formatKeyName(parts ...string) string {
	return strings.Join(parts, ":")
}
