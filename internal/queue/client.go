package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
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

// redisBackend is the minimal interface this package needs from a Redis client.
// The concrete implementation lives in internal/daemon, which is on the
// forbidrawstoreimports allowlist. Pattern mirrors internal/idempotency.
type redisBackend interface {
	LPush(ctx context.Context, key, value string) error
	// BRPop blocks until a value arrives on key; returns ("", nil) when the
	// context is cancelled or no value is available within the timeout.
	BRPop(ctx context.Context, key string) (string, error)
	Publish(ctx context.Context, channel, message string) error
	// Subscribe returns a string payload channel and a cancel func that closes
	// the underlying subscription. The channel is closed when cancel is called
	// or the underlying connection is dropped.
	Subscribe(ctx context.Context, channel string) (<-chan string, func(), error)
	HSet(ctx context.Context, key string, fields map[string]string) error
	HGetAll(ctx context.Context, key string) (map[string]string, error)
	SAdd(ctx context.Context, key, member string) error
	SMembers(ctx context.Context, key string) ([]string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Get returns ("", nil) when the key is absent.
	Get(ctx context.Context, key string) (string, error)
	Incr(ctx context.Context, key string) error
	Decr(ctx context.Context, key string) error
	Close() error
}

// RedisClient implements the Client interface using an injected redisBackend.
type RedisClient struct {
	backend redisBackend
}

// NewRedisClient wraps backend in a RedisClient. The backend is constructed by
// callers in packages that are allowed to import go-redis directly
// (e.g., internal/daemon via newQueueBackend).
func NewRedisClient(backend redisBackend) *RedisClient {
	return &RedisClient{backend: backend}
}

// Push adds a work item to the end of a queue.
func (c *RedisClient) Push(ctx context.Context, queue string, item WorkItem) error {
	data, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal work item: %w", err)
	}

	if err := c.backend.LPush(ctx, queue, string(data)); err != nil {
		return fmt.Errorf("failed to push to queue %s: %w", queue, err)
	}

	return nil
}

// Pop removes and returns a work item from the front of a queue.
// Blocks until an item is available or context is cancelled.
func (c *RedisClient) Pop(ctx context.Context, queue string) (*WorkItem, error) {
	val, err := c.backend.BRPop(ctx, queue)
	if err != nil {
		return nil, fmt.Errorf("failed to pop from queue %s: %w", queue, err)
	}
	if val == "" {
		return nil, nil
	}

	var item WorkItem
	if err := json.Unmarshal([]byte(val), &item); err != nil {
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

	if err := c.backend.Publish(ctx, channel, string(data)); err != nil {
		return fmt.Errorf("failed to publish to channel %s: %w", channel, err)
	}

	return nil
}

// Subscribe creates a subscription to a pub/sub channel.
func (c *RedisClient) Subscribe(ctx context.Context, channel string) (<-chan Result, error) {
	msgChan, cancel, err := c.backend.Subscribe(ctx, channel)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to channel %s: %w", channel, err)
	}

	resultChan := make(chan Result)

	go func() {
		defer close(resultChan)
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return
			case payload, ok := <-msgChan:
				if !ok {
					return
				}

				var result Result
				if err := json.Unmarshal([]byte(payload), &result); err != nil {
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
	tagsJSON, err := json.Marshal(meta.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

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
	if meta.FileDescriptorSet != "" {
		metaMap["file_descriptor_set"] = meta.FileDescriptorSet
	}

	metaKey := fmt.Sprintf("tool:%s:meta", meta.Name)
	if err := c.backend.HSet(ctx, metaKey, metaMap); err != nil {
		return fmt.Errorf("failed to set tool metadata: %w", err)
	}

	if err := c.backend.SAdd(ctx, "tools:available", meta.Name); err != nil {
		return fmt.Errorf("failed to add tool to available set: %w", err)
	}

	return nil
}

// ListTools returns metadata for all registered tools.
func (c *RedisClient) ListTools(ctx context.Context) ([]ToolMeta, error) {
	toolNames, err := c.backend.SMembers(ctx, "tools:available")
	if err != nil {
		return nil, fmt.Errorf("failed to get available tools: %w", err)
	}

	tools := make([]ToolMeta, 0, len(toolNames))

	for _, name := range toolNames {
		metaKey := fmt.Sprintf("tool:%s:meta", name)
		metaMap, err := c.backend.HGetAll(ctx, metaKey)
		if err != nil {
			continue
		}

		if len(metaMap) == 0 {
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

		if tagsStr, ok := metaMap["tags"]; ok {
			var tags []string
			if err := json.Unmarshal([]byte(tagsStr), &tags); err == nil {
				meta.Tags = tags
			}
		}

		if countStr, ok := metaMap["worker_count"]; ok {
			if count, err := strconv.Atoi(countStr); err == nil {
				meta.WorkerCount = count
			}
		}

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
	if err := c.backend.Set(ctx, healthKey, "ok", 30*time.Second); err != nil {
		return fmt.Errorf("failed to set heartbeat for tool %s: %w", toolName, err)
	}
	return nil
}

// GetWorkerCount returns the current worker count for a tool.
func (c *RedisClient) GetWorkerCount(ctx context.Context, toolName string) (int, error) {
	workerKey := fmt.Sprintf("tool:%s:workers", toolName)
	countStr, err := c.backend.Get(ctx, workerKey)
	if err != nil {
		return 0, fmt.Errorf("failed to get worker count for tool %s: %w", toolName, err)
	}
	if countStr == "" {
		return 0, nil
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
	if err := c.backend.Incr(ctx, workerKey); err != nil {
		return fmt.Errorf("failed to increment worker count for tool %s: %w", toolName, err)
	}
	return nil
}

// DecrementWorkerCount decrements the worker count for a tool.
func (c *RedisClient) DecrementWorkerCount(ctx context.Context, toolName string) error {
	workerKey := fmt.Sprintf("tool:%s:workers", toolName)
	if err := c.backend.Decr(ctx, workerKey); err != nil {
		return fmt.Errorf("failed to decrement worker count for tool %s: %w", toolName, err)
	}
	return nil
}

// Close closes the Redis connection.
func (c *RedisClient) Close() error {
	return c.backend.Close()
}

// formatKeyName ensures consistent key naming with tool:<name>:* pattern.
func formatKeyName(parts ...string) string {
	return strings.Join(parts, ":")
}
