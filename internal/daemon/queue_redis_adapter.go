package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/queue"
)

// redisQueueAdapter adapts *redis.Client to the queue package's unexported
// redisBackend interface. Lives in internal/daemon, which is on the
// forbidrawstoreimports allowlist. Pattern mirrors internal/idempotency.
type redisQueueAdapter struct {
	client *redis.Client
}

func (a *redisQueueAdapter) LPush(ctx context.Context, key, value string) error {
	return a.client.LPush(ctx, key, value).Err()
}

// BRPop blocks until a value arrives on key.
// Returns ("", nil) when the context is cancelled or expires.
func (a *redisQueueAdapter) BRPop(ctx context.Context, key string) (string, error) {
	result, err := a.client.BRPop(ctx, 0, key).Result()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", nil
		}
		return "", err
	}
	if len(result) != 2 {
		return "", fmt.Errorf("unexpected BRPOP result length: %d", len(result))
	}
	return result[1], nil
}

func (a *redisQueueAdapter) Publish(ctx context.Context, channel, message string) error {
	return a.client.Publish(ctx, channel, message).Err()
}

// Subscribe returns a channel of raw message payloads and a cancel func.
// Calling cancel closes the underlying pubsub subscription; the channel is
// then closed once the pump goroutine drains it.
func (a *redisQueueAdapter) Subscribe(ctx context.Context, channel string) (<-chan string, func(), error) {
	pubsub := a.client.Subscribe(ctx, channel)
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		return nil, nil, fmt.Errorf("subscribe confirmation failed: %w", err)
	}

	out := make(chan string)
	go func() {
		defer close(out)
		ch := pubsub.Channel()
		for msg := range ch {
			select {
			case out <- msg.Payload:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, func() { _ = pubsub.Close() }, nil
}

func (a *redisQueueAdapter) HSet(ctx context.Context, key string, fields map[string]string) error {
	args := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return a.client.HSet(ctx, key, args...).Err()
}

func (a *redisQueueAdapter) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return a.client.HGetAll(ctx, key).Result()
}

func (a *redisQueueAdapter) SAdd(ctx context.Context, key, member string) error {
	return a.client.SAdd(ctx, key, member).Err()
}

func (a *redisQueueAdapter) SMembers(ctx context.Context, key string) ([]string, error) {
	return a.client.SMembers(ctx, key).Result()
}

func (a *redisQueueAdapter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return a.client.Set(ctx, key, value, ttl).Err()
}

// Get returns ("", nil) when the key is absent.
func (a *redisQueueAdapter) Get(ctx context.Context, key string) (string, error) {
	val, err := a.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

func (a *redisQueueAdapter) Incr(ctx context.Context, key string) error {
	return a.client.Incr(ctx, key).Err()
}

func (a *redisQueueAdapter) Decr(ctx context.Context, key string) error {
	return a.client.Decr(ctx, key).Err()
}

func (a *redisQueueAdapter) Close() error {
	return a.client.Close()
}

// newQueueBackend parses url, pings, and returns a queue.Client backed by the
// resulting *redis.Client. Called from initRedis in infrastructure.go.
func newQueueBackend(url string, connectTimeout, readTimeout time.Duration) (queue.Client, error) {
	if connectTimeout == 0 {
		connectTimeout = 5 * time.Second
	}
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	opts.DialTimeout = connectTimeout
	opts.ReadTimeout = readTimeout

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return queue.NewRedisClient(&redisQueueAdapter{client: client}), nil
}
