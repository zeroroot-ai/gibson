package pools

import (
	"context"
	"fmt"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
)

// RedisOptions carries required and optional tuning for NewRedis.
// Required fields must be non-zero; NewRedis returns an error otherwise.
type RedisOptions struct {
	// Addr is the host:port of the Redis server (e.g. "redis:6379").
	//
	// Required: must not be empty.
	Addr string

	// PoolSize is the maximum number of socket connections in the pool.
	// More connections means more parallelism at the cost of more memory
	// and file descriptors.
	//
	// Required: must be > 0.
	PoolSize int

	// DialTimeout is the timeout for establishing new connections.
	//
	// Required: must be > 0. A common production value is 5 s.
	DialTimeout time.Duration

	// ReadTimeout is the timeout for socket reads. If reached, the command
	// fails with a timeout error.
	//
	// Required: must be > 0. A common production value is 3 s.
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for socket writes.
	//
	// Required: must be > 0. A common production value is 3 s.
	WriteTimeout time.Duration

	// ConnMaxLifetime is the maximum duration a connection may be reused.
	// Connections older than this are closed and replaced.
	//
	// Required: must be > 0. A common production value is 30 min.
	ConnMaxLifetime time.Duration

	// DB is the Redis logical database index to select after connecting.
	// Defaults to 0 (the default Redis database) when not set.
	DB int

	// Password is the Redis AUTH password. Leave empty when authentication
	// is not configured.
	Password string

	// Username is used with Redis 6+ ACL authentication. Leave empty when
	// not required.
	Username string

	// MaxRetries is the maximum number of retries before giving up.
	// A value of 0 means "use go-redis default" (3 retries).
	MaxRetries int

	// MinRetryBackoff is the minimum backoff between retries.
	// A zero value means "use go-redis default" (8 ms).
	MinRetryBackoff time.Duration

	// MaxRetryBackoff is the maximum backoff between retries.
	// A zero value means "use go-redis default" (512 ms).
	MaxRetryBackoff time.Duration

	// Circuit configures the gobreaker circuit breaker wrapping all Redis
	// calls. The zero value substitutes DefaultCircuitConfig().
	Circuit resilience.CircuitConfig
}

// validate returns a non-nil error if any required field is zero or empty.
func (o RedisOptions) validate() error {
	if o.Addr == "" {
		return fmt.Errorf("pools.NewRedis: RedisOptions.Addr is required (must not be empty)")
	}
	if o.PoolSize <= 0 {
		return fmt.Errorf("pools.NewRedis: RedisOptions.PoolSize is required (must be > 0)")
	}
	if o.DialTimeout == 0 {
		return fmt.Errorf("pools.NewRedis: RedisOptions.DialTimeout is required (must be > 0)")
	}
	if o.ReadTimeout == 0 {
		return fmt.Errorf("pools.NewRedis: RedisOptions.ReadTimeout is required (must be > 0)")
	}
	if o.WriteTimeout == 0 {
		return fmt.Errorf("pools.NewRedis: RedisOptions.WriteTimeout is required (must be > 0)")
	}
	if o.ConnMaxLifetime == 0 {
		return fmt.Errorf("pools.NewRedis: RedisOptions.ConnMaxLifetime is required (must be > 0)")
	}
	return nil
}

// CircuitRedisClient wraps *redis.Client with a gobreaker circuit breaker.
// Every command is routed through the breaker's Execute method so a run of
// failures will open the circuit and fast-fail subsequent calls until the
// backend recovers.
//
// Callers that need access to commands not explicitly wrapped here (e.g. for
// administrative operations or direct pipelining) can call Unwrap to retrieve
// the underlying client.
type CircuitRedisClient struct {
	inner *redis.Client
	cb    *gobreaker.CircuitBreaker
}

// Unwrap returns the underlying *redis.Client. Use this to access Redis
// commands that are not directly wrapped on CircuitRedisClient.
func (c *CircuitRedisClient) Unwrap() *redis.Client {
	return c.inner
}

// Close closes the underlying connection pool.
func (c *CircuitRedisClient) Close() error {
	return c.inner.Close()
}

// Ping sends a PING command wrapped in the circuit breaker.
func (c *CircuitRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	var cmd *redis.StatusCmd
	_, _ = c.cb.Execute(func() (interface{}, error) {
		cmd = c.inner.Ping(ctx)
		return nil, cmd.Err()
	})
	if cmd == nil {
		cmd = redis.NewStatusCmd(ctx)
		cmd.SetErr(gobreaker.ErrOpenState)
	}
	return cmd
}

// Do executes a raw Redis command wrapped in the circuit breaker.
func (c *CircuitRedisClient) Do(ctx context.Context, args ...interface{}) *redis.Cmd {
	var cmd *redis.Cmd
	_, _ = c.cb.Execute(func() (interface{}, error) {
		cmd = c.inner.Do(ctx, args...)
		return nil, cmd.Err()
	})
	if cmd == nil {
		cmd = redis.NewCmd(ctx, args...)
		cmd.SetErr(gobreaker.ErrOpenState)
	}
	return cmd
}

// XAdd appends a message to a Redis stream, wrapped in the circuit breaker.
func (c *CircuitRedisClient) XAdd(ctx context.Context, a *redis.XAddArgs) *redis.StringCmd {
	var cmd *redis.StringCmd
	_, _ = c.cb.Execute(func() (interface{}, error) {
		cmd = c.inner.XAdd(ctx, a)
		return nil, cmd.Err()
	})
	if cmd == nil {
		cmd = redis.NewStringCmd(ctx)
		cmd.SetErr(gobreaker.ErrOpenState)
	}
	return cmd
}

// XReadGroup reads messages from a Redis stream consumer group, wrapped in the
// circuit breaker.
func (c *CircuitRedisClient) XReadGroup(ctx context.Context, a *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
	var cmd *redis.XStreamSliceCmd
	_, _ = c.cb.Execute(func() (interface{}, error) {
		cmd = c.inner.XReadGroup(ctx, a)
		return nil, cmd.Err()
	})
	if cmd == nil {
		cmd = redis.NewXStreamSliceCmd(ctx)
		cmd.SetErr(gobreaker.ErrOpenState)
	}
	return cmd
}

// XAck acknowledges one or more messages in a Redis stream consumer group,
// wrapped in the circuit breaker.
func (c *CircuitRedisClient) XAck(ctx context.Context, stream, group string, ids ...string) *redis.IntCmd {
	var cmd *redis.IntCmd
	_, _ = c.cb.Execute(func() (interface{}, error) {
		cmd = c.inner.XAck(ctx, stream, group, ids...)
		return nil, cmd.Err()
	})
	if cmd == nil {
		cmd = redis.NewIntCmd(ctx)
		cmd.SetErr(gobreaker.ErrOpenState)
	}
	return cmd
}

// JSONSet stores a JSON value at path in key using RedisJSON, wrapped in the
// circuit breaker.
func (c *CircuitRedisClient) JSONSet(ctx context.Context, key, path string, value interface{}) *redis.Cmd {
	return c.Do(ctx, "JSON.SET", key, path, value)
}

// JSONGet retrieves a JSON value at path from key using RedisJSON, wrapped in
// the circuit breaker.
func (c *CircuitRedisClient) JSONGet(ctx context.Context, key string, paths ...string) *redis.Cmd {
	args := make([]interface{}, 0, 2+len(paths))
	args = append(args, "JSON.GET", key)
	for _, p := range paths {
		args = append(args, p)
	}
	return c.Do(ctx, args...)
}

// NewRedis constructs a *CircuitRedisClient with required-override enforcement.
//
// Required opts fields: Addr, PoolSize, DialTimeout, ReadTimeout,
// WriteTimeout, ConnMaxLifetime. Returns an error when any is zero/empty.
//
// The returned client is safe for concurrent use. Callers must call
// client.Close when done to release pool connections.
//
// The circuit breaker is configured from opts.Circuit; a zero CircuitConfig
// applies resilience.DefaultCircuitConfig().
func NewRedis(opts RedisOptions) (*CircuitRedisClient, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	redisOpts := &redis.Options{
		Addr:            opts.Addr,
		Password:        opts.Password,
		Username:        opts.Username,
		DB:              opts.DB,
		PoolSize:        opts.PoolSize,
		DialTimeout:     opts.DialTimeout,
		ReadTimeout:     opts.ReadTimeout,
		WriteTimeout:    opts.WriteTimeout,
		ConnMaxLifetime: opts.ConnMaxLifetime,
	}
	if opts.MaxRetries != 0 {
		redisOpts.MaxRetries = opts.MaxRetries
	}
	if opts.MinRetryBackoff != 0 {
		redisOpts.MinRetryBackoff = opts.MinRetryBackoff
	}
	if opts.MaxRetryBackoff != 0 {
		redisOpts.MaxRetryBackoff = opts.MaxRetryBackoff
	}

	client := redis.NewClient(redisOpts)

	cb := resilience.NewBreaker("redis/"+opts.Addr, opts.Circuit, nil)

	return &CircuitRedisClient{
		inner: client,
		cb:    cb,
	}, nil
}
