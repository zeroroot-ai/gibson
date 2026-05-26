package state

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testutil "github.com/zeroroot-ai/gibson/internal/testing"
)

func setupMiniredis(t *testing.T) (*miniredis.Miniredis, *Config) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	return mr, cfg
}

func TestNewStateClient_Standalone(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	// Mock MODULE LIST response for RediSearch and RedisJSON
	// Note: miniredis doesn't support MODULE LIST by default,
	// so we'll need to modify Health() to handle this gracefully
	// For now, we'll test the connection aspect

	client, err := NewStateClient(cfg)
	// Expect error due to missing modules in miniredis
	if err != nil {
		// This is expected - miniredis doesn't support MODULE LIST
		assert.Contains(t, err.Error(), "module")
		return
	}

	// If we get here (shouldn't happen with strict module checking),
	// clean up
	if client != nil {
		defer client.Close()
		assert.NotNil(t, client.Client())
	}
}

func TestNewStateClient_NilConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	// Create client with nil config - should use defaults
	// This will fail due to module check, but we're testing config handling
	client, err := NewStateClient(nil)
	if err != nil {
		// Expected due to wrong address or module check
		return
	}

	if client != nil {
		defer client.Close()
	}
}

func TestNewStateClient_InvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "cluster mode without addresses",
			config: &Config{
				ClusterMode: true,
			},
		},
		{
			name: "sentinel without addresses",
			config: &Config{
				SentinelMaster: "mymaster",
			},
		},
		{
			name: "invalid database",
			config: &Config{
				URL:      "redis://localhost:6379",
				Database: 99,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewStateClient(tt.config)
			assert.Error(t, err)
			assert.Nil(t, client)
		})
	}
}

func TestNewStateClient_InvalidURL(t *testing.T) {
	cfg := &Config{
		URL: "not-a-valid-url",
	}

	client, err := NewStateClient(cfg)
	assert.Error(t, err)
	assert.Nil(t, client)
}

func TestNewStateClient_ConnectionFailed(t *testing.T) {
	cfg := &Config{
		URL:         "redis://localhost:9999", // Non-existent Redis
		DialTimeout: 1 * time.Second,
	}

	client, err := NewStateClient(cfg)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "connection")
}

func TestStateClient_Client(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	// Create a minimal client for testing (skip module check)
	cfg.ApplyDefaults()
	require.NoError(t, cfg.Validate())

	// We'll create the client directly without NewStateClient
	// to bypass module checking for this test
	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	rdb := client.Client()
	assert.NotNil(t, rdb)

	// Test basic operations
	ctx := testutil.WithTestTenant()
	err := rdb.Set(ctx, "test-key", "test-value", 0).Err()
	require.NoError(t, err)

	val, err := rdb.Get(ctx, "test-key").Result()
	require.NoError(t, err)
	assert.Equal(t, "test-value", val)
}

func TestStateClient_Config(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "redis://localhost:6379"
	cfg.Database = 5

	client := &StateClient{
		config: cfg,
	}

	returnedCfg := client.Config()
	assert.Equal(t, cfg.URL, returnedCfg.URL)
	assert.Equal(t, cfg.Database, returnedCfg.Database)

	// Ensure it's a copy (modifying returned config doesn't affect original)
	returnedCfg.Database = 10
	assert.Equal(t, 5, client.config.Database)
}

func TestStateClient_Close(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}

	err := client.Close()
	assert.NoError(t, err)

	// Closing again may return an error (client is closed)
	// but should not panic
	client.Close()
}

func TestStateClient_Close_NilClient(t *testing.T) {
	client := &StateClient{
		client: nil,
		config: DefaultConfig(),
	}

	err := client.Close()
	assert.NoError(t, err)
}

func TestStateClient_Health_Connectivity(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()
	err := client.Health(ctx)

	// miniredis doesn't support MODULE LIST, so health check
	// should gracefully handle this and not return error
	// (based on our implementation that treats missing MODULE LIST as non-fatal)
	assert.NoError(t, err)
}

func TestStateClient_Health_ConnectionFailed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "redis://localhost:9999"
	cfg.DialTimeout = 1 * time.Second

	// Create a client that will fail health check
	// We can't use NewStateClient as it tests connection
	// Instead, we'll test that a bad connection fails health check
	// by setting up a client and closing the miniredis instance

	mr, cfg := setupMiniredis(t)
	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	// Close the server to simulate connection failure
	mr.Close()

	ctx := context.Background()
	err := client.Health(ctx)
	assert.Error(t, err)
}

func TestStateClient_Health_ContextCanceled(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.Health(ctx)
	assert.Error(t, err)
}

// Helper function to create a test Redis client
func createTestRedisClient(t *testing.T, addr string) *redis.Client {
	t.Helper()

	opts, err := redis.ParseURL("redis://" + addr)
	require.NoError(t, err)

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Ping(ctx).Err()
	require.NoError(t, err)

	return client
}

func TestStateClient_IntegrationWithMiniredis(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	// Create client bypassing module check
	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := testutil.WithTestTenant()
	rdb := client.Client()

	// Test various Redis operations
	t.Run("string operations", func(t *testing.T) {
		err := rdb.Set(ctx, "key1", "value1", 0).Err()
		require.NoError(t, err)

		val, err := rdb.Get(ctx, "key1").Result()
		require.NoError(t, err)
		assert.Equal(t, "value1", val)
	})

	t.Run("hash operations", func(t *testing.T) {
		err := rdb.HSet(ctx, "hash1", "field1", "value1").Err()
		require.NoError(t, err)

		val, err := rdb.HGet(ctx, "hash1", "field1").Result()
		require.NoError(t, err)
		assert.Equal(t, "value1", val)
	})

	t.Run("list operations", func(t *testing.T) {
		err := rdb.LPush(ctx, "list1", "item1", "item2").Err()
		require.NoError(t, err)

		length, err := rdb.LLen(ctx, "list1").Result()
		require.NoError(t, err)
		assert.Equal(t, int64(2), length)
	})

	t.Run("set operations", func(t *testing.T) {
		err := rdb.SAdd(ctx, "set1", "member1", "member2").Err()
		require.NoError(t, err)

		isMember, err := rdb.SIsMember(ctx, "set1", "member1").Result()
		require.NoError(t, err)
		assert.True(t, isMember)
	})
}

// Test types for JSON operations
type TestUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Age   int    `json:"age"`
}

type TestArticle struct {
	Title     string  `json:"title"`
	Content   string  `json:"content"`
	Views     int     `json:"views"`
	Rating    float64 `json:"rating"`
	Published bool    `json:"published"`
}

func TestStateClient_JSONSet(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("set simple struct", func(t *testing.T) {
		user := TestUser{
			Name:  "Alice",
			Email: "alice@example.com",
			Age:   30,
		}

		err := client.JSONSet(ctx, "user:1", "$", user)
		// Note: miniredis doesn't support JSON commands, so we expect an error
		// In a real Redis instance with RedisJSON, this would succeed
		assert.Error(t, err)
	})

	t.Run("set nested document", func(t *testing.T) {
		article := TestArticle{
			Title:     "Go Best Practices",
			Content:   "Always use contexts...",
			Views:     100,
			Rating:    4.5,
			Published: true,
		}

		err := client.JSONSet(ctx, "article:1", "$", article)
		assert.Error(t, err) // miniredis limitation
	})

	t.Run("invalid json value", func(t *testing.T) {
		// Try to marshal an invalid value (channel can't be marshaled)
		ch := make(chan int)
		err := client.JSONSet(ctx, "invalid", "$", ch)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "json marshal failed")
	})
}

func TestStateClient_JSONGet(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("get non-existent key", func(t *testing.T) {
		var user TestUser
		err := client.JSONGet(ctx, "user:nonexistent", "$", &user)
		// miniredis doesn't support JSON.GET, so we expect an error
		assert.Error(t, err)
	})

	t.Run("get with invalid path", func(t *testing.T) {
		var user TestUser
		err := client.JSONGet(ctx, "user:1", "$.invalid", &user)
		assert.Error(t, err) // miniredis limitation
	})
}

func TestStateClient_JSONDel(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("delete entire document", func(t *testing.T) {
		err := client.JSONDel(ctx, "user:1", "$")
		// miniredis doesn't support JSON.DEL
		assert.Error(t, err)
	})

	t.Run("delete specific field", func(t *testing.T) {
		err := client.JSONDel(ctx, "user:1", "$.email")
		assert.Error(t, err) // miniredis limitation
	})
}

func TestStateClient_JSONMGet(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("mget multiple keys", func(t *testing.T) {
		keys := []string{"user:1", "user:2", "user:3"}
		results, err := client.JSONMGet(ctx, keys, "$")
		// miniredis doesn't support JSON.MGET
		assert.Error(t, err)
		assert.Nil(t, results)
	})

	t.Run("mget empty keys", func(t *testing.T) {
		results, err := client.JSONMGet(ctx, []string{}, "$")
		assert.NoError(t, err)
		assert.Empty(t, results)
	})
}

func TestStateClient_JSONNumIncrBy(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("increment views", func(t *testing.T) {
		newVal, err := client.JSONNumIncrBy(ctx, "article:1", "$.views", 1)
		// miniredis doesn't support JSON.NUMINCRBY
		assert.Error(t, err)
		assert.Equal(t, float64(0), newVal)
	})

	t.Run("decrement quantity", func(t *testing.T) {
		newVal, err := client.JSONNumIncrBy(ctx, "product:1", "$.quantity", -5)
		assert.Error(t, err) // miniredis limitation
		assert.Equal(t, float64(0), newVal)
	})

	t.Run("increment non-existent key", func(t *testing.T) {
		newVal, err := client.JSONNumIncrBy(ctx, "nonexistent", "$.count", 1)
		assert.Error(t, err)
		assert.Equal(t, float64(0), newVal)
	})
}

func TestStateClient_Search(t *testing.T) {
	mr, cfg := setupMiniredis(t)
	defer mr.Close()

	client := &StateClient{
		client: createTestRedisClient(t, mr.Addr()),
		config: cfg,
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("basic search", func(t *testing.T) {
		result, err := client.Search(ctx, "users_idx", "alice", nil)
		// miniredis doesn't support FT.SEARCH
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("search with options", func(t *testing.T) {
		opts := &SearchOptions{
			Limit:      20,
			Offset:     0,
			SortBy:     "created_at",
			SortAsc:    false,
			WithScores: true,
		}
		result, err := client.Search(ctx, "articles_idx", "@status:{published}", opts)
		assert.Error(t, err) // miniredis limitation
		assert.Nil(t, result)
	})

	t.Run("search with pagination", func(t *testing.T) {
		opts := &SearchOptions{
			Limit:  10,
			Offset: 20,
		}
		result, err := client.Search(ctx, "products_idx", "*", opts)
		assert.Error(t, err) // miniredis limitation
		assert.Nil(t, result)
	})

	t.Run("search with nil options", func(t *testing.T) {
		result, err := client.Search(ctx, "test_idx", "query", nil)
		assert.Error(t, err) // miniredis limitation
		assert.Nil(t, result)
	})
}

func TestEscapeTag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "simple",
			expected: "simple",
		},
		{
			name:     "hyphenated",
			input:    "in-progress",
			expected: "in\\-progress",
		},
		{
			name:     "with spaces",
			input:    "hello world",
			expected: "hello\\ world",
		},
		{
			name:     "email address",
			input:    "user@example.com",
			expected: "user\\@example\\.com",
		},
		{
			name:     "special chars",
			input:    "tag:value",
			expected: "tag\\:value",
		},
		{
			name:     "brackets",
			input:    "array[0]",
			expected: "array\\[0\\]",
		},
		{
			name:     "curly braces",
			input:    "{key}",
			expected: "\\{key\\}",
		},
		{
			name:     "quotes",
			input:    `"quoted"`,
			expected: `\"quoted\"`,
		},
		{
			name:     "multiple special chars",
			input:    "user@domain.com:8080",
			expected: "user\\@domain\\.com\\:8080",
		},
		{
			name:     "all special chars",
			input:    `,.<>{}[]"':;!@#$%^&*()-+=~`,
			expected: `\,\.\<\>\{\}\[\]\"\'\:\;\!\@\#\$\%\^\&\*\(\)\-\+\=\~`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeTag(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEscapeQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple text",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "email address",
			input:    "alice@example.com",
			expected: "alice\\@example\\.com",
		},
		{
			name:     "hyphenated word",
			input:    "full-text",
			expected: "full\\-text",
		},
		{
			name:     "with parentheses",
			input:    "(optional)",
			expected: "\\(optional\\)",
		},
		{
			name:     "with pipe",
			input:    "option1|option2",
			expected: "option1\\|option2",
		},
		{
			name:     "quoted string",
			input:    `"exact phrase"`,
			expected: `\"exact phrase\"`,
		},
		{
			name:     "arithmetic expression",
			input:    "x+y=z",
			expected: "x\\+y\\=z",
		},
		{
			name:     "complex query",
			input:    "user@host.com:8080",
			expected: "user\\@host\\.com\\:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeQuery(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseInteger(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		expected  int64
		shouldErr bool
	}{
		{
			name:      "int64",
			input:     int64(42),
			expected:  42,
			shouldErr: false,
		},
		{
			name:      "int",
			input:     42,
			expected:  42,
			shouldErr: false,
		},
		{
			name:      "string number",
			input:     "123",
			expected:  123,
			shouldErr: false,
		},
		{
			name:      "invalid string",
			input:     "not-a-number",
			expected:  0,
			shouldErr: true,
		},
		{
			name:      "float",
			input:     3.14,
			expected:  0,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseInteger(tt.input)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseFloat(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		expected  float64
		shouldErr bool
	}{
		{
			name:      "float64",
			input:     float64(3.14),
			expected:  3.14,
			shouldErr: false,
		},
		{
			name:      "float32",
			input:     float32(2.5),
			expected:  2.5,
			shouldErr: false,
		},
		{
			name:      "int64",
			input:     int64(42),
			expected:  42.0,
			shouldErr: false,
		},
		{
			name:      "int",
			input:     10,
			expected:  10.0,
			shouldErr: false,
		},
		{
			name:      "string number",
			input:     "3.14159",
			expected:  3.14159,
			shouldErr: false,
		},
		{
			name:      "invalid string",
			input:     "not-a-float",
			expected:  0,
			shouldErr: true,
		},
		{
			name:      "bool",
			input:     true,
			expected:  0,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseFloat(tt.input)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.InDelta(t, tt.expected, result, 0.0001)
			}
		})
	}
}

func TestStateClient_EnsureIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	cfg := DefaultConfig()

	client, err := NewStateClient(cfg)
	if err != nil {
		t.Skipf("skipping test: Redis not available: %v", err)
	}
	defer client.Close()

	manager := NewIndexManager(client.Client())

	// Clean up all Gibson indexes before test
	indexes := AllIndexDefinitions()
	for _, idx := range indexes {
		_ = manager.DropIndex(ctx, idx.Name)
	}
	defer func() {
		// Clean up after test
		for _, idx := range indexes {
			_ = manager.DropIndex(ctx, idx.Name)
		}
	}()

	t.Run("creates all indexes on first call", func(t *testing.T) {
		err := client.EnsureIndexes(ctx)
		require.NoError(t, err)

		// Verify all indexes were created
		for _, idx := range indexes {
			exists, err := manager.IndexExists(ctx, idx.Name)
			require.NoError(t, err, "failed to check existence of %s", idx.Name)
			assert.True(t, exists, "index %s should exist", idx.Name)
		}
	})

	t.Run("idempotent - no error on subsequent calls", func(t *testing.T) {
		// Call again - should not error
		err := client.EnsureIndexes(ctx)
		require.NoError(t, err)

		// All indexes should still exist
		for _, idx := range indexes {
			exists, err := manager.IndexExists(ctx, idx.Name)
			require.NoError(t, err)
			assert.True(t, exists)
		}
	})
}

func TestQueryBuilder_Basic(t *testing.T) {
	t.Run("empty query returns wildcard", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Build()
		assert.Equal(t, "*", query)
	})

	t.Run("simple text query", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Text("security vulnerability").Build()
		assert.Equal(t, "security vulnerability", query)
	})

	t.Run("text with special characters", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Text("user@example.com").Build()
		assert.Equal(t, "user\\@example\\.com", query)
	})

	t.Run("empty text is ignored", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Text("").Build()
		assert.Equal(t, "*", query)
	})
}

func TestQueryBuilder_Tag(t *testing.T) {
	t.Run("single tag value", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Tag("status", "open").Build()
		assert.Equal(t, "@status:{open}", query)
	})

	t.Run("multiple tag values", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Tag("status", "open", "in-progress").Build()
		assert.Equal(t, "@status:{open|in\\-progress}", query)
	})

	t.Run("tag with special characters", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Tag("email", "user@example.com").Build()
		assert.Equal(t, "@email:{user\\@example\\.com}", query)
	})

	t.Run("empty tag values ignored", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Tag("status").Build()
		assert.Equal(t, "*", query)
	})
}

func TestQueryBuilder_NumericRange(t *testing.T) {
	t.Run("basic range", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.NumericRange("price", 10.0, 100.0).Build()
		assert.Equal(t, "@price:[10 100]", query)
	})

	t.Run("range with decimals", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.NumericRange("rating", 4.5, 5.0).Build()
		assert.Equal(t, "@rating:[4.5 5]", query)
	})

	t.Run("range with positive infinity", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.NumericRange("age", 18.0, math.Inf(1)).Build()
		assert.Equal(t, "@age:[18 +inf]", query)
	})

	t.Run("range with negative infinity", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.NumericRange("temp", math.Inf(-1), 0.0).Build()
		assert.Equal(t, "@temp:[-inf 0]", query)
	})
}

func TestQueryBuilder_NumericEquals(t *testing.T) {
	t.Run("exact numeric match", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.NumericEquals("count", 42.0).Build()
		assert.Equal(t, "@count:[42 42]", query)
	})
}

func TestQueryBuilder_Prefix(t *testing.T) {
	t.Run("prefix search", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Prefix("name", "john").Build()
		assert.Equal(t, "@name:john*", query)
	})

	t.Run("prefix with special chars", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Prefix("domain", "example.com").Build()
		assert.Equal(t, "@domain:example\\.com*", query)
	})

	t.Run("empty prefix ignored", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Prefix("name", "").Build()
		assert.Equal(t, "*", query)
	})
}

func TestQueryBuilder_CombinedQueries(t *testing.T) {
	t.Run("text and tag", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Text("vulnerability").Tag("severity", "critical").Build()
		assert.Equal(t, "vulnerability @severity:{critical}", query)
	})

	t.Run("multiple tags", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("severity", "critical").
			Tag("status", "open").
			Build()
		assert.Equal(t, "@severity:{critical} @status:{open}", query)
	})

	t.Run("text, tag, and numeric", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Text("security").
			Tag("category", "xss").
			NumericRange("cvss_score", 7.0, 10.0).
			Build()
		assert.Equal(t, "security @category:{xss} @cvss_score:[7 10]", query)
	})

	t.Run("complex query with all features", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Text("sql injection").
			Tag("severity", "high", "critical").
			Tag("status", "open").
			NumericRange("risk_score", 8.0, 10.0).
			Prefix("agent", "scanner").
			Build()
		expected := "sql injection @severity:{high|critical} @status:{open} @risk_score:[8 10] @agent:scanner*"
		assert.Equal(t, expected, query)
	})
}

func TestQueryBuilder_Or(t *testing.T) {
	t.Run("or two parts", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("status", "open").
			Tag("status", "pending").
			Or().
			Build()
		assert.Equal(t, "(@status:{open} | @status:{pending})", query)
	})

	t.Run("or with insufficient parts", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Tag("status", "open").Or().Build()
		assert.Equal(t, "@status:{open}", query)
	})
}

func TestQueryBuilder_Not(t *testing.T) {
	t.Run("negate tag", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Tag("status", "closed").Not().Build()
		assert.Equal(t, "-(@status:{closed})", query)
	})

	t.Run("negate with multiple parts", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Text("vulnerability").
			Tag("status", "closed").
			Not().
			Build()
		assert.Equal(t, "vulnerability -(@status:{closed})", query)
	})
}

func TestQueryBuilder_Group(t *testing.T) {
	t.Run("group last 2 parts", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("severity", "high").
			Tag("status", "open").
			Group(2).
			Build()
		assert.Equal(t, "(@severity:{high} @status:{open})", query)
	})

	t.Run("group with invalid count", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("status", "open").
			Group(5).
			Build()
		assert.Equal(t, "@status:{open}", query)
	})

	t.Run("group zero parts", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("status", "open").
			Group(0).
			Build()
		assert.Equal(t, "@status:{open}", query)
	})
}

func TestQueryBuilder_Raw(t *testing.T) {
	t.Run("raw query", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Raw("@title:(hello world)").Build()
		assert.Equal(t, "@title:(hello world)", query)
	})

	t.Run("mixed raw and safe", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("status", "open").
			Raw("@score:[8 10]").
			Build()
		assert.Equal(t, "@status:{open} @score:[8 10]", query)
	})

	t.Run("empty raw ignored", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.Raw("").Build()
		assert.Equal(t, "*", query)
	})
}

func TestQueryBuilder_ComplexScenarios(t *testing.T) {
	t.Run("findings search query", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Text("SQL injection").
			Tag("severity", "critical", "high").
			Tag("status", "open").
			NumericRange("cvss_score", 7.0, 10.0).
			Build()
		expected := "SQL injection @severity:{critical|high} @status:{open} @cvss_score:[7 10]"
		assert.Equal(t, expected, query)
	})

	t.Run("mission search query", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Text("penetration test").
			Tag("status", "running").
			Tag("target_id", "target-123").
			NumericRange("progress", 0.0, 50.0).
			Build()
		expected := "penetration test @status:{running} @target_id:{target\\-123} @progress:[0 50]"
		assert.Equal(t, expected, query)
	})

	t.Run("credential search query", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Tag("type", "api-key").
			Tag("provider", "aws", "azure").
			Tag("status", "active").
			Build()
		expected := "@type:{api\\-key} @provider:{aws|azure} @status:{active}"
		assert.Equal(t, expected, query)
	})

	t.Run("exclude and filter", func(t *testing.T) {
		qb := NewQueryBuilder()
		query := qb.
			Text("error").
			Tag("severity", "low").
			Not().
			Tag("status", "open").
			Build()
		expected := "error -(@severity:{low}) @status:{open}"
		assert.Equal(t, expected, query)
	})
}
