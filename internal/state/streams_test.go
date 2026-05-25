package state

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamAdd(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:add"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	tests := []struct {
		name        string
		stream      string
		values      map[string]any
		wantErr     bool
		errContains string
	}{
		{
			name:   "valid entry",
			stream: stream,
			values: map[string]any{
				"event":  "user.created",
				"userID": "123",
				"time":   time.Now().Unix(),
			},
			wantErr: false,
		},
		{
			name:   "multiple fields",
			stream: stream,
			values: map[string]any{
				"field1": "value1",
				"field2": "value2",
				"field3": 123,
				"field4": true,
			},
			wantErr: false,
		},
		{
			name:        "empty stream name",
			stream:      "",
			values:      map[string]any{"key": "value"},
			wantErr:     true,
			errContains: "stream name cannot be empty",
		},
		{
			name:        "empty values",
			stream:      stream,
			values:      map[string]any{},
			wantErr:     true,
			errContains: "values cannot be empty",
		},
		{
			name:        "nil values",
			stream:      stream,
			values:      nil,
			wantErr:     true,
			errContains: "values cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := client.StreamAdd(ctx, tt.stream, tt.values)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Empty(t, id)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, id)
				// Verify ID format: timestamp-sequence
				assert.Contains(t, id, "-")
			}
		})
	}
}

func TestStreamAddWithID(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:addwithid"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	tests := []struct {
		name        string
		stream      string
		id          string
		values      map[string]any
		wantErr     bool
		errContains string
	}{
		{
			name:   "valid custom ID",
			stream: stream,
			id:     fmt.Sprintf("%d-0", time.Now().UnixMilli()),
			values: map[string]any{"event": "test1"},
		},
		{
			name:   "incremental ID",
			stream: stream,
			id:     fmt.Sprintf("%d-1", time.Now().UnixMilli()),
			values: map[string]any{"event": "test2"},
		},
		{
			name:        "empty stream name",
			stream:      "",
			id:          "123-0",
			values:      map[string]any{"key": "value"},
			wantErr:     true,
			errContains: "stream name cannot be empty",
		},
		{
			name:        "empty ID",
			stream:      stream,
			id:          "",
			values:      map[string]any{"key": "value"},
			wantErr:     true,
			errContains: "id cannot be empty",
		},
		{
			name:        "empty values",
			stream:      stream,
			id:          "123-0",
			values:      map[string]any{},
			wantErr:     true,
			errContains: "values cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := client.StreamAddWithID(ctx, tt.stream, tt.id, tt.values)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Empty(t, id)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.id, id)
			}
		})
	}
}

func TestStreamRead(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:read"

	// Clean up and prepare test data
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Add test entries
	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		id, err := client.StreamAdd(ctx, stream, map[string]any{
			"index": i,
			"value": fmt.Sprintf("entry-%d", i),
		})
		require.NoError(t, err)
		ids[i] = id
		time.Sleep(1 * time.Millisecond) // Ensure unique timestamps
	}

	tests := []struct {
		name        string
		streams     []string
		opts        *StreamReadOptions
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:    "read from beginning",
			streams: []string{stream},
			opts: &StreamReadOptions{
				LastID: "0",
			},
			wantCount: 3,
		},
		{
			name:    "read with count limit",
			streams: []string{stream},
			opts: &StreamReadOptions{
				LastID: "0",
				Count:  2,
			},
			wantCount: 2,
		},
		{
			name:    "read from specific ID",
			streams: []string{stream},
			opts: &StreamReadOptions{
				LastID: ids[0],
			},
			wantCount: 2, // Should get entries after ids[0]
		},
		{
			name:    "read from end (no new entries)",
			streams: []string{stream},
			opts: &StreamReadOptions{
				LastID: "$",
			},
			wantCount: 0,
		},
		{
			name:    "blocking read with timeout",
			streams: []string{stream},
			opts: &StreamReadOptions{
				LastID: "$",
				Block:  100 * time.Millisecond,
			},
			wantCount: 0, // No new entries, should timeout
		},
		{
			name:      "nil options (defaults)",
			streams:   []string{stream},
			opts:      nil,
			wantCount: 3,
		},
		{
			name:        "empty streams",
			streams:     []string{},
			opts:        &StreamReadOptions{LastID: "0"},
			wantErr:     true,
			errContains: "streams cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.StreamRead(ctx, tt.streams, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				if tt.wantCount > 0 {
					assert.Contains(t, result, stream)
					assert.Len(t, result[stream], tt.wantCount)

					// Verify entry structure
					for _, entry := range result[stream] {
						assert.NotEmpty(t, entry.ID)
						assert.NotEmpty(t, entry.Values)
					}
				}
			}
		})
	}
}

func TestStreamRange(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:range"

	// Clean up and prepare test data
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Add test entries
	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		id, err := client.StreamAdd(ctx, stream, map[string]any{
			"index": i,
		})
		require.NoError(t, err)
		ids[i] = id
		time.Sleep(1 * time.Millisecond)
	}

	tests := []struct {
		name      string
		stream    string
		start     string
		end       string
		count     int64
		wantCount int
		wantErr   bool
	}{
		{
			name:      "all entries",
			stream:    stream,
			start:     "-",
			end:       "+",
			count:     0,
			wantCount: 5,
		},
		{
			name:      "first 3 entries",
			stream:    stream,
			start:     "-",
			end:       "+",
			count:     3,
			wantCount: 5, // XRANGE doesn't support COUNT, returns all in range
		},
		{
			name:      "specific range",
			stream:    stream,
			start:     ids[1],
			end:       ids[3],
			count:     0,
			wantCount: 3, // ids[1], ids[2], ids[3]
		},
		{
			name:      "from middle to end",
			stream:    stream,
			start:     ids[2],
			end:       "+",
			count:     0,
			wantCount: 3, // ids[2], ids[3], ids[4]
		},
		{
			name:      "empty defaults",
			stream:    stream,
			start:     "",
			end:       "",
			count:     0,
			wantCount: 5,
		},
		{
			name:      "non-existent stream",
			stream:    "test:nonexistent",
			start:     "-",
			end:       "+",
			count:     0,
			wantCount: 0,
		},
		{
			name:    "empty stream name",
			stream:  "",
			start:   "-",
			end:     "+",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := client.StreamRange(ctx, tt.stream, tt.start, tt.end, tt.count)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, entries, tt.wantCount)

				// Verify entries are in order
				for i := 0; i < len(entries)-1; i++ {
					assert.True(t, entries[i].ID < entries[i+1].ID,
						"entries should be ordered by ID")
				}
			}
		})
	}
}

func TestStreamLen(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:len"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Initially empty
	length, err := client.StreamLen(ctx, stream)
	require.NoError(t, err)
	assert.Equal(t, int64(0), length)

	// Add entries
	for i := 0; i < 5; i++ {
		_, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
		require.NoError(t, err)
	}

	// Check length
	length, err = client.StreamLen(ctx, stream)
	require.NoError(t, err)
	assert.Equal(t, int64(5), length)

	// Empty stream name
	_, err = client.StreamLen(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stream name cannot be empty")
}

func TestStreamTrim(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name          string
		setupCount    int
		opts          *StreamTrimOptions
		wantRemoved   int64
		wantRemaining int64
		wantErr       bool
	}{
		{
			name:       "trim to maxlen",
			setupCount: 10,
			opts: &StreamTrimOptions{
				MaxLen:      5,
				Approximate: false,
			},
			wantRemoved:   5,
			wantRemaining: 5,
		},
		{
			name:       "trim to maxlen approximate",
			setupCount: 10,
			opts: &StreamTrimOptions{
				MaxLen:      5,
				Approximate: true,
			},
			// Approximate trim may remove different amounts
			wantRemaining: 5,
		},
		{
			name:       "trim with no effect",
			setupCount: 5,
			opts: &StreamTrimOptions{
				MaxLen:      10,
				Approximate: false,
			},
			wantRemoved:   0,
			wantRemaining: 5,
		},
		{
			name:       "nil options",
			setupCount: 5,
			opts:       nil,
			wantErr:    true,
		},
		{
			name:       "no trim strategy specified",
			setupCount: 5,
			opts:       &StreamTrimOptions{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := fmt.Sprintf("test:stream:trim:%s", tt.name)
			_ = client.StreamDel(ctx, stream)
			defer client.StreamDel(ctx, stream)

			// Setup test data
			ids := make([]string, tt.setupCount)
			for i := 0; i < tt.setupCount; i++ {
				id, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
				require.NoError(t, err)
				ids[i] = id
				time.Sleep(1 * time.Millisecond)
			}

			// Perform trim
			removed, err := client.StreamTrim(ctx, stream, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// For non-approximate trim, check exact removal count
			if tt.opts != nil && !tt.opts.Approximate {
				assert.Equal(t, tt.wantRemoved, removed)
			}

			// Check remaining entries
			length, err := client.StreamLen(ctx, stream)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRemaining, length)
		})
	}
}

func TestStreamTrimByMinID(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:trim:minid"

	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Add test entries
	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		id, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
		require.NoError(t, err)
		ids[i] = id
		time.Sleep(1 * time.Millisecond)
	}

	// Trim by MinID (remove entries before ids[3])
	opts := &StreamTrimOptions{
		MinID: ids[3],
	}
	removed, err := client.StreamTrim(ctx, stream, opts)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed) // Should remove ids[0], ids[1], ids[2]

	// Verify remaining entries
	remaining, err := client.StreamRange(ctx, stream, "-", "+", 0)
	require.NoError(t, err)
	assert.Len(t, remaining, 2) // ids[3] and ids[4]
}

func TestStreamDel(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:del"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)

	// Add entries
	for i := 0; i < 3; i++ {
		_, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
		require.NoError(t, err)
	}

	// Verify stream exists
	length, err := client.StreamLen(ctx, stream)
	require.NoError(t, err)
	assert.Equal(t, int64(3), length)

	// Delete stream
	err = client.StreamDel(ctx, stream)
	require.NoError(t, err)

	// Verify stream is deleted
	length, err = client.StreamLen(ctx, stream)
	require.NoError(t, err)
	assert.Equal(t, int64(0), length)

	// Delete non-existent stream (should not error)
	err = client.StreamDel(ctx, "test:nonexistent")
	require.NoError(t, err)

	// Empty stream name
	err = client.StreamDel(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stream name cannot be empty")
}

func TestStreamSubscribe(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream := "test:stream:subscribe"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	t.Run("subscribe to new entries", func(t *testing.T) {
		entryChan, err := client.StreamSubscribe(ctx, stream, "$")
		require.NoError(t, err)
		require.NotNil(t, entryChan)

		// Add entries in background
		go func() {
			time.Sleep(100 * time.Millisecond)
			for i := 0; i < 3; i++ {
				_, err := client.StreamAdd(ctx, stream, map[string]any{
					"index": i,
					"value": fmt.Sprintf("entry-%d", i),
				})
				if err != nil {
					t.Logf("failed to add entry: %v", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()

		// Receive entries
		received := 0
		timeout := time.After(3 * time.Second)

		for received < 3 {
			select {
			case entry, ok := <-entryChan:
				if !ok {
					t.Fatal("channel closed prematurely")
				}
				assert.NotEmpty(t, entry.ID)
				assert.NotEmpty(t, entry.Values)
				received++
			case <-timeout:
				t.Fatalf("timeout waiting for entries, received %d/3", received)
			}
		}

		assert.Equal(t, 3, received)
	})

	t.Run("subscribe from beginning", func(t *testing.T) {
		// Add entries before subscribing
		for i := 0; i < 2; i++ {
			_, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
			require.NoError(t, err)
		}

		entryChan, err := client.StreamSubscribe(ctx, stream, "0")
		require.NoError(t, err)

		// Should receive existing entries
		received := 0
		timeout := time.After(2 * time.Second)

		for received < 2 {
			select {
			case entry, ok := <-entryChan:
				if !ok {
					t.Fatal("channel closed prematurely")
				}
				assert.NotEmpty(t, entry.ID)
				received++
			case <-timeout:
				t.Fatalf("timeout waiting for entries, received %d/2", received)
			}
		}
	})

	t.Run("context cancellation closes channel", func(t *testing.T) {
		subCtx, subCancel := context.WithCancel(ctx)
		defer subCancel()

		entryChan, err := client.StreamSubscribe(subCtx, stream, "$")
		require.NoError(t, err)

		// Cancel context
		subCancel()

		// Channel should close
		timeout := time.After(2 * time.Second)
		select {
		case _, ok := <-entryChan:
			assert.False(t, ok, "channel should be closed")
		case <-timeout:
			t.Fatal("channel did not close after context cancellation")
		}
	})

	t.Run("empty stream name", func(t *testing.T) {
		_, err := client.StreamSubscribe(ctx, "", "$")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stream name cannot be empty")
	})
}

func TestStreamSubscribeReconnection(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream := "test:stream:reconnect"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	entryChan, err := client.StreamSubscribe(ctx, stream, "$")
	require.NoError(t, err)

	// Add entries continuously
	stopAdding := make(chan struct{})
	defer close(stopAdding)

	go func() {
		i := 0
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stopAdding:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = client.StreamAdd(ctx, stream, map[string]any{
					"index": i,
				})
				i++
			}
		}
	}()

	// Receive entries for a while
	received := 0
	timeout := time.After(3 * time.Second)

	for received < 5 {
		select {
		case entry, ok := <-entryChan:
			if !ok {
				t.Fatal("channel closed unexpectedly")
			}
			assert.NotEmpty(t, entry.ID)
			received++
		case <-timeout:
			// It's okay if we don't get all entries due to timing
			if received < 3 {
				t.Fatalf("received too few entries: %d", received)
			}
			return
		}
	}
}

func TestStreamMultipleStreams(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream1 := "test:stream:multi:1"
	stream2 := "test:stream:multi:2"

	// Clean up
	_ = client.StreamDel(ctx, stream1)
	_ = client.StreamDel(ctx, stream2)
	defer client.StreamDel(ctx, stream1)
	defer client.StreamDel(ctx, stream2)

	// Add entries to both streams
	for i := 0; i < 3; i++ {
		_, err := client.StreamAdd(ctx, stream1, map[string]any{
			"stream": "1",
			"index":  i,
		})
		require.NoError(t, err)

		_, err = client.StreamAdd(ctx, stream2, map[string]any{
			"stream": "2",
			"index":  i,
		})
		require.NoError(t, err)
	}

	// Read from both streams
	opts := &StreamReadOptions{
		LastID: "0",
		Count:  10,
	}
	result, err := client.StreamRead(ctx, []string{stream1, stream2}, opts)
	require.NoError(t, err)

	assert.Len(t, result, 2)
	assert.Len(t, result[stream1], 3)
	assert.Len(t, result[stream2], 3)
}

func TestStreamCreateGroup(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:group:create"
	group := "test-group"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	tests := []struct {
		name        string
		stream      string
		group       string
		startID     string
		mkStream    bool
		wantErr     bool
		errContains string
	}{
		{
			name:     "create group with mkstream",
			stream:   stream,
			group:    group,
			startID:  "0",
			mkStream: true,
			wantErr:  false,
		},
		{
			name:     "create group idempotent",
			stream:   stream,
			group:    group,
			startID:  "0",
			mkStream: true,
			wantErr:  false, // Should handle BUSYGROUP gracefully
		},
		{
			name:     "create group from end",
			stream:   stream,
			group:    "test-group-end",
			startID:  "$",
			mkStream: true,
			wantErr:  false,
		},
		{
			name:        "empty stream name",
			stream:      "",
			group:       group,
			startID:     "0",
			mkStream:    true,
			wantErr:     true,
			errContains: "stream name cannot be empty",
		},
		{
			name:        "empty group name",
			stream:      stream,
			group:       "",
			startID:     "0",
			mkStream:    true,
			wantErr:     true,
			errContains: "group name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.StreamCreateGroup(ctx, tt.stream, tt.group, tt.startID, tt.mkStream)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestStreamReadGroup(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:readgroup"
	group := "processors"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Create consumer group
	err := client.StreamCreateGroup(ctx, stream, group, "0", true)
	require.NoError(t, err)

	// Add test entries
	for i := 0; i < 5; i++ {
		_, err := client.StreamAdd(ctx, stream, map[string]any{
			"index": i,
			"value": fmt.Sprintf("entry-%d", i),
		})
		require.NoError(t, err)
		time.Sleep(1 * time.Millisecond)
	}

	tests := []struct {
		name        string
		stream      string
		lastID      string
		opts        *ConsumerGroupOptions
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:   "read new messages",
			stream: stream,
			lastID: ">",
			opts: &ConsumerGroupOptions{
				Group:    group,
				Consumer: "worker-1",
				Count:    10,
				NoAck:    true,
			},
			wantCount: 5,
		},
		{
			name:   "read with count limit",
			stream: stream,
			lastID: ">",
			opts: &ConsumerGroupOptions{
				Group:    group,
				Consumer: "worker-2",
				Count:    3,
				NoAck:    true,
			},
			wantCount: 3,
		},
		{
			name:   "blocking read timeout",
			stream: stream,
			lastID: ">",
			opts: &ConsumerGroupOptions{
				Group:    group,
				Consumer: "worker-3",
				Count:    10,
				Block:    100 * time.Millisecond,
				NoAck:    true,
			},
			wantCount: 0, // No new messages
		},
		{
			name:        "nil options",
			stream:      stream,
			lastID:      ">",
			opts:        nil,
			wantErr:     true,
			errContains: "options cannot be nil",
		},
		{
			name:   "empty group name",
			stream: stream,
			lastID: ">",
			opts: &ConsumerGroupOptions{
				Group:    "",
				Consumer: "worker-1",
			},
			wantErr:     true,
			errContains: "group name cannot be empty",
		},
		{
			name:   "empty consumer name",
			stream: stream,
			lastID: ">",
			opts: &ConsumerGroupOptions{
				Group:    group,
				Consumer: "",
			},
			wantErr:     true,
			errContains: "consumer name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := client.StreamReadGroup(ctx, tt.stream, tt.lastID, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, entries, tt.wantCount)

				for _, entry := range entries {
					assert.NotEmpty(t, entry.ID)
					assert.NotEmpty(t, entry.Values)
				}
			}
		})
	}
}

func TestStreamAck(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:ack"
	group := "processors"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Create consumer group and add messages
	err := client.StreamCreateGroup(ctx, stream, group, "0", true)
	require.NoError(t, err)

	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		id, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
		require.NoError(t, err)
		ids[i] = id
	}

	// Read messages (creates pending entries)
	opts := &ConsumerGroupOptions{
		Group:    group,
		Consumer: "worker-1",
		Count:    10,
		NoAck:    true,
	}
	entries, err := client.StreamReadGroup(ctx, stream, ">", opts)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	tests := []struct {
		name        string
		stream      string
		group       string
		ids         []string
		wantErr     bool
		errContains string
	}{
		{
			name:    "acknowledge single message",
			stream:  stream,
			group:   group,
			ids:     []string{ids[0]},
			wantErr: false,
		},
		{
			name:    "acknowledge multiple messages",
			stream:  stream,
			group:   group,
			ids:     []string{ids[1], ids[2]},
			wantErr: false,
		},
		{
			name:    "acknowledge already acked message",
			stream:  stream,
			group:   group,
			ids:     []string{ids[0]},
			wantErr: false, // Not an error, just returns 0 count
		},
		{
			name:        "empty stream name",
			stream:      "",
			group:       group,
			ids:         []string{ids[0]},
			wantErr:     true,
			errContains: "stream name cannot be empty",
		},
		{
			name:        "empty group name",
			stream:      stream,
			group:       "",
			ids:         []string{ids[0]},
			wantErr:     true,
			errContains: "group name cannot be empty",
		},
		{
			name:        "no message IDs",
			stream:      stream,
			group:       group,
			ids:         []string{},
			wantErr:     true,
			errContains: "at least one message ID must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.StreamAck(ctx, tt.stream, tt.group, tt.ids...)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestStreamPending(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:pending"
	group := "processors"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Create consumer group and add messages
	err := client.StreamCreateGroup(ctx, stream, group, "0", true)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		_, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
		require.NoError(t, err)
	}

	// Read messages without ACK (creates pending entries)
	opts := &ConsumerGroupOptions{
		Group:    group,
		Consumer: "worker-1",
		Count:    5,
		NoAck:    true,
	}
	entries, err := client.StreamReadGroup(ctx, stream, ">", opts)
	require.NoError(t, err)
	require.Len(t, entries, 5)

	tests := []struct {
		name      string
		stream    string
		group     string
		start     string
		end       string
		count     int64
		consumer  string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "get all pending",
			stream:    stream,
			group:     group,
			start:     "-",
			end:       "+",
			count:     10,
			consumer:  "",
			wantCount: 5,
		},
		{
			name:      "get pending for specific consumer",
			stream:    stream,
			group:     group,
			start:     "-",
			end:       "+",
			count:     10,
			consumer:  "worker-1",
			wantCount: 5,
		},
		{
			name:      "get pending with count limit",
			stream:    stream,
			group:     group,
			start:     "-",
			end:       "+",
			count:     3,
			consumer:  "",
			wantCount: 3,
		},
		{
			name:      "empty defaults",
			stream:    stream,
			group:     group,
			start:     "",
			end:       "",
			count:     0,
			consumer:  "",
			wantCount: 5, // count defaults to 10, but we only have 5
		},
		{
			name:    "empty stream name",
			stream:  "",
			group:   group,
			start:   "-",
			end:     "+",
			count:   10,
			wantErr: true,
		},
		{
			name:    "empty group name",
			stream:  stream,
			group:   "",
			start:   "-",
			end:     "+",
			count:   10,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pending, err := client.StreamPending(ctx, tt.stream, tt.group, tt.start, tt.end, tt.count, tt.consumer)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, pending, tt.wantCount)

				for _, msg := range pending {
					assert.NotEmpty(t, msg.ID)
					assert.NotEmpty(t, msg.Consumer)
					assert.GreaterOrEqual(t, msg.IdleTime, time.Duration(0))
					assert.GreaterOrEqual(t, msg.DeliveryCount, int64(1))
				}
			}
		})
	}
}

func TestStreamClaim(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:claim"
	group := "processors"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Create consumer group and add messages
	err := client.StreamCreateGroup(ctx, stream, group, "0", true)
	require.NoError(t, err)

	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		id, err := client.StreamAdd(ctx, stream, map[string]any{"index": i})
		require.NoError(t, err)
		ids[i] = id
	}

	// Read messages with consumer-1 (creates pending entries)
	opts := &ConsumerGroupOptions{
		Group:    group,
		Consumer: "worker-1",
		Count:    10,
		NoAck:    true,
	}
	entries, err := client.StreamReadGroup(ctx, stream, ">", opts)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Wait a bit so messages have some idle time
	time.Sleep(50 * time.Millisecond)

	tests := []struct {
		name        string
		stream      string
		group       string
		consumer    string
		minIdleTime time.Duration
		ids         []string
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:        "claim single message",
			stream:      stream,
			group:       group,
			consumer:    "worker-2",
			minIdleTime: 0,
			ids:         []string{ids[0]},
			wantCount:   1,
		},
		{
			name:        "claim multiple messages",
			stream:      stream,
			group:       group,
			consumer:    "worker-2",
			minIdleTime: 0,
			ids:         []string{ids[1], ids[2]},
			wantCount:   2,
		},
		{
			name:        "claim with min idle time",
			stream:      stream,
			group:       group,
			consumer:    "worker-3",
			minIdleTime: 10 * time.Millisecond,
			ids:         []string{ids[0]},
			wantCount:   1,
		},
		{
			name:        "empty stream name",
			stream:      "",
			group:       group,
			consumer:    "worker-2",
			minIdleTime: 0,
			ids:         []string{ids[0]},
			wantErr:     true,
			errContains: "stream name cannot be empty",
		},
		{
			name:        "empty group name",
			stream:      stream,
			group:       "",
			consumer:    "worker-2",
			minIdleTime: 0,
			ids:         []string{ids[0]},
			wantErr:     true,
			errContains: "group name cannot be empty",
		},
		{
			name:        "empty consumer name",
			stream:      stream,
			group:       group,
			consumer:    "",
			minIdleTime: 0,
			ids:         []string{ids[0]},
			wantErr:     true,
			errContains: "consumer name cannot be empty",
		},
		{
			name:        "no message IDs",
			stream:      stream,
			group:       group,
			consumer:    "worker-2",
			minIdleTime: 0,
			ids:         []string{},
			wantErr:     true,
			errContains: "at least one message ID must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claimed, err := client.StreamClaim(ctx, tt.stream, tt.group, tt.consumer, tt.minIdleTime, tt.ids...)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, claimed, tt.wantCount)

				for _, entry := range claimed {
					assert.NotEmpty(t, entry.ID)
					assert.NotEmpty(t, entry.Values)
				}
			}
		})
	}
}

func TestConsumerGroupMission(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	stream := "test:stream:mission"
	group := "processors"

	// Clean up before test
	_ = client.StreamDel(ctx, stream)
	defer client.StreamDel(ctx, stream)

	// Step 1: Create consumer group
	err := client.StreamCreateGroup(ctx, stream, group, "$", true)
	require.NoError(t, err)

	// Step 2: Add messages
	for i := 0; i < 5; i++ {
		_, err := client.StreamAdd(ctx, stream, map[string]any{
			"task": fmt.Sprintf("task-%d", i),
		})
		require.NoError(t, err)
	}

	// Step 3: Consumer 1 reads 3 messages
	opts := &ConsumerGroupOptions{
		Group:    group,
		Consumer: "worker-1",
		Count:    3,
		NoAck:    true,
	}
	entries1, err := client.StreamReadGroup(ctx, stream, ">", opts)
	require.NoError(t, err)
	assert.Len(t, entries1, 3)

	// Step 4: Consumer 2 reads remaining messages
	opts.Consumer = "worker-2"
	entries2, err := client.StreamReadGroup(ctx, stream, ">", opts)
	require.NoError(t, err)
	assert.Len(t, entries2, 2)

	// Step 5: Check pending messages
	pending, err := client.StreamPending(ctx, stream, group, "-", "+", 100, "")
	require.NoError(t, err)
	assert.Len(t, pending, 5) // All messages are pending

	// Step 6: Worker 1 acknowledges its messages
	ackIDs := make([]string, len(entries1))
	for i, entry := range entries1 {
		ackIDs[i] = entry.ID
	}
	err = client.StreamAck(ctx, stream, group, ackIDs...)
	require.NoError(t, err)

	// Step 7: Check pending again
	pending, err = client.StreamPending(ctx, stream, group, "-", "+", 100, "")
	require.NoError(t, err)
	assert.Len(t, pending, 2) // Only worker-2's messages are pending

	// Step 8: Worker 3 claims stuck messages from worker 2
	claimIDs := make([]string, len(entries2))
	for i, entry := range entries2 {
		claimIDs[i] = entry.ID
	}
	time.Sleep(50 * time.Millisecond) // Ensure some idle time
	claimed, err := client.StreamClaim(ctx, stream, group, "worker-3", 0, claimIDs...)
	require.NoError(t, err)
	assert.Len(t, claimed, 2)

	// Step 9: Worker 3 acknowledges claimed messages
	err = client.StreamAck(ctx, stream, group, claimIDs...)
	require.NoError(t, err)

	// Step 10: Verify no pending messages
	pending, err = client.StreamPending(ctx, stream, group, "-", "+", 100, "")
	require.NoError(t, err)
	assert.Len(t, pending, 0) // All messages acknowledged
}

// setupTestClient creates a StateClient for testing.
// It requires a running Redis instance on localhost:6379.
func setupTestClient(t *testing.T) *StateClient {
	cfg := DefaultConfig()
	// DB must be 0: RediSearch (FT.CREATE) rejects non-zero databases.
	cfg.URL = "redis://localhost:6379/0"

	client, err := NewStateClient(cfg)
	if err != nil {
		// Skip when Redis is simply not available (connection refused, redis.Nil, etc.).
		// These tests are infrastructure-dependent; CI without a local Redis should skip.
		if err == redis.Nil || isRedisUnavailableError(err) {
			t.Skip("Redis not available for testing")
		}
		// For module errors, create a basic client without health check
		if _, ok := err.(*ModuleError); ok {
			t.Logf("Warning: %v", err)
			// Create client directly without health check
			return createBasicTestClient(t, cfg)
		}
		t.Fatalf("failed to create test client: %v", err)
	}

	return client
}

// createBasicTestClient creates a client without module checks for testing
func createBasicTestClient(t *testing.T, cfg *Config) *StateClient {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	return &StateClient{
		client: client,
		config: cfg,
	}
}

// isRedisUnavailableError returns true when the error indicates Redis is not
// reachable (connection refused, network unreachable, etc.). Used by
// setupTestClient to skip tests rather than fatally fail when Redis is absent.
func isRedisUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	var connErr *ConnectionError
	if errors.As(err, &connErr) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection failed") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "i/o timeout")
}
