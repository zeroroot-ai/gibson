package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRingBuffer(t *testing.T) {
	tests := []struct {
		name         string
		size         int
		expectedSize int
	}{
		{
			name:         "positive size",
			size:         100,
			expectedSize: 100,
		},
		{
			name:         "zero size defaults to 1000",
			size:         0,
			expectedSize: 1000,
		},
		{
			name:         "negative size defaults to 1000",
			size:         -5,
			expectedSize: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewRingBuffer(tt.size)
			require.NotNil(t, buf)
			assert.Equal(t, tt.expectedSize, buf.size)
			assert.Equal(t, 0, buf.Count())
		})
	}
}

func TestRingBuffer_Add(t *testing.T) {
	buf := NewRingBuffer(5)

	// Add first entry
	entry1 := LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "first message",
		Component: "test-component",
	}
	buf.Add(entry1)

	assert.Equal(t, 1, buf.Count())

	// Add more entries
	for i := 2; i <= 5; i++ {
		buf.Add(LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test-component",
		})
	}

	assert.Equal(t, 5, buf.Count())

	// Add one more to trigger overflow
	buf.Add(LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "overflow message",
		Component: "test-component",
	})

	// Count should still be 5 (max size)
	assert.Equal(t, 5, buf.Count())
}

func TestRingBuffer_GetLast(t *testing.T) {
	buf := NewRingBuffer(10)

	// Test empty buffer
	entries := buf.GetLast(5)
	assert.Empty(t, entries)

	// Add 5 entries
	now := time.Now()
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	// Get last 3 entries
	entries = buf.GetLast(3)
	assert.Len(t, entries, 3)
	assert.Equal(t, "message 2", entries[0].Message)
	assert.Equal(t, "message 3", entries[1].Message)
	assert.Equal(t, "message 4", entries[2].Message)

	// Get all entries
	entries = buf.GetLast(0)
	assert.Len(t, entries, 5)
	assert.Equal(t, "message 0", entries[0].Message)

	// Get more entries than available
	entries = buf.GetLast(100)
	assert.Len(t, entries, 5)
}

func TestRingBuffer_GetLast_Overflow(t *testing.T) {
	buf := NewRingBuffer(5)

	// Fill buffer completely
	now := time.Now()
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	// Add 3 more entries (causing overflow)
	for i := 5; i < 8; i++ {
		buf.Add(LogEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	// Buffer should contain messages 3-7 (oldest 0-2 were overwritten)
	entries := buf.GetLast(0)
	assert.Len(t, entries, 5)
	assert.Equal(t, "message 3", entries[0].Message)
	assert.Equal(t, "message 4", entries[1].Message)
	assert.Equal(t, "message 5", entries[2].Message)
	assert.Equal(t, "message 6", entries[3].Message)
	assert.Equal(t, "message 7", entries[4].Message)

	// Get last 2 entries
	entries = buf.GetLast(2)
	assert.Len(t, entries, 2)
	assert.Equal(t, "message 6", entries[0].Message)
	assert.Equal(t, "message 7", entries[1].Message)
}

func TestRingBuffer_GetSince(t *testing.T) {
	buf := NewRingBuffer(10)

	// Test empty buffer
	now := time.Now()
	entries := buf.GetSince(now)
	assert.Empty(t, entries)

	// Add entries with specific timestamps
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	// Get entries since 2 minutes after base time
	sinceTime := baseTime.Add(2 * time.Minute)
	entries = buf.GetSince(sinceTime)

	// Should get messages 3 and 4 (timestamps at 3 and 4 minutes)
	assert.Len(t, entries, 2)
	assert.Equal(t, "message 3", entries[0].Message)
	assert.Equal(t, "message 4", entries[1].Message)

	// Get entries since before all entries
	entries = buf.GetSince(baseTime.Add(-1 * time.Minute))
	assert.Len(t, entries, 5)

	// Get entries since after all entries
	entries = buf.GetSince(baseTime.Add(10 * time.Minute))
	assert.Empty(t, entries)
}

func TestRingBuffer_GetSince_Overflow(t *testing.T) {
	buf := NewRingBuffer(3)

	// Add entries that will cause overflow
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	// Buffer should contain only messages 2, 3, 4
	// Get entries since 1 minute (should include 2, 3, 4)
	sinceTime := baseTime.Add(1 * time.Minute)
	entries := buf.GetSince(sinceTime)

	assert.Len(t, entries, 3)
	assert.Equal(t, "message 2", entries[0].Message)
	assert.Equal(t, "message 3", entries[1].Message)
	assert.Equal(t, "message 4", entries[2].Message)
}

func TestRingBuffer_Clear(t *testing.T) {
	buf := NewRingBuffer(10)

	// Add some entries
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "message",
			Component: "test",
		})
	}

	assert.Equal(t, 5, buf.Count())

	// Clear the buffer
	buf.Clear()

	assert.Equal(t, 0, buf.Count())
	entries := buf.GetAll()
	assert.Empty(t, entries)
}

func TestRingBuffer_ConcurrentAccess(t *testing.T) {
	buf := NewRingBuffer(1000)
	var wg sync.WaitGroup

	// Number of goroutines for writers and readers
	numWriters := 10
	numReaders := 10
	entriesPerWriter := 100

	// Start writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for j := 0; j < entriesPerWriter; j++ {
				buf.Add(LogEntry{
					Timestamp: time.Now(),
					Level:     "info",
					Message:   "concurrent message",
					Component: "test",
				})
			}
		}(i)
	}

	// Start readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = buf.GetLast(10)
				_ = buf.GetSince(time.Now().Add(-1 * time.Second))
				_ = buf.Count()
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify buffer is in valid state
	count := buf.Count()
	assert.True(t, count <= 1000, "count should not exceed buffer size")
	assert.True(t, count > 0, "count should be greater than 0")

	// Verify we can still read from buffer
	entries := buf.GetLast(10)
	assert.True(t, len(entries) <= 10, "should not return more entries than requested")
}

func TestRingBuffer_GetAll(t *testing.T) {
	buf := NewRingBuffer(10)

	// Add some entries
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	entries := buf.GetAll()
	assert.Len(t, entries, 5)
	assert.Equal(t, "message 0", entries[0].Message)
	assert.Equal(t, "message 4", entries[4].Message)
}

func TestRingBuffer_ChronologicalOrder(t *testing.T) {
	buf := NewRingBuffer(5)

	// Add entries with incrementing timestamps
	baseTime := time.Now()
	for i := 0; i < 10; i++ {
		buf.Add(LogEntry{
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
			Level:     "info",
			Message:   "message " + string(rune('0'+i)),
			Component: "test",
		})
	}

	// Get all entries - should be in chronological order
	entries := buf.GetAll()
	require.Len(t, entries, 5)

	// Verify chronological order
	for i := 1; i < len(entries); i++ {
		assert.True(t, entries[i].Timestamp.After(entries[i-1].Timestamp),
			"entries should be in chronological order")
	}

	// First entry should be message 5 (oldest after overflow)
	assert.Equal(t, "message 5", entries[0].Message)
	// Last entry should be message 9 (newest)
	assert.Equal(t, "message 9", entries[4].Message)
}
