package daemon

import (
	"sync"
	"time"
)

// LogEntry represents a single log entry from a component.
type LogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level,omitempty"`
	Message   string         `json:"message"`
	Component string         `json:"component"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// RingBuffer provides a thread-safe ring buffer for storing recent log entries.
// When the buffer is full, adding new entries will overwrite the oldest entries.
type RingBuffer struct {
	entries []LogEntry
	size    int
	head    int  // Points to the next write position
	count   int  // Number of entries currently stored
	mu      sync.RWMutex
}

// NewRingBuffer creates a new ring buffer with the specified size.
func NewRingBuffer(size int) *RingBuffer {
	if size <= 0 {
		size = 1000 // Default size
	}
	return &RingBuffer{
		entries: make([]LogEntry, size),
		size:    size,
		head:    0,
		count:   0,
	}
}

// Add adds a new entry to the buffer. If the buffer is full,
// the oldest entry will be overwritten.
func (b *RingBuffer) Add(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.size

	if b.count < b.size {
		b.count++
	}
}

// GetLast returns the last n entries from the buffer in chronological order.
// If n is greater than the number of entries available, all entries are returned.
// If n is 0 or negative, all entries are returned.
func (b *RingBuffer) GetLast(n int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if n <= 0 || n >= b.count {
		n = b.count
	}

	if b.count == 0 {
		return []LogEntry{}
	}

	result := make([]LogEntry, n)

	// Calculate the starting position
	// If buffer is full: start = (head - n + size) % size
	// If buffer is not full: start = count - n
	var start int
	if b.count == b.size {
		// Buffer is full, head points to oldest entry
		start = (b.head - n + b.size) % b.size
	} else {
		// Buffer is not full, entries are from 0 to count-1
		start = b.count - n
	}

	// Copy entries in chronological order
	for i := 0; i < n; i++ {
		idx := (start + i) % b.size
		result[i] = b.entries[idx]
	}

	return result
}

// GetSince returns all entries with timestamps after the specified time.
// Entries are returned in chronological order.
func (b *RingBuffer) GetSince(since time.Time) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.count == 0 {
		return []LogEntry{}
	}

	var result []LogEntry

	// Calculate the starting position (oldest entry)
	var start int
	if b.count == b.size {
		start = b.head // Oldest entry is at head position when full
	} else {
		start = 0 // Oldest entry is at position 0 when not full
	}

	// Iterate through all entries in chronological order
	for i := 0; i < b.count; i++ {
		idx := (start + i) % b.size
		entry := b.entries[idx]

		if entry.Timestamp.After(since) {
			result = append(result, entry)
		}
	}

	return result
}

// GetAll returns all entries in the buffer in chronological order.
func (b *RingBuffer) GetAll() []LogEntry {
	return b.GetLast(0)
}

// Count returns the current number of entries in the buffer.
func (b *RingBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// Clear removes all entries from the buffer.
func (b *RingBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.head = 0
	b.count = 0
	// Don't reallocate, just reset pointers
}
