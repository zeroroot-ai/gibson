package contract

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// inMemoryBroker is a thread-safe, map-backed SecretsBroker implementation
// used as a test double for callers that depend on SecretsBroker. Each call
// to NewInMemoryBroker returns an independent instance with empty storage.
//
// Capabilities: CanPut, CanDelete, and CanList are all true.
// MaxValueBytes is 1 MiB. SupportsVersion is false (overwrites replace the
// current value; no version history is kept).
type inMemoryBroker struct {
	mu   sync.RWMutex
	data map[auth.TenantID]map[string][]byte
}

// maxInMemoryBytes is the maximum value size enforced by the in-memory
// broker (1 MiB).
const maxInMemoryBytes = 1 << 20

// NewInMemoryBroker returns a thread-safe, map-backed SecretsBroker. It is
// intended for use in unit tests of components that depend on SecretsBroker
// and as the reference implementation exercised by RunContract.
//
// The returned broker is fully independent: data written to one instance is
// not visible to any other instance. It holds data only in process memory;
// nothing persists across process restarts or across calls to
// NewInMemoryBroker.
func NewInMemoryBroker() secrets.Broker {
	return &inMemoryBroker{
		data: make(map[auth.TenantID]map[string][]byte),
	}
}

// Get returns the stored value for the named secret under the given tenant.
// It returns ErrNotFound when no secret with that name exists.
func (b *inMemoryBroker) Get(_ context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	td, ok := b.data[tenant]
	if !ok {
		return nil, fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
	}
	v, ok := td[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
	}
	// Return a copy so the caller owns the slice.
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// Put stores value under name for the given tenant, creating or overwriting
// any existing value. It returns ErrTooLarge when len(value) exceeds 1 MiB.
func (b *inMemoryBroker) Put(_ context.Context, tenant auth.TenantID, name string, value []byte) error {
	if len(value) > maxInMemoryBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", secrets.ErrTooLarge, len(value), maxInMemoryBytes)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.data[tenant]; !ok {
		b.data[tenant] = make(map[string][]byte)
	}
	// Store a copy so later mutations of the caller's slice do not
	// corrupt the stored value.
	stored := make([]byte, len(value))
	copy(stored, value)
	b.data[tenant][name] = stored
	return nil
}

// Delete removes the named secret for the given tenant. Deleting a
// non-existent secret is a no-op (idempotent).
func (b *inMemoryBroker) Delete(_ context.Context, tenant auth.TenantID, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if td, ok := b.data[tenant]; ok {
		delete(td, name)
	}
	return nil
}

// List returns the names of all secrets for the given tenant that match
// filter. When filter.Prefix is non-empty, only names with that prefix are
// returned. When filter.Limit is positive, at most that many results are
// returned after applying Offset.
func (b *inMemoryBroker) List(_ context.Context, tenant auth.TenantID, filter secrets.Filter) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	td, ok := b.data[tenant]
	if !ok {
		return nil, nil
	}

	var names []string
	for n := range td {
		if filter.Prefix == "" || strings.HasPrefix(n, filter.Prefix) {
			names = append(names, n)
		}
	}

	// Apply offset and limit.
	if filter.Offset > 0 {
		if filter.Offset >= len(names) {
			return nil, nil
		}
		names = names[filter.Offset:]
	}
	if filter.Limit > 0 && len(names) > filter.Limit {
		names = names[:filter.Limit]
	}
	return names, nil
}

// Health always returns nil for the in-memory broker.
func (b *inMemoryBroker) Health(_ context.Context) error {
	return nil
}

// Probe always returns nil for the in-memory broker. A real probe
// (write–read–delete canary) is unnecessary for an in-memory store.
func (b *inMemoryBroker) Probe(_ context.Context) error {
	return nil
}

// Capabilities returns the static capability set for the in-memory broker:
// CanPut, CanDelete, and CanList are all true; SupportsVersion is false;
// MaxValueBytes is 1 MiB.
func (b *inMemoryBroker) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{
		CanPut:          true,
		CanDelete:       true,
		CanList:         true,
		SupportsVersion: false,
		MaxValueBytes:   maxInMemoryBytes,
	}
}
