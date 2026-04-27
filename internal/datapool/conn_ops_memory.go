package datapool

import (
	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/datapool/vectordb"
)

// MemoryBackends holds the per-tenant storage backends for the 3-tier memory system.
// Callers use the fields directly to construct tier-specific memory stores.
//
// Working memory is intentionally excluded here because it is an in-process
// map (no storage backend needed); create a new WorkingMemory per mission in
// the memory factory.
//
// Mission memory uses the tenant-bound Redis client; keys carry no tenant prefix
// because the client itself is the isolation boundary (audit C16 closure).
//
// Long-term memory uses the tenant-bound vector client.
type MemoryBackends struct {
	// Redis is the tenant-bound *redis.Client for mission memory (tier 2).
	// Never points at the master index DB (db 0).
	Redis *goredis.Client

	// Vector is the tenant-bound vector store client for long-term memory (tier 3).
	Vector vectordb.Client
}

// Memory returns the per-tenant storage backends for the 3-tier memory system.
// The returned struct is valid only while the Conn is held (before Release is called).
func (c *Conn) Memory() MemoryBackends {
	return MemoryBackends{
		Redis:  c.Redis,
		Vector: c.Vector,
	}
}
