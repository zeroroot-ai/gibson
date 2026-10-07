// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

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
}

// Memory returns the per-tenant storage backends for the 3-tier memory system.
// The returned struct is valid only while the Conn is held (before Release is called).
func (c *Conn) Memory() MemoryBackends {
	return MemoryBackends{}
}
