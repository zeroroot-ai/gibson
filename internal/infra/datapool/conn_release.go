package datapool

// connRelease implements the Conn.Release cleanup lifecycle. It is called
// by Conn.Release exactly once (guarded by the atomic in Conn).
//
// Order of operations:
//  1. Zero every byte of the KEK and nil the slice.
//  2. Call the Conn's release func (which decrements the eviction tracker,
//     returns the Postgres conn to its pool, closes the Neo4j session, and
//     returns the Redis client to the per-tenant wrapper).
func connRelease(c *Conn) {
	// Step 1: zero the KEK. This must happen before any other cleanup so
	// that the key material is scrubbed from memory even if a subsequent
	// step panics.
	zeroKEK(c)

	// Step 2: invoke the pool-internal release hook.
	if c.release != nil {
		c.release()
	}
}

// zeroKEK overwrites every byte of c.KEK with zero and sets the slice to nil.
// After this call, c.KEK == nil and the original backing array is zeroed.
func zeroKEK(c *Conn) {
	for i := range c.KEK {
		c.KEK[i] = 0
	}
	c.KEK = nil
}
