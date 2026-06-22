// Package pools provides opinionated, production-safe constructors for
// Neo4j, Redis, and pgxpool connection pools. Every constructor enforces
// mandatory overrides at construction time — a zero value for any required
// field is rejected immediately so misconfiguration fails fast, before the
// first live request.
//
// # Required overrides
//
// Silent default tuning is the primary source of production pool incidents.
// These constructors make the contract explicit: callers MUST supply the
// fields documented as "Required" in each Options struct. Missing a required
// field returns a descriptive error from the constructor; the pool is never
// returned in a misconfigured state.
//
// # Anti-pattern: defer session.Close inside a for-loop
//
// A common Neo4j bug is placing session cleanup inside a loop with defer:
//
//	// WRONG — defer is function-scoped, not loop-scoped.
//	// All sessions accumulate open until the enclosing function returns.
//	for _, id := range ids {
//	    session := driver.NewSession(ctx, neo4j.SessionConfig{})
//	    defer session.Close(ctx) // BUG: not closed until the function exits
//	    // ... work ...
//	}
//
// The correct pattern closes the session at the end of each iteration, either
// with an explicit close or by extracting the body into a helper function:
//
//	// CORRECT — explicit close at end of each iteration.
//	for _, id := range ids {
//	    session := driver.NewSession(ctx, neo4j.SessionConfig{})
//	    // ... work ...
//	    if err := session.Close(ctx); err != nil {
//	        // handle
//	    }
//	}
//
//	// ALSO CORRECT — defer is fine inside a named helper.
//	func processOne(ctx context.Context, driver neo4j.DriverWithContext, id string) error {
//	    session := driver.NewSession(ctx, neo4j.SessionConfig{})
//	    defer session.Close(ctx) // OK: deferred to helper return, not outer loop
//	    // ...
//	}
//
// Reference: tenant-operator prior bug where a for-loop accumulated open
// Neo4j sessions until the reconciler goroutine ran out of connections.
package pools
