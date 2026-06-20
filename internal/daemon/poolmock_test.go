package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// --- shared test mocks ---
//
// mockPool / minimalConn were extracted here when the dead GraphRAG bridge adapter
// (and its test) were removed (gibson#835/#768); they back graph_service_test.go
// and tenant_isolation_gate_test.go.

// mockPool is a controllable datapool.Pool for unit tests.
type mockPool struct {
	conn *datapool.Conn
	err  error
}

func (p *mockPool) For(_ context.Context, _ auth.TenantID) (*datapool.Conn, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.conn, nil
}

func (p *mockPool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, fmt.Errorf("admin pool not configured in mock")
}

func (p *mockPool) SetAdminPool(_ datapool.AdminAcquirer) {}

func (p *mockPool) Close() error { return nil }

// Ensure mockPool satisfies datapool.Pool at compile time.
var _ datapool.Pool = (*mockPool)(nil)

// minimalConn returns a *datapool.Conn with all nil fields. SessionGraphClient is
// nil-safe so operations on a nil session return driver-not-connected errors (not
// panics), which is acceptable for these unit tests.
func minimalConn() *datapool.Conn {
	return &datapool.Conn{
		Neo4j: nil,
	}
}
