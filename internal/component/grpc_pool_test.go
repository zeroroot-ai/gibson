package component

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// mockGRPCServer creates a test gRPC server that implements the health check service.
type mockGRPCServer struct {
	addr     string
	server   *grpc.Server
	listener net.Listener
	started  chan struct{}
}

func newMockGRPCServer(t *testing.T) *mockGRPCServer {
	t.Helper()

	// Create listener on random port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	// Create gRPC server
	server := grpc.NewServer()

	// Register health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)

	return &mockGRPCServer{
		addr:     listener.Addr().String(),
		server:   server,
		listener: listener,
		started:  make(chan struct{}),
	}
}

func (m *mockGRPCServer) start() {
	go func() {
		close(m.started)
		_ = m.server.Serve(m.listener)
	}()

	// Wait for server to start
	<-m.started

	// Give server a moment to fully start
	time.Sleep(50 * time.Millisecond)
}

func (m *mockGRPCServer) stop() {
	m.server.GracefulStop()
	_ = m.listener.Close()
}

func TestNewGRPCPool(t *testing.T) {
	t.Run("creates empty pool with no options", func(t *testing.T) {
		pool := NewGRPCPool()

		if pool == nil {
			t.Fatal("expected non-nil pool")
		}

		if pool.conns == nil {
			t.Fatal("expected conns map to be initialized")
		}

		if len(pool.conns) != 0 {
			t.Errorf("expected empty pool, got %d connections", len(pool.conns))
		}

		if len(pool.opts) != 0 {
			t.Errorf("expected no dial options, got %d", len(pool.opts))
		}
	})

	t.Run("creates pool with custom options", func(t *testing.T) {
		opts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		}

		pool := NewGRPCPool(opts...)

		if len(pool.opts) != len(opts) {
			t.Errorf("expected %d dial options, got %d", len(opts), len(pool.opts))
		}
	})
}

func TestGRPCPool_Get(t *testing.T) {
	t.Run("returns error for empty endpoint", func(t *testing.T) {
		pool := NewGRPCPool()
		defer pool.Close()

		ctx := context.Background()
		_, err := pool.Get(ctx, "")

		if err == nil {
			t.Fatal("expected error for empty endpoint")
		}

		if err.Error() != "endpoint cannot be empty" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("creates new connection on first call", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()
		defer server.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()
		conn, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		if conn == nil {
			t.Fatal("expected non-nil connection")
		}

		// Verify connection is in pool
		if pool.Len() != 1 {
			t.Errorf("expected 1 connection in pool, got %d", pool.Len())
		}

		// Verify connection state is healthy (READY or CONNECTING)
		state := conn.GetState()
		if state != connectivity.Ready && state != connectivity.Connecting && state != connectivity.Idle {
			t.Errorf("expected healthy state (READY/CONNECTING/IDLE), got %v", state)
		}
	})

	t.Run("reuses existing healthy connection", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()
		defer server.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// First call - creates connection
		conn1, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		// Second call - should reuse connection
		conn2, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		// Should be the same connection
		if conn1 != conn2 {
			t.Error("expected same connection to be reused")
		}

		// Pool should still have only 1 connection
		if pool.Len() != 1 {
			t.Errorf("expected 1 connection in pool, got %d", pool.Len())
		}
	})

	t.Run("recreates connection if in bad state", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// Create initial connection
		conn1, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		// Stop the server to force connection into bad state
		server.stop()

		// Wait for connection to detect failure with timeout
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		// Try to wait for state change, but with timeout
		state := conn1.GetState()
		for state != connectivity.TransientFailure && state != connectivity.Shutdown {
			if !conn1.WaitForStateChange(waitCtx, state) {
				// Timeout or context canceled - skip this test case
				t.Skip("connection didn't transition to bad state within timeout")
			}
			state = conn1.GetState()
		}

		// Start new server on same address (simulate service restart)
		server2 := newMockGRPCServer(t)
		server2.listener, err = net.Listen("tcp", server.addr)
		if err != nil {
			t.Fatalf("failed to recreate listener: %v", err)
		}
		server2.addr = server.addr
		server2.start()
		defer server2.stop()

		// Get connection again - should detect bad state and recreate
		conn2, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection after restart: %v", err)
		}

		// Should be different connection
		if conn1 == conn2 {
			t.Error("expected new connection to be created")
		}
	})

	t.Run("concurrent Get calls are safe", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()
		defer server.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// Launch 10 concurrent goroutines trying to get the same connection
		var wg sync.WaitGroup
		conns := make([]*grpc.ClientConn, 10)
		errors := make([]error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				conns[idx], errors[idx] = pool.Get(ctx, server.addr)
			}(i)
		}

		wg.Wait()

		// All should succeed
		for i, err := range errors {
			if err != nil {
				t.Errorf("goroutine %d failed: %v", i, err)
			}
		}

		// All should get the same connection
		firstConn := conns[0]
		for i, conn := range conns {
			if conn != firstConn {
				t.Errorf("goroutine %d got different connection", i)
			}
		}

		// Pool should have only 1 connection
		if pool.Len() != 1 {
			t.Errorf("expected 1 connection in pool, got %d", pool.Len())
		}
	})

	t.Run("handles multiple endpoints", func(t *testing.T) {
		// Start two mock servers
		server1 := newMockGRPCServer(t)
		server1.start()
		defer server1.stop()

		server2 := newMockGRPCServer(t)
		server2.start()
		defer server2.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// Get connections to both servers
		conn1, err := pool.Get(ctx, server1.addr)
		if err != nil {
			t.Fatalf("failed to get connection 1: %v", err)
		}

		conn2, err := pool.Get(ctx, server2.addr)
		if err != nil {
			t.Fatalf("failed to get connection 2: %v", err)
		}

		// Should be different connections
		if conn1 == conn2 {
			t.Error("expected different connections for different endpoints")
		}

		// Pool should have 2 connections
		if pool.Len() != 2 {
			t.Errorf("expected 2 connections in pool, got %d", pool.Len())
		}
	})
}

func TestGRPCPool_Remove(t *testing.T) {
	t.Run("removes existing connection", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()
		defer server.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// Create connection
		conn, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		// Verify it's in the pool
		if pool.Len() != 1 {
			t.Errorf("expected 1 connection in pool, got %d", pool.Len())
		}

		// Remove the connection
		if err := pool.Remove(server.addr); err != nil {
			t.Errorf("failed to remove connection: %v", err)
		}

		// Verify it's removed from pool
		if pool.Len() != 0 {
			t.Errorf("expected 0 connections in pool, got %d", pool.Len())
		}

		// Verify connection is closed
		state := conn.GetState()
		if state != connectivity.Shutdown {
			t.Errorf("expected SHUTDOWN state, got %v", state)
		}
	})

	t.Run("no-op for non-existent endpoint", func(t *testing.T) {
		pool := NewGRPCPool()
		defer pool.Close()

		// Remove non-existent endpoint should not error
		if err := pool.Remove("localhost:9999"); err != nil {
			t.Errorf("expected no error for non-existent endpoint, got: %v", err)
		}
	})

	t.Run("concurrent Remove calls are safe", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()
		defer server.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// Create connection
		_, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		// Launch 5 concurrent Remove calls
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = pool.Remove(server.addr)
			}()
		}

		wg.Wait()

		// Pool should be empty
		if pool.Len() != 0 {
			t.Errorf("expected 0 connections in pool, got %d", pool.Len())
		}
	})
}

func TestGRPCPool_Close(t *testing.T) {
	t.Run("closes all connections", func(t *testing.T) {
		// Start three mock servers
		servers := make([]*mockGRPCServer, 3)
		for i := 0; i < 3; i++ {
			servers[i] = newMockGRPCServer(t)
			servers[i].start()
			defer servers[i].stop()
		}

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))

		ctx := context.Background()

		// Create connections to all servers
		conns := make([]*grpc.ClientConn, 3)
		for i, server := range servers {
			var err error
			conns[i], err = pool.Get(ctx, server.addr)
			if err != nil {
				t.Fatalf("failed to get connection %d: %v", i, err)
			}
		}

		// Verify pool has 3 connections
		if pool.Len() != 3 {
			t.Errorf("expected 3 connections in pool, got %d", pool.Len())
		}

		// Close the pool
		if err := pool.Close(); err != nil {
			t.Errorf("failed to close pool: %v", err)
		}

		// Verify pool is empty
		if pool.Len() != 0 {
			t.Errorf("expected 0 connections in pool after close, got %d", pool.Len())
		}

		// Verify all connections are closed
		for i, conn := range conns {
			state := conn.GetState()
			if state != connectivity.Shutdown {
				t.Errorf("connection %d not shutdown, state: %v", i, state)
			}
		}
	})

	t.Run("no error for empty pool", func(t *testing.T) {
		pool := NewGRPCPool()

		if err := pool.Close(); err != nil {
			t.Errorf("expected no error for empty pool, got: %v", err)
		}
	})

	t.Run("concurrent Close calls are safe", func(t *testing.T) {
		// Start mock server
		server := newMockGRPCServer(t)
		server.start()
		defer server.stop()

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))

		ctx := context.Background()

		// Create connection
		_, err := pool.Get(ctx, server.addr)
		if err != nil {
			t.Fatalf("failed to get connection: %v", err)
		}

		// Launch 5 concurrent Close calls
		var wg sync.WaitGroup
		errors := make([]error, 5)

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				errors[idx] = pool.Close()
			}(i)
		}

		wg.Wait()

		// At least one should succeed (others may see empty pool)
		// All should either succeed or return nil
		for i, err := range errors {
			if err != nil {
				t.Errorf("Close call %d failed: %v", i, err)
			}
		}

		// Pool should be empty
		if pool.Len() != 0 {
			t.Errorf("expected 0 connections in pool, got %d", pool.Len())
		}
	})
}

func TestGRPCPool_Len(t *testing.T) {
	t.Run("returns correct count", func(t *testing.T) {
		// Start three mock servers
		servers := make([]*mockGRPCServer, 3)
		for i := 0; i < 3; i++ {
			servers[i] = newMockGRPCServer(t)
			servers[i].start()
			defer servers[i].stop()
		}

		pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
		defer pool.Close()

		ctx := context.Background()

		// Initially empty
		if pool.Len() != 0 {
			t.Errorf("expected 0 connections, got %d", pool.Len())
		}

		// Add connections one by one
		for i, server := range servers {
			_, err := pool.Get(ctx, server.addr)
			if err != nil {
				t.Fatalf("failed to get connection %d: %v", i, err)
			}

			expected := i + 1
			if pool.Len() != expected {
				t.Errorf("expected %d connections, got %d", expected, pool.Len())
			}
		}

		// Remove connections one by one
		for i, server := range servers {
			_ = pool.Remove(server.addr)

			expected := len(servers) - i - 1
			if pool.Len() != expected {
				t.Errorf("expected %d connections, got %d", expected, pool.Len())
			}
		}
	})
}

// Benchmark tests
func BenchmarkGRPCPool_Get(b *testing.B) {
	server := &mockGRPCServer{}
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatalf("failed to create listener: %v", err)
	}

	server.addr = listener.Addr().String()
	server.server = grpc.NewServer()
	server.listener = listener
	server.started = make(chan struct{})

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server.server, healthServer)

	go func() {
		close(server.started)
		_ = server.server.Serve(listener)
	}()

	<-server.started
	time.Sleep(50 * time.Millisecond)

	defer server.stop()

	pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer pool.Close()

	ctx := context.Background()

	// Pre-populate one connection to test reuse path
	_, err = pool.Get(ctx, server.addr)
	if err != nil {
		b.Fatalf("failed to get initial connection: %v", err)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := pool.Get(ctx, server.addr)
			if err != nil {
				b.Errorf("Get failed: %v", err)
			}
		}
	})
}

func BenchmarkGRPCPool_GetMultipleEndpoints(b *testing.B) {
	// Create 10 servers
	servers := make([]*mockGRPCServer, 10)
	for i := 0; i < 10; i++ {
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			b.Fatalf("failed to create listener: %v", err)
		}

		server := &mockGRPCServer{
			addr:     listener.Addr().String(),
			server:   grpc.NewServer(),
			listener: listener,
			started:  make(chan struct{}),
		}

		healthServer := health.NewServer()
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		grpc_health_v1.RegisterHealthServer(server.server, healthServer)

		go func() {
			close(server.started)
			_ = server.server.Serve(listener)
		}()

		<-server.started
		time.Sleep(50 * time.Millisecond)

		servers[i] = server
		defer server.stop()
	}

	pool := NewGRPCPool(grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer pool.Close()

	ctx := context.Background()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Round-robin through servers
			endpoint := servers[i%len(servers)].addr
			_, err := pool.Get(ctx, endpoint)
			if err != nil {
				b.Errorf("Get failed: %v", err)
			}
			i++
		}
	})
}

// Example tests
func ExampleGRPCPool_Get() {
	// Create pool
	pool := NewGRPCPool()
	defer pool.Close()

	// Get connection (creates if needed, reuses if exists)
	ctx := context.Background()
	conn, err := pool.Get(ctx, "localhost:50051")
	if err != nil {
		fmt.Printf("failed to get connection: %v\n", err)
		return
	}

	// Use the connection
	fmt.Printf("connection state: %v\n", conn.GetState())
}

func ExampleGRPCPool_Remove() {
	pool := NewGRPCPool()
	defer pool.Close()

	ctx := context.Background()
	_, err := pool.Get(ctx, "localhost:50051")
	if err != nil {
		fmt.Printf("failed to get connection: %v\n", err)
		return
	}

	// If RPC fails, remove the connection
	if err := pool.Remove("localhost:50051"); err != nil {
		fmt.Printf("failed to remove connection: %v\n", err)
		return
	}

	fmt.Println("connection removed")
	// Output: connection removed
}
