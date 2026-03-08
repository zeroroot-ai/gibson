//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	healthhttp "github.com/zero-day-ai/sdk/health/http"
	"github.com/zero-day-ai/sdk/types"
)

// TestHealthz_Returns200_WhenDaemonHealthy verifies that /healthz returns 200 OK
// when the daemon is running and healthy with no liveness checks registered.
func TestHealthz_Returns200_WhenDaemonHealthy(t *testing.T) {
	// Create and start health server
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	err := server.Start()
	require.NoError(t, err, "Failed to start health server")

	// Ensure cleanup
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Make request to /healthz
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	resp, err := http.Get(url)
	require.NoError(t, err, "Failed to GET /healthz")
	defer resp.Body.Close()

	// Verify status code
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected 200 OK from /healthz")

	// Verify Content-Type header
	contentType := resp.Header.Get("Content-Type")
	assert.Equal(t, "application/json", contentType, "Expected application/json content type")

	// Parse response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	var healthResp healthhttp.Response
	err = json.Unmarshal(body, &healthResp)
	require.NoError(t, err, "Failed to unmarshal JSON response")

	// Verify response structure
	assert.Equal(t, "healthy", healthResp.Status, "Expected healthy status")
	assert.NotEmpty(t, healthResp.Timestamp, "Expected non-empty timestamp")

	// Verify timestamp is in RFC3339 format
	_, err = time.Parse(time.RFC3339, healthResp.Timestamp)
	assert.NoError(t, err, "Timestamp should be in RFC3339 format")

	t.Logf("Successfully verified /healthz returns 200 OK with status: %s", healthResp.Status)
}

// TestHealthz_WithLivenessChecks verifies that /healthz runs liveness checks
// and returns appropriate status based on check results.
func TestHealthz_WithLivenessChecks(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	// Register a healthy liveness check
	server.RegisterLivenessCheck("basic", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("service is alive")
	})

	err := server.Start()
	require.NoError(t, err, "Failed to start health server")

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Test healthy liveness check
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Healthy liveness check should return 200")

	var healthResp healthhttp.Response
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &healthResp)
	assert.Equal(t, "healthy", healthResp.Status)

	t.Logf("Successfully verified /healthz with healthy liveness check")
}

// TestReadyz_Returns200_WhenDependenciesUp verifies that /readyz returns 200 OK
// when all registered readiness checks pass.
func TestReadyz_Returns200_WhenDependenciesUp(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	// Register multiple healthy readiness checks simulating dependencies
	server.RegisterReadinessCheck("database", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("database connection healthy")
	})

	server.RegisterReadinessCheck("cache", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("cache connection healthy")
	})

	server.RegisterReadinessCheck("message_queue", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("message queue connection healthy")
	})

	err := server.Start()
	require.NoError(t, err, "Failed to start health server")

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Make request to /readyz
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	resp, err := http.Get(url)
	require.NoError(t, err, "Failed to GET /readyz")
	defer resp.Body.Close()

	// Verify status code
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected 200 OK when all dependencies healthy")

	// Parse response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var readyResp healthhttp.Response
	err = json.Unmarshal(body, &readyResp)
	require.NoError(t, err)

	// Verify overall status
	assert.Equal(t, "healthy", readyResp.Status, "Expected overall healthy status")
	assert.NotEmpty(t, readyResp.Timestamp, "Expected timestamp")

	// Verify individual check results are included
	require.NotNil(t, readyResp.Checks, "Expected check results in response")
	assert.Len(t, readyResp.Checks, 3, "Expected 3 check results")

	// Verify each check is healthy
	for name, checkResult := range readyResp.Checks {
		assert.Equal(t, "healthy", checkResult.Status, "Check %s should be healthy", name)
		assert.NotEmpty(t, checkResult.Message, "Check %s should have a message", name)
	}

	t.Logf("Successfully verified /readyz returns 200 OK with %d healthy checks", len(readyResp.Checks))
}

// TestReadyz_Returns503_WhenDependencyDown verifies that /readyz returns 503
// Service Unavailable when one or more readiness checks fail.
func TestReadyz_Returns503_WhenDependencyDown(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	// Register healthy and unhealthy readiness checks
	server.RegisterReadinessCheck("database", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("database connection healthy")
	})

	server.RegisterReadinessCheck("redis", func(ctx context.Context) types.HealthStatus {
		return types.NewUnhealthyStatus("redis connection failed", map[string]any{
			"error": "connection refused",
		})
	})

	server.RegisterReadinessCheck("neo4j", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("neo4j connection healthy")
	})

	err := server.Start()
	require.NoError(t, err, "Failed to start health server")

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Make request to /readyz
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	resp, err := http.Get(url)
	require.NoError(t, err, "Failed to GET /readyz")
	defer resp.Body.Close()

	// Verify status code is 503 Service Unavailable
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"Expected 503 Service Unavailable when dependency fails")

	// Parse response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var readyResp healthhttp.Response
	err = json.Unmarshal(body, &readyResp)
	require.NoError(t, err)

	// Verify overall status is unhealthy
	assert.Equal(t, "unhealthy", readyResp.Status, "Expected overall unhealthy status")
	assert.NotEmpty(t, readyResp.Message, "Expected error message")
	assert.Contains(t, readyResp.Message, "failed", "Error message should mention failures")

	// Verify individual check results
	require.NotNil(t, readyResp.Checks)
	assert.Len(t, readyResp.Checks, 3, "Expected 3 check results")

	// Verify redis check is unhealthy
	redisCheck, exists := readyResp.Checks["redis"]
	require.True(t, exists, "Redis check should be in response")
	assert.Equal(t, "unhealthy", redisCheck.Status, "Redis check should be unhealthy")
	assert.Contains(t, redisCheck.Message, "connection failed", "Should have failure message")
	assert.NotNil(t, redisCheck.Details, "Should have error details")

	// Verify other checks are healthy
	dbCheck := readyResp.Checks["database"]
	assert.Equal(t, "healthy", dbCheck.Status, "Database check should be healthy")

	neo4jCheck := readyResp.Checks["neo4j"]
	assert.Equal(t, "healthy", neo4jCheck.Status, "Neo4j check should be healthy")

	t.Logf("Successfully verified /readyz returns 503 when dependency down: %s", readyResp.Message)
}

// TestReadyz_Returns503_WhenDegradedDependency verifies that /readyz returns 503
// even when a dependency is only degraded (not completely unhealthy).
func TestReadyz_Returns503_WhenDegradedDependency(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	// Register checks with one degraded dependency
	server.RegisterReadinessCheck("primary_db", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("primary database healthy")
	})

	server.RegisterReadinessCheck("cache", func(ctx context.Context) types.HealthStatus {
		return types.NewDegradedStatus("cache running slowly", map[string]any{
			"latency_ms": 500,
		})
	})

	err := server.Start()
	require.NoError(t, err)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Make request to /readyz
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify status code is 503 (degraded is treated as not ready)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"Expected 503 when dependency is degraded")

	var readyResp healthhttp.Response
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &readyResp)

	assert.Equal(t, "degraded", readyResp.Status, "Expected degraded status")
	assert.Contains(t, readyResp.Message, "degraded", "Message should mention degradation")

	t.Logf("Successfully verified /readyz returns 503 for degraded dependency: %s", readyResp.Message)
}

// TestHealthEndpoints_JSONFormat verifies that both endpoints return properly
// formatted JSON responses that match the specification.
func TestHealthEndpoints_JSONFormat(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	// Register readiness checks
	server.RegisterReadinessCheck("test_check", func(ctx context.Context) types.HealthStatus {
		return types.NewHealthyStatus("test check passed")
	})

	err := server.Start()
	require.NoError(t, err)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	tests := []struct {
		name     string
		endpoint string
	}{
		{
			name:     "healthz endpoint",
			endpoint: "/healthz",
		},
		{
			name:     "readyz endpoint",
			endpoint: "/readyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("http://127.0.0.1:%d%s", port, tt.endpoint)
			resp, err := http.Get(url)
			require.NoError(t, err, "Failed to GET %s", tt.endpoint)
			defer resp.Body.Close()

			// Verify Content-Type is JSON
			contentType := resp.Header.Get("Content-Type")
			assert.Equal(t, "application/json", contentType,
				"Content-Type should be application/json")

			// Parse response
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err, "Failed to read response body")

			var healthResp healthhttp.Response
			err = json.Unmarshal(body, &healthResp)
			require.NoError(t, err, "Response should be valid JSON")

			// Verify required fields
			assert.NotEmpty(t, healthResp.Status, "Status field is required")
			assert.Contains(t, []string{"healthy", "degraded", "unhealthy"}, healthResp.Status,
				"Status must be one of: healthy, degraded, unhealthy")

			assert.NotEmpty(t, healthResp.Timestamp, "Timestamp field is required")

			// Verify timestamp format (RFC3339)
			parsedTime, err := time.Parse(time.RFC3339, healthResp.Timestamp)
			assert.NoError(t, err, "Timestamp must be in RFC3339 format")
			assert.WithinDuration(t, time.Now(), parsedTime, 5*time.Second,
				"Timestamp should be close to current time")

			// For /readyz, verify checks are included
			if tt.endpoint == "/readyz" {
				assert.NotNil(t, healthResp.Checks, "Readyz should include check results")
				assert.NotEmpty(t, healthResp.Checks, "Readyz should have at least one check")

				// Verify check result structure
				for checkName, checkResult := range healthResp.Checks {
					assert.NotEmpty(t, checkResult.Status, "Check %s must have status", checkName)
					assert.Contains(t, []string{"healthy", "degraded", "unhealthy"}, checkResult.Status,
						"Check %s status must be valid", checkName)
					// Message and Details are optional, but if present should be valid
					if checkResult.Details != nil {
						assert.IsType(t, map[string]any{}, checkResult.Details,
							"Check %s details must be a map", checkName)
					}
				}
			}

			t.Logf("Verified JSON format for %s: status=%s, timestamp=%s",
				tt.endpoint, healthResp.Status, healthResp.Timestamp)
		})
	}
}

// TestHealthEndpoints_ConcurrentRequests verifies that the health server
// handles multiple concurrent requests correctly.
func TestHealthEndpoints_ConcurrentRequests(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 5 * time.Second,
	})

	// Register a check that takes some time
	server.RegisterReadinessCheck("slow_check", func(ctx context.Context) types.HealthStatus {
		time.Sleep(100 * time.Millisecond)
		return types.NewHealthyStatus("slow check completed")
	})

	err := server.Start()
	require.NoError(t, err)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Make 10 concurrent requests to /readyz
	numRequests := 10
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			url := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
			resp, err := http.Get(url)
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("unexpected status code: %d", resp.StatusCode)
				return
			}

			results <- nil
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		select {
		case err := <-results:
			assert.NoError(t, err, "Concurrent request %d failed", i)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	t.Logf("Successfully handled %d concurrent requests", numRequests)
}

// TestHealthEndpoints_CheckTimeout verifies that checks respect the timeout
// configuration and don't block indefinitely.
func TestHealthEndpoints_CheckTimeout(t *testing.T) {
	port := getAvailablePort(t)
	server := healthhttp.NewServer(&healthhttp.Config{
		Port:         port,
		BindAddress:  "127.0.0.1",
		CheckTimeout: 500 * time.Millisecond, // Short timeout
	})

	// Register a check that takes longer than the timeout
	server.RegisterReadinessCheck("hanging_check", func(ctx context.Context) types.HealthStatus {
		select {
		case <-time.After(2 * time.Second): // Longer than timeout
			return types.NewHealthyStatus("check completed")
		case <-ctx.Done():
			// Context was cancelled due to timeout
			return types.NewUnhealthyStatus("check timed out", map[string]any{
				"error": ctx.Err().Error(),
			})
		}
	})

	err := server.Start()
	require.NoError(t, err)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Make request that should complete within timeout window
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	start := time.Now()
	resp, err := http.Get(url)
	duration := time.Since(start)

	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify request completed quickly (within reasonable time after timeout)
	assert.Less(t, duration, 2*time.Second,
		"Request should complete within timeout period, took %v", duration)

	// Status should be unhealthy due to timeout
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"Should return 503 when check times out")

	t.Logf("Successfully verified check timeout handling, duration: %v", duration)
}

// Helper functions

// getAvailablePort finds an available port for testing.
func getAvailablePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to find available port")
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}
