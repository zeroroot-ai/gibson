package builtin

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

func TestRateLimiter_BasicRateLimiting(t *testing.T) {
	// Allow 5 requests per second
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Second,
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://example.com/api",
		},
	}

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
		result, err := limiter.CheckInput(context.Background(), input)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("request %d: expected allow, got %s", i, result.Action)
		}
	}

	// 6th request should be blocked
	result, err := limiter.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for 6th request, got %s", result.Action)
	}

	// Check that retry-after metadata is present
	if result.Metadata == nil {
		t.Error("expected metadata in blocked result")
	} else {
		if _, ok := result.Metadata["retry_after_seconds"]; !ok {
			t.Error("expected retry_after_seconds in metadata")
		}
	}
}

func TestRateLimiter_BurstCapacity(t *testing.T) {
	// Allow 10 requests per second with burst of 20
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 10,
		Window:      time.Second,
		BurstSize:   20,
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://example.com/api",
		},
	}

	// First 20 requests should succeed (burst capacity)
	for i := 0; i < 20; i++ {
		result, err := limiter.CheckInput(context.Background(), input)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("request %d: expected allow, got %s (burst should allow 20)", i, result.Action)
		}
	}

	// 21st request should be blocked
	result, err := limiter.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for 21st request, got %s", result.Action)
	}
}

func TestRateLimiter_PerTargetIsolation(t *testing.T) {
	// Per-target rate limiting: 5 requests per second per domain
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Second,
		PerTarget:   true,
	})

	input1 := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://example.com/api",
		},
	}

	input2 := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://other.com/api",
		},
	}

	// Make 5 requests to example.com
	for i := 0; i < 5; i++ {
		result, err := limiter.CheckInput(context.Background(), input1)
		if err != nil {
			t.Fatalf("example.com request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("example.com request %d: expected allow, got %s", i, result.Action)
		}
	}

	// 6th request to example.com should be blocked
	result, err := limiter.CheckInput(context.Background(), input1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for 6th request to example.com, got %s", result.Action)
	}

	// But requests to other.com should still be allowed (separate limit)
	for i := 0; i < 5; i++ {
		result, err := limiter.CheckInput(context.Background(), input2)
		if err != nil {
			t.Fatalf("other.com request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("other.com request %d: expected allow (separate limit), got %s", i, result.Action)
		}
	}
}

func TestRateLimiter_GlobalLimit(t *testing.T) {
	// Global rate limiting: 5 requests per second across all domains
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Second,
		PerTarget:   false,
	})

	input1 := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://example.com/api",
		},
	}

	input2 := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://other.com/api",
		},
	}

	// Make 3 requests to example.com
	for i := 0; i < 3; i++ {
		result, err := limiter.CheckInput(context.Background(), input1)
		if err != nil {
			t.Fatalf("example.com request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("example.com request %d: expected allow, got %s", i, result.Action)
		}
	}

	// Make 2 requests to other.com (total 5)
	for i := 0; i < 2; i++ {
		result, err := limiter.CheckInput(context.Background(), input2)
		if err != nil {
			t.Fatalf("other.com request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("other.com request %d: expected allow, got %s", i, result.Action)
		}
	}

	// Next request to either domain should be blocked (global limit reached)
	result, err := limiter.CheckInput(context.Background(), input1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for 6th total request (global limit), got %s", result.Action)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	// Test thread safety with concurrent access
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 50,
		Window:      time.Second,
		PerTarget:   true,
	})

	var wg sync.WaitGroup
	numGoroutines := 10
	requestsPerGoroutine := 10

	allowCount := make([]int, numGoroutines)
	blockCount := make([]int, numGoroutines)

	// Launch multiple goroutines making requests to different domains
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: "https://example.com/api",
				},
			}

			for j := 0; j < requestsPerGoroutine; j++ {
				result, err := limiter.CheckInput(context.Background(), input)
				if err != nil {
					t.Errorf("goroutine %d request %d: unexpected error: %v", id, j, err)
					return
				}

				if result.Action == guardrail.GuardrailActionAllow {
					allowCount[id]++
				} else {
					blockCount[id]++
				}
			}
		}(i)
	}

	wg.Wait()

	// Count total allows and blocks
	totalAllows := 0
	totalBlocks := 0
	for i := 0; i < numGoroutines; i++ {
		totalAllows += allowCount[i]
		totalBlocks += blockCount[i]
	}

	// We should have some allows and some blocks
	if totalAllows == 0 {
		t.Error("expected some requests to be allowed")
	}

	if totalBlocks == 0 {
		t.Error("expected some requests to be blocked")
	}

	// Total should match
	if totalAllows+totalBlocks != numGoroutines*requestsPerGoroutine {
		t.Errorf("expected %d total requests, got %d", numGoroutines*requestsPerGoroutine, totalAllows+totalBlocks)
	}
}

func TestRateLimiter_RetryAfterMetadata(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 1,
		Window:      time.Second,
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://example.com/api",
		},
	}

	// First request allowed
	result, err := limiter.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionAllow {
		t.Errorf("expected allow, got %s", result.Action)
	}

	// Second request blocked
	result, err = limiter.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	// Check metadata
	if result.Metadata == nil {
		t.Fatal("expected metadata in blocked result")
	}

	retryAfterSeconds, ok := result.Metadata["retry_after_seconds"]
	if !ok {
		t.Error("expected retry_after_seconds in metadata")
	}

	retryAfterStr, ok := result.Metadata["retry_after"]
	if !ok {
		t.Error("expected retry_after in metadata")
	}

	// Verify types
	if _, ok := retryAfterSeconds.(float64); !ok {
		t.Errorf("expected retry_after_seconds to be float64, got %T", retryAfterSeconds)
	}

	if _, ok := retryAfterStr.(string); !ok {
		t.Errorf("expected retry_after to be string, got %T", retryAfterStr)
	}
}

func TestRateLimiter_CheckOutput(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 1,
		Window:      time.Second,
	})

	output := guardrail.GuardrailOutput{
		Content: "some response",
	}

	result, err := limiter.CheckOutput(context.Background(), output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Output should always be allowed for rate limiter
	if result.Action != guardrail.GuardrailActionAllow {
		t.Errorf("expected allow for output, got %s", result.Action)
	}
}

func TestRateLimiter_DefaultBurstSize(t *testing.T) {
	// When BurstSize is 0, it should default to MaxRequests
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 10,
		Window:      time.Second,
		BurstSize:   0, // Should default to MaxRequests
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "https://example.com/api",
		},
	}

	// Should allow MaxRequests (10) initially
	for i := 0; i < 10; i++ {
		result, err := limiter.CheckInput(context.Background(), input)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("request %d: expected allow (burst should default to MaxRequests), got %s", i, result.Action)
		}
	}

	// 11th request should be blocked
	result, err := limiter.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for 11th request, got %s", result.Action)
	}
}

func TestRateLimiter_Name(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 10,
		Window:      time.Second,
	})

	if limiter.Name() != "rate-limiter" {
		t.Errorf("expected name 'rate-limiter', got %s", limiter.Name())
	}
}

func TestRateLimiter_Type(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 10,
		Window:      time.Second,
	})

	if limiter.Type() != guardrail.GuardrailTypeRate {
		t.Errorf("expected type %s, got %s", guardrail.GuardrailTypeRate, limiter.Type())
	}
}

func TestRateLimiter_MissingURL(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Second,
		PerTarget:   true,
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "",
		},
	}

	// Should use "default" domain and work normally
	for i := 0; i < 5; i++ {
		result, err := limiter.CheckInput(context.Background(), input)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}

		if result.Action != guardrail.GuardrailActionAllow {
			t.Errorf("request %d: expected allow, got %s", i, result.Action)
		}
	}

	// 6th request should be blocked
	result, err := limiter.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for 6th request, got %s", result.Action)
	}
}

func TestRateLimiter_PerTargetMultipleDomains(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Second,
		PerTarget:   true,
	})

	domains := []string{
		"https://domain1.com/api",
		"https://domain2.com/api",
		"https://domain3.com/api",
	}

	// Each domain should have its own limit
	for _, domain := range domains {
		input := guardrail.GuardrailInput{
			TargetInfo: &harness.TargetInfo{
				URL: domain,
			},
		}

		// Make 5 requests (should all succeed)
		for i := 0; i < 5; i++ {
			result, err := limiter.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("%s request %d: unexpected error: %v", domain, i, err)
			}

			if result.Action != guardrail.GuardrailActionAllow {
				t.Errorf("%s request %d: expected allow, got %s", domain, i, result.Action)
			}
		}

		// 6th request should be blocked
		result, err := limiter.CheckInput(context.Background(), input)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", domain, err)
		}

		if result.Action != guardrail.GuardrailActionBlock {
			t.Errorf("%s: expected block for 6th request, got %s", domain, result.Action)
		}
	}
}
