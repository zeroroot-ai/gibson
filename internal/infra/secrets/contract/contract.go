// Package contract provides RunContract, a shared test suite that every
// SecretsBroker implementation must pass. Test authors add a _test.go in
// each provider package that calls RunContract with a real or emulated
// backend to prove the provider conforms to the interface contract.
//
// RunContract respects ProviderCapabilities: operations not declared by the
// provider are skipped rather than failing. Adding a new provider requires
// only: a new package implementing SecretsBroker, a _test.go calling
// RunContract, a registration in the daemon's broker registry, and an entry
// in the provider enum. No changes to this package are required.
//
// Spec: secrets-broker Requirement 5.
package contract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// testTenant is the tenant used throughout the contract suite. It must
// satisfy auth.TenantID validation rules (lowercase, alphanumeric + hyphens).
var testTenant = auth.MustNewTenantID("contract-test")

// RunContract exercises every method of b against the contract defined in
// secrets-broker Requirement 5. It skips assertions for operations that are
// not declared in b.Capabilities() so that read-only or limited providers
// can still pass the suite for the subset they implement.
//
// t.Helper is called so failures point at the line in the caller's _test.go,
// not inside RunContract.
func RunContract(t *testing.T, b secrets.Broker) {
	t.Helper()
	caps := b.Capabilities()

	t.Run("health", func(t *testing.T) {
		runHealth(t, b)
	})
	t.Run("get_nonexistent_returns_not_found", func(t *testing.T) {
		runGetNotFound(t, b)
	})
	if caps.CanPut {
		t.Run("put_then_get_roundtrip", func(t *testing.T) {
			runPutGetRoundtrip(t, b, caps)
		})
		t.Run("put_overwrite", func(t *testing.T) {
			runPutOverwrite(t, b)
		})
		t.Run("binary_content_with_null_bytes", func(t *testing.T) {
			runBinaryContent(t, b)
		})
		if caps.MaxValueBytes > 0 {
			t.Run("max_value_size", func(t *testing.T) {
				runMaxValueSize(t, b, caps)
			})
		}
		t.Run("concurrent_put_get_different_names", func(t *testing.T) {
			runConcurrent(t, b)
		})
	}
	if caps.CanPut && caps.CanDelete {
		t.Run("delete_then_get_returns_not_found", func(t *testing.T) {
			runDeleteThenGet(t, b)
		})
	}
	if caps.CanList {
		t.Run("list_without_filter", func(t *testing.T) {
			runListNoFilter(t, b, caps)
		})
		t.Run("list_with_prefix_filter", func(t *testing.T) {
			runListWithPrefix(t, b, caps)
		})
	}
	t.Run("error_mapping", func(t *testing.T) {
		runErrorMapping(t, b, caps)
	})
}

// runHealth calls Health and expects no error.
func runHealth(t *testing.T, b secrets.Broker) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.Health(ctx); err != nil {
		t.Fatalf("Health() returned unexpected error: %v", err)
	}
}

// runGetNotFound asserts that Get of a name that was never Put returns
// ErrNotFound.
func runGetNotFound(t *testing.T, b secrets.Broker) {
	t.Helper()
	ctx := context.Background()
	name := uniqueName("nonexistent")
	_, err := b.Get(ctx, testTenant, name)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get(%q): want ErrNotFound, got %v", name, err)
	}
}

// runPutGetRoundtrip puts a value and immediately gets it back, asserting
// byte-for-byte equality.
func runPutGetRoundtrip(t *testing.T, b secrets.Broker, caps secrets.Capabilities) {
	t.Helper()
	ctx := context.Background()
	name := uniqueName("roundtrip")
	value := []byte("hello from contract suite")

	if err := b.Put(ctx, testTenant, name, value); err != nil {
		t.Fatalf("Put(%q): unexpected error: %v", name, err)
	}
	cleanupDelete(t, b, name, caps)

	got, err := b.Get(ctx, testTenant, name)
	if err != nil {
		t.Fatalf("Get(%q): unexpected error: %v", name, err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("Get(%q): value mismatch\n  want %q\n  got  %q", name, value, got)
	}
}

// runBinaryContent asserts that binary values including null bytes survive a
// Put/Get round-trip unchanged.
func runBinaryContent(t *testing.T, b secrets.Broker) {
	t.Helper()
	ctx := context.Background()
	name := uniqueName("binary")
	// Deliberately include null bytes, high bytes, and a mix of ASCII.
	value := []byte{0x00, 0xFF, 0x01, 0xFE, 0x00, 'h', 'e', 'l', 'l', 'o', 0x00}

	if err := b.Put(ctx, testTenant, name, value); err != nil {
		t.Fatalf("Put(%q) binary: unexpected error: %v", name, err)
	}
	got, err := b.Get(ctx, testTenant, name)
	if err != nil {
		t.Fatalf("Get(%q) binary: unexpected error: %v", name, err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("Get(%q) binary: value mismatch\n  want %v\n  got  %v", name, value, got)
	}
}

// runPutOverwrite puts a value, overwrites it, and asserts the second value
// is returned by a subsequent Get.
func runPutOverwrite(t *testing.T, b secrets.Broker) {
	t.Helper()
	ctx := context.Background()
	name := uniqueName("overwrite")
	first := []byte("first value")
	second := []byte("second value — overwrite")

	if err := b.Put(ctx, testTenant, name, first); err != nil {
		t.Fatalf("Put(%q) first: %v", name, err)
	}
	if err := b.Put(ctx, testTenant, name, second); err != nil {
		t.Fatalf("Put(%q) overwrite: %v", name, err)
	}
	got, err := b.Get(ctx, testTenant, name)
	if err != nil {
		t.Fatalf("Get(%q) after overwrite: %v", name, err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("Get(%q) after overwrite: want %q, got %q", name, second, got)
	}
}

// runDeleteThenGet puts a value, deletes it, and asserts that a subsequent
// Get returns ErrNotFound.
func runDeleteThenGet(t *testing.T, b secrets.Broker) {
	t.Helper()
	ctx := context.Background()
	name := uniqueName("delete")

	if err := b.Put(ctx, testTenant, name, []byte("to be deleted")); err != nil {
		t.Fatalf("Put(%q): %v", name, err)
	}
	if err := b.Delete(ctx, testTenant, name); err != nil {
		t.Fatalf("Delete(%q): %v", name, err)
	}
	_, err := b.Get(ctx, testTenant, name)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get(%q) after Delete: want ErrNotFound, got %v", name, err)
	}
}

// runListNoFilter puts several secrets and asserts they appear in a
// filter-free List.
func runListNoFilter(t *testing.T, b secrets.Broker, caps secrets.Capabilities) {
	t.Helper()
	ctx := context.Background()
	prefix := uniqueName("listall")
	names := []string{
		prefix + "-alpha",
		prefix + "-beta",
		prefix + "-gamma",
	}
	for _, n := range names {
		if err := b.Put(ctx, testTenant, n, []byte(n)); err != nil {
			t.Fatalf("Put(%q) for list setup: %v", n, err)
		}
	}
	cleanupDeleteAll(t, b, names, caps)

	listed, err := b.List(ctx, testTenant, secrets.Filter{})
	if err != nil {
		t.Fatalf("List(empty filter): %v", err)
	}
	listedSet := toSet(listed)
	for _, n := range names {
		if !listedSet[n] {
			t.Errorf("List: missing expected name %q in result %v", n, listed)
		}
	}
}

// runListWithPrefix puts secrets under two different prefixes, then lists
// with a prefix filter and asserts only the matching names are returned.
func runListWithPrefix(t *testing.T, b secrets.Broker, caps secrets.Capabilities) {
	t.Helper()
	ctx := context.Background()
	prefixA := uniqueName("pfx-a")
	prefixB := uniqueName("pfx-b")
	namesA := []string{prefixA + "-one", prefixA + "-two"}
	namesB := []string{prefixB + "-one"}

	for _, n := range append(namesA, namesB...) {
		if err := b.Put(ctx, testTenant, n, []byte(n)); err != nil {
			t.Fatalf("Put(%q) for prefix-list setup: %v", n, err)
		}
	}
	cleanupDeleteAll(t, b, append(namesA, namesB...), caps)

	listed, err := b.List(ctx, testTenant, secrets.Filter{Prefix: prefixA})
	if err != nil {
		t.Fatalf("List(prefix=%q): %v", prefixA, err)
	}
	listedSet := toSet(listed)
	for _, n := range namesA {
		if !listedSet[n] {
			t.Errorf("List(prefix=%q): missing %q in result %v", prefixA, n, listed)
		}
	}
	for _, n := range namesB {
		if listedSet[n] {
			t.Errorf("List(prefix=%q): unexpected name %q from other prefix in result %v", prefixA, n, listed)
		}
	}
}

// runMaxValueSize verifies that Put rejects a value exactly one byte larger
// than MaxValueBytes with ErrTooLarge, and accepts a value exactly at the
// limit.
func runMaxValueSize(t *testing.T, b secrets.Broker, caps secrets.Capabilities) {
	t.Helper()
	max := caps.MaxValueBytes
	if max <= 0 {
		t.Skip("MaxValueBytes is 0; skipping max-size test")
	}
	// Some providers with very large limits (> 1 MiB) would make this test
	// allocation-heavy. Cap the test at 1 MiB to keep it practical; if
	// MaxValueBytes is larger than 1 MiB we only test the ErrTooLarge path
	// at MaxValueBytes+1.
	const testCap = 1 << 20 // 1 MiB
	if max <= testCap {
		ctx := context.Background()
		atLimit := make([]byte, max)
		for i := range atLimit {
			atLimit[i] = 0xAB
		}
		name := uniqueName("maxsize-at")
		if err := b.Put(ctx, testTenant, name, atLimit); err != nil {
			t.Errorf("Put(%q) at MaxValueBytes (%d): unexpected error: %v", name, max, err)
		}
	}

	// One byte over the limit must return ErrTooLarge.
	ctx := context.Background()
	overLimit := make([]byte, max+1)
	name := uniqueName("maxsize-over")
	err := b.Put(ctx, testTenant, name, overLimit)
	if !errors.Is(err, secrets.ErrTooLarge) {
		t.Errorf("Put(%q) at MaxValueBytes+1 (%d): want ErrTooLarge, got %v", name, max+1, err)
	}
}

// runConcurrent launches multiple goroutines each putting and getting
// distinct named secrets concurrently. It asserts that each goroutine's
// Get returns the value it Put (no cross-write corruption).
func runConcurrent(t *testing.T, b secrets.Broker) {
	t.Helper()
	const workers = 10
	var wg sync.WaitGroup
	errs := make([]error, workers)

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			name := uniqueName(fmt.Sprintf("concurrent-%d", i))
			value := []byte(fmt.Sprintf("value-for-worker-%d", i))

			if err := b.Put(ctx, testTenant, name, value); err != nil {
				errs[i] = fmt.Errorf("Put(%q): %w", name, err)
				return
			}
			got, err := b.Get(ctx, testTenant, name)
			if err != nil {
				errs[i] = fmt.Errorf("Get(%q): %w", name, err)
				return
			}
			if !bytes.Equal(got, value) {
				errs[i] = fmt.Errorf("Get(%q): want %q, got %q", name, value, got)
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", i, err)
		}
	}
}

// runErrorMapping asserts that error sentinels are correctly returned for
// known bad inputs. Only operations declared by Capabilities are exercised.
func runErrorMapping(t *testing.T, b secrets.Broker, caps secrets.Capabilities) {
	t.Helper()
	ctx := context.Background()

	// ErrNotFound must be returned by Get when the secret does not exist.
	{
		name := uniqueName("errmapping-notfound")
		_, err := b.Get(ctx, testTenant, name)
		if !errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("Get of nonexistent: want ErrNotFound, got %v", err)
		}
	}

	// ErrUnsupported must be returned when the operation is not declared.
	if !caps.CanPut {
		name := uniqueName("errmapping-unsupported-put")
		err := b.Put(ctx, testTenant, name, []byte("x"))
		if !errors.Is(err, secrets.ErrUnsupported) {
			t.Errorf("Put on CanPut=false broker: want ErrUnsupported, got %v", err)
		}
	}
	if !caps.CanDelete {
		name := uniqueName("errmapping-unsupported-delete")
		err := b.Delete(ctx, testTenant, name)
		if !errors.Is(err, secrets.ErrUnsupported) {
			t.Errorf("Delete on CanDelete=false broker: want ErrUnsupported, got %v", err)
		}
	}
	if !caps.CanList {
		_, err := b.List(ctx, testTenant, secrets.Filter{})
		if !errors.Is(err, secrets.ErrUnsupported) {
			t.Errorf("List on CanList=false broker: want ErrUnsupported, got %v", err)
		}
	}
}

// cleanupDelete registers a cleanup function that deletes name after the test
// completes. It only registers the cleanup when the provider supports Delete.
func cleanupDelete(t *testing.T, b secrets.Broker, name string, caps secrets.Capabilities) {
	t.Helper()
	if !caps.CanDelete {
		return
	}
	t.Cleanup(func() {
		// Best-effort; ignore not-found.
		_ = b.Delete(context.Background(), testTenant, name)
	})
}

// cleanupDeleteAll registers cleanup deletions for all listed names.
func cleanupDeleteAll(t *testing.T, b secrets.Broker, names []string, caps secrets.Capabilities) {
	t.Helper()
	if !caps.CanDelete {
		return
	}
	t.Cleanup(func() {
		for _, n := range names {
			_ = b.Delete(context.Background(), testTenant, n)
		}
	})
}

// toSet converts a string slice to a map for O(1) membership tests.
func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// uniqueName generates a name that is unlikely to collide across parallel
// test runs by appending a nanosecond timestamp. The base must be a valid
// secret name component (lowercase, no special characters beyond hyphens).
func uniqueName(base string) string {
	// Replace any underscores in base with hyphens to keep names
	// compatible with providers that disallow underscores.
	safe := strings.ReplaceAll(base, "_", "-")
	return fmt.Sprintf("contract-%s-%d", safe, time.Now().UnixNano())
}
