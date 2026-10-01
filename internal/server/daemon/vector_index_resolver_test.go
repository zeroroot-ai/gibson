// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/sdk/auth"
)

type fakeSecretResolver struct {
	payload []byte
	err     error
	gotName string
	gotTen  string
}

func (f *fakeSecretResolver) Resolve(ctx context.Context, name string) ([]byte, error) {
	f.gotName = name
	if id, ok := auth.TenantFromContext(ctx); ok {
		f.gotTen = id.String()
	}
	return f.payload, f.err
}

func TestResolveVectorIndex(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")

	t.Run("nil reader is not provisioned", func(t *testing.T) {
		_, err := resolveVectorIndex(context.Background(), nil, tenant)
		var np *datapool.NotProvisionedError
		require.ErrorAs(t, err, &np)
		assert.Equal(t, "acme", np.Tenant)
	})

	t.Run("vault read failure names the path", func(t *testing.T) {
		_, err := resolveVectorIndex(context.Background(), &fakeSecretResolver{err: errors.New("denied")}, tenant)
		var np *datapool.NotProvisionedError
		require.ErrorAs(t, err, &np)
		assert.Contains(t, np.Reason, pdataplane.VaultPathInfraVector)
		assert.Contains(t, np.Reason, "denied")
	})

	t.Run("malformed payload is a fault", func(t *testing.T) {
		_, err := resolveVectorIndex(context.Background(), &fakeSecretResolver{payload: []byte("{not json")}, tenant)
		require.Error(t, err)
		var np *datapool.NotProvisionedError
		assert.NotErrorAs(t, err, &np)
	})

	t.Run("empty index name passes through", func(t *testing.T) {
		got, err := resolveVectorIndex(context.Background(), &fakeSecretResolver{payload: []byte(`{"index_name":""}`)}, tenant)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("happy path reads the infra/vector path as the tenant", func(t *testing.T) {
		f := &fakeSecretResolver{payload: []byte(`{"index_name":"vector_idx:tenant_acme"}`)}
		got, err := resolveVectorIndex(context.Background(), f, tenant)
		require.NoError(t, err)
		assert.Equal(t, "vector_idx:tenant_acme", got)
		assert.Equal(t, pdataplane.VaultPathInfraVector, f.gotName)
		assert.Equal(t, "acme", f.gotTen)
	})
}

// A nil *secrets.Service must reach resolveVectorIndex as a nil interface.
// Otherwise the nil check never fires and Resolve panics on a nil receiver.
func TestDaemonVectorIndexResolver_NilServiceIsNotProvisioned(t *testing.T) {
	d := &daemonImpl{}
	_, err := d.vectorIndexResolver().VectorIndex(context.Background(), auth.MustNewTenantID("acme"))
	var np *datapool.NotProvisionedError
	require.ErrorAs(t, err, &np)
}

// The XOR rule: both vector fields are set, or neither is. A config carrying an
// address and no resolver is refused by NewPool, and that half-configured state
// is how every vector-backed graph read answered "no vector collection
// provisioned" on a cluster whose index existed (gibson#468).
func TestWireVectorStore(t *testing.T) {
	resolver := datapool.VectorIndexResolverFunc(
		func(context.Context, auth.TenantID) (string, error) { return "idx", nil })

	t.Run("a redis address wires both halves", func(t *testing.T) {
		cfg := &datapool.Config{RedisAddr: "10.0.0.1:6379"}
		if !wireVectorStore(cfg, resolver) {
			t.Fatal("want wired=true when an address is present")
		}
		if cfg.VectorStoreAddr != "10.0.0.1:6379" {
			t.Errorf("VectorStoreAddr = %q, want the redis address", cfg.VectorStoreAddr)
		}
		if cfg.VectorIndexResolver == nil {
			t.Error("VectorIndexResolver must be set alongside the address")
		}
	})

	t.Run("no redis address wires neither half", func(t *testing.T) {
		cfg := &datapool.Config{}
		if wireVectorStore(cfg, resolver) {
			t.Fatal("want wired=false with no address")
		}
		if cfg.VectorStoreAddr != "" {
			t.Errorf("VectorStoreAddr = %q, want empty", cfg.VectorStoreAddr)
		}
		if cfg.VectorIndexResolver != nil {
			t.Error("a resolver with no address is the config NewPool refuses")
		}
	})

	// Defensive: the caller passes &poolCfg from a long startup function, and a
	// nil there must not panic the daemon on the way up.
	t.Run("a nil config is not wired and does not panic", func(t *testing.T) {
		if wireVectorStore(nil, resolver) {
			t.Fatal("want wired=false for a nil config")
		}
	})
}

// The typed-nil trap: a nil *secrets.Service assigned into an interface
// produces an interface that is NOT nil, so the obvious `reader != nil` guard
// passes and the resolver calls through it. secretReaderOf must return a nil
// INTERFACE, not an interface holding a nil pointer.
func TestSecretReaderOf_NilServiceYieldsNilInterface(t *testing.T) {
	got := secretReaderOf(nil)
	if got != nil {
		t.Fatalf("secretReaderOf(nil) = %#v, want a nil interface", got)
	}

	// The trap itself, so the test states what it defends against rather than
	// describing it. `trap` is what the inline version produced: an interface
	// HOLDING a nil pointer, which is not a nil interface. Comparing the two
	// interfaces asserts the distinction directly — and staticcheck flags
	// `trap == nil` as never true, which is the same fact proved at compile
	// time, so asserting that would be a tautology rather than a test.
	var trap secretResolver = (*secrets.Service)(nil)
	if got := secretReaderOf(nil); got == trap {
		t.Fatal("secretReaderOf(nil) returned an interface holding a nil pointer; " +
			"the resolver would call through it and panic on what reads as a nil check")
	}
}

// A non-nil service is passed through unchanged, or the resolver would report
// every tenant unprovisioned on a daemon whose broker stack is wired.
func TestSecretReaderOf_RealServicePassesThrough(t *testing.T) {
	svc := &secrets.Service{}
	got := secretReaderOf(svc)
	if got == nil {
		t.Fatal("secretReaderOf(non-nil) returned nil; the resolver would see no reader")
	}
	if got != secretResolver(svc) {
		t.Error("secretReaderOf must pass the service through, not wrap it")
	}
}
