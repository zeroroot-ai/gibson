// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
)

// registerFTCommands registers FT.CREATE, FT.INFO, and FT.DROPINDEX handlers
// on the given miniredis server. The stub is minimal: FT.CREATE succeeds on
// first call and returns "Index already exists" on subsequent calls; FT.INFO
// returns success for known indexes; FT.DROPINDEX removes the index.
//
// registerFTCommands is idempotent: registering the same command twice on the
// same server is a no-op (miniredis returns "already registered" which we
// silently ignore) so callers don't need to guard against duplicate calls when
// sharing a miniredis instance across subtests.
func registerFTCommands(t *testing.T, mr *miniredis.Miniredis) {
	t.Helper()
	type state struct {
		indexes map[string]bool
	}
	st := &state{indexes: make(map[string]bool)}
	srv := mr.Server()

	_ = srv.Register("FT.CREATE", func(c *server.Peer, cmd string, args []string) {
		if len(args) < 1 {
			c.WriteError("ERR wrong number of arguments for FT.CREATE")
			return
		}
		idxName := args[0]
		if st.indexes[idxName] {
			c.WriteError("Index already exists")
			return
		}
		st.indexes[idxName] = true
		c.WriteInline("OK")
	})

	_ = srv.Register("FT.INFO", func(c *server.Peer, cmd string, args []string) {
		if len(args) < 1 {
			c.WriteError("ERR wrong number of arguments for FT.INFO")
			return
		}
		idxName := args[0]
		if !st.indexes[idxName] {
			c.WriteError("no such index")
			return
		}
		// Return a minimal two-field array; provisioner only checks err.
		c.WriteLen(2)
		c.WriteBulk("index_name")
		c.WriteBulk(idxName)
	})

	_ = srv.Register("FT.DROPINDEX", func(c *server.Peer, cmd string, args []string) {
		if len(args) < 1 {
			c.WriteError("ERR wrong number of arguments for FT.DROPINDEX")
			return
		}
		idxName := args[0]
		if !st.indexes[idxName] {
			c.WriteError("no such index")
			return
		}
		delete(st.indexes, idxName)
		c.WriteInline("OK")
	})
}

// newTestVSSProvisioner starts a miniredis instance with FT.* stubs and
// returns a provisioner wired against it. Automatically closed via t.Cleanup.
func newTestVSSProvisioner(t *testing.T) *redisVSSProvisioner {
	t.Helper()
	mr := miniredis.RunT(t)
	registerFTCommands(t, mr)
	p, err := NewRedisVSSProvisioner(RedisVSSConfig{
		Addr:      mr.Addr(),
		VectorDim: 1536,
	})
	if err != nil {
		t.Fatalf("NewRedisVSSProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestRedisVSSProvisionCreatesIndex(t *testing.T) {
	t.Parallel()
	p := newTestVSSProvisioner(t)
	if err := p.Provision(context.Background(), "acme-corp"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
}

func TestRedisVSSIndexName(t *testing.T) {
	t.Parallel()
	// Index name must be "vector_idx:tenant_acme_corp".
	name, err := vssIndexName("acme-corp")
	if err != nil {
		t.Fatalf("vssIndexName: %v", err)
	}
	if name != "vector_idx:tenant_acme_corp" {
		t.Errorf("got %q, want vector_idx:tenant_acme_corp", name)
	}
}

func TestRedisVSSKeyPrefix(t *testing.T) {
	t.Parallel()
	// Key prefix must be "vec:tenant_acme_corp:".
	kp, err := vssKeyPrefix("acme-corp")
	if err != nil {
		t.Fatalf("vssKeyPrefix: %v", err)
	}
	if kp != "vec:tenant_acme_corp:" {
		t.Errorf("got %q, want vec:tenant_acme_corp:", kp)
	}
}

func TestRedisVSSProvisionIdempotent(t *testing.T) {
	t.Parallel()
	p := newTestVSSProvisioner(t)
	ctx := context.Background()

	// First call creates the index.
	if err := p.Provision(ctx, "acme-corp"); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	// Second call must succeed — "already exists" is treated as idempotent.
	if err := p.Provision(ctx, "acme-corp"); err != nil {
		t.Fatalf("second Provision (idempotent): %v", err)
	}
}

func TestRedisVSSDeprovision(t *testing.T) {
	t.Parallel()
	p := newTestVSSProvisioner(t)
	ctx := context.Background()

	if err := p.Provision(ctx, "acme-corp"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := p.Deprovision(ctx, "acme-corp"); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
}

func TestRedisVSSDeprovisionIdempotent(t *testing.T) {
	t.Parallel()
	p := newTestVSSProvisioner(t)

	// Deprovision on a never-provisioned tenant — "no such index" is success.
	if err := p.Deprovision(context.Background(), "missing-tenant"); err != nil {
		t.Fatalf("Deprovision of missing index should succeed, got: %v", err)
	}
}

func TestRedisVSSDefaultDim(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	registerFTCommands(t, mr)

	// VectorDim=0 must default to 1536.
	p, err := NewRedisVSSProvisioner(RedisVSSConfig{Addr: mr.Addr()})
	if err != nil {
		t.Fatalf("NewRedisVSSProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if p.cfg.VectorDim != 1536 {
		t.Errorf("default VectorDim: got %d, want 1536", p.cfg.VectorDim)
	}
}

func TestRedisVSSProvisionRequiresAddr(t *testing.T) {
	t.Parallel()
	_, err := NewRedisVSSProvisioner(RedisVSSConfig{})
	if err == nil {
		t.Error("expected error when Addr is empty, got nil")
	}
	if !strings.Contains(err.Error(), "Addr is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRedisVSSVaultWriteRepeatsOnIdempotentProvision pins the contract that
// every successful Provision records the index name, including the attempt that
// finds the index already there.
//
// This test replaces TestRedisVSSVaultWriteSkippedOnIdempotentProvision, which
// was named for the opposite behavior and asserted neither: it only checked that
// the map held a key, so it passed whether the write happened once, twice or on
// every reconcile. It could not fail.
func TestRedisVSSVaultWriteRepeatsOnIdempotentProvision(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	registerFTCommands(t, mr)

	rec := newRecordingVaultAdmin()
	p, err := NewRedisVSSProvisioner(RedisVSSConfig{
		Addr:        mr.Addr(),
		VaultClient: rec,
	})
	if err != nil {
		t.Fatalf("NewRedisVSSProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if err := p.Provision(ctx, "acme-corp"); err != nil {
			t.Fatalf("Provision attempt %d: %v", i, err)
		}
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if got := rec.vectorWrites["acme-corp"]; got != 2 {
		t.Fatalf("WriteInfraVector calls = %d, want 2 (the already-exists path must still record the name)", got)
	}
	if got := rec.vectorWritten["acme-corp"].IndexName; got != "vector_idx:tenant_acme_corp" {
		t.Fatalf("recorded index name = %q", got)
	}
}

// TestRedisVSSProvisionRecordsIndexAfterVaultWriteRetry is the reachable state
// that the old early return made permanent.
//
// Attempt 1 creates the index and fails the Vault write, so the saga retries.
// Attempt 2 finds the index already there. If the step returns early on that
// path, the index exists forever with no recorded name, and the daemon reports
// the tenant unprovisioned for every vector-backed read (gibson#468).
func TestRedisVSSProvisionRecordsIndexAfterVaultWriteRetry(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	registerFTCommands(t, mr)

	rec := newRecordingVaultAdmin()
	rec.vectorWriteErr = errors.New("vault unreachable")
	p, err := NewRedisVSSProvisioner(RedisVSSConfig{
		Addr:        mr.Addr(),
		VaultClient: rec,
	})
	if err != nil {
		t.Fatalf("NewRedisVSSProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()
	if err := p.Provision(ctx, "acme-corp"); err == nil {
		t.Fatal("attempt 1: expected the injected Vault write failure")
	}

	// The retry: the index is already there.
	if err := p.Provision(ctx, "acme-corp"); err != nil {
		t.Fatalf("attempt 2: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if got := rec.vectorWritten["acme-corp"].IndexName; got != "vector_idx:tenant_acme_corp" {
		t.Fatalf("index name after retry = %q, want it recorded", got)
	}
}

func TestRedisVSSClientPing(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	registerFTCommands(t, mr)

	p, err := NewRedisVSSProvisioner(RedisVSSConfig{Addr: mr.Addr()})
	if err != nil {
		t.Fatalf("NewRedisVSSProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if err := p.client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("client PING: %v", err)
	}
}
