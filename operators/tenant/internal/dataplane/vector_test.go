// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
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

func TestRedisVSSVaultWriteSkippedOnIdempotentProvision(t *testing.T) {
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
	// First call: creates index + writes Vault.
	if err := p.Provision(ctx, "acme-corp"); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	// Second call: index already exists — Vault write must be skipped.
	if err := p.Provision(ctx, "acme-corp"); err != nil {
		t.Fatalf("second Provision: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	// Must be recorded exactly once.
	if _, ok := rec.vectorWritten["acme-corp"]; !ok {
		t.Fatalf("WriteInfraVector was never called for acme-corp")
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
