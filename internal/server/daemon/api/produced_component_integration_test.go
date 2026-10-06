// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

package api

// The record of produced components against a real Postgres, with the shipped
// migration 042 (gibson#33). It proves the quota holds under concurrent
// enrollments of one tenant.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/zeroroot-ai/gibson/tests/testhelpers"
)

func producedStorePostgres(t *testing.T) *sql.DB {
	t.Helper()
	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{User: "testuser", Password: "testpass", Database: "testdb"})
	db, err := sql.Open("postgres", pg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	deadline := time.Now().Add(30 * time.Second)
	for db.PingContext(context.Background()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("Postgres not ready")
		}
		time.Sleep(200 * time.Millisecond)
	}
	up, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "pkg", "platform", "migrations", "postgres", "platform", "042_produced_component.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(up)); err != nil {
		t.Fatalf("apply 041: %v", err)
	}
	return db
}

func TestSQLProducedComponentStore_QuotaNameAndRelease(t *testing.T) {
	db := producedStorePostgres(t)
	st := sqlProducedComponentStore{db: db}
	ctx := context.Background()
	c := ProducedComponent{Kind: "tool", Name: "a-tool", Version: "1", Image: "img@sha256:x"}

	if err := st.Reserve(ctx, "acme", "owner", "agent_principal:p", c, 2); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if err := st.Reserve(ctx, "acme", "owner", "agent_principal:p", c, 2); !errors.Is(err, errProducedExists) {
		t.Fatalf("same name: want errProducedExists, got %v", err)
	}
	c2 := c
	c2.Name = "b-tool"
	if err := st.Reserve(ctx, "acme", "owner", "agent_principal:p", c2, 2); err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	c3 := c
	c3.Name = "c-tool"
	if err := st.Reserve(ctx, "acme", "owner", "agent_principal:p", c3, 2); !errors.Is(err, errProducedQuota) {
		t.Fatalf("over the quota: want errProducedQuota, got %v", err)
	}
	// Another tenant has its own quota.
	if err := st.Reserve(ctx, "beta", "owner", "agent_principal:q", c3, 2); err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	// A bound row stays on release. An unbound row leaves.
	if err := st.Bind(ctx, "acme", "tool", "a-tool", "tool_principal:1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Release(ctx, "acme", "tool", "a-tool"); err != nil {
		t.Fatal(err)
	}
	if err := st.Release(ctx, "acme", "tool", "b-tool"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM produced_component WHERE tenant_id = 'acme'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows of acme = %d, want 1 (the bound one)", n)
	}
}

func TestSQLProducedComponentStore_ConcurrentEnrollmentsKeepTheQuota(t *testing.T) {
	db := producedStorePostgres(t)
	st := sqlProducedComponentStore{db: db}
	ctx := context.Background()
	const limit = 3
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := ProducedComponent{Kind: "tool", Name: fmt.Sprintf("tool-%02d", i), Version: "1", Image: "img@sha256:x"}
			if err := st.Reserve(ctx, "acme", "owner", "agent_principal:p", c, limit); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != limit {
		t.Fatalf("%d concurrent reservations passed, want exactly %d", ok, limit)
	}
}
