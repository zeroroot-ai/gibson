// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakePendingQueue is an in-memory pending_tenant_provisioning table behind a
// database/sql driver. It answers the statements of the queue: the table
// guard, the insert, the owner read and the operator list. Any other statement
// fails the call, so a test sees a query that it does not expect.
type fakePendingQueue struct {
	mu   sync.Mutex
	rows []fakeQueueRow
}

// fakeQueueRow is one queued tenant.
type fakeQueueRow struct {
	tenantID, ownerUserID, ownerEmail, workspaceName, tier, status, auditRecordID string
}

// row returns the queued row of tenantID.
func (q *fakePendingQueue) row(tenantID string) (fakeQueueRow, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, r := range q.rows {
		if r.tenantID == tenantID {
			return r, true
		}
	}
	return fakeQueueRow{}, false
}

var (
	fakeQueues  sync.Map
	fakeQueueID atomic.Int64
)

func init() { sql.Register("fakependingqueue", fakeQueueDriver{}) }

// withPendingQueue gives srv a platform database that holds an empty queue.
func withPendingQueue(t *testing.T, srv *DaemonServer) *fakePendingQueue {
	t.Helper()
	q := &fakePendingQueue{}
	name := fmt.Sprintf("queue-%d", fakeQueueID.Add(1))
	fakeQueues.Store(name, q)
	db, err := sql.Open("fakependingqueue", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(); fakeQueues.Delete(name) })
	srv.platformDB = db
	return q
}

type fakeQueueDriver struct{}

func (fakeQueueDriver) Open(name string) (driver.Conn, error) {
	q, ok := fakeQueues.Load(name)
	if !ok {
		return nil, fmt.Errorf("no fake queue %q", name)
	}
	return &fakeQueueConn{q: q.(*fakePendingQueue)}, nil
}

type fakeQueueConn struct{ q *fakePendingQueue }

func (c *fakeQueueConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("fake queue: Prepare is not supported")
}
func (c *fakeQueueConn) Close() error { return nil }
func (c *fakeQueueConn) Begin() (driver.Tx, error) {
	return nil, errors.New("fake queue: transactions are not supported")
}

func argString(args []driver.NamedValue, i int) string {
	if i >= len(args) {
		return ""
	}
	if s, ok := args[i].Value.(string); ok {
		return s
	}
	return ""
}

func (c *fakeQueueConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	switch {
	case strings.Contains(query, "CREATE TABLE IF NOT EXISTS pending_tenant_provisioning"):
		return driver.RowsAffected(0), nil
	case strings.Contains(query, "INSERT INTO pending_tenant_provisioning"):
		id := argString(args, 0)
		c.q.mu.Lock()
		defer c.q.mu.Unlock()
		for _, r := range c.q.rows {
			if r.tenantID == id {
				return driver.RowsAffected(0), nil
			}
		}
		c.q.rows = append(c.q.rows, fakeQueueRow{
			tenantID: id, ownerUserID: argString(args, 1), ownerEmail: argString(args, 2),
			workspaceName: argString(args, 3), tier: argString(args, 4), status: argString(args, 5),
			auditRecordID: argString(args, 10),
		})
		return driver.RowsAffected(1), nil
	}
	return nil, fmt.Errorf("fake queue: unexpected statement %q", query)
}

func (c *fakeQueueConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.q.mu.Lock()
	defer c.q.mu.Unlock()
	switch {
	case strings.Contains(query, "SELECT owner_user_id FROM pending_tenant_provisioning"):
		out := &fakeQueueRows{cols: []string{"owner_user_id"}}
		for _, r := range c.q.rows {
			if r.tenantID == argString(args, 0) {
				out.vals = append(out.vals, []driver.Value{r.ownerUserID})
			}
		}
		return out, nil
	case strings.Contains(query, "FROM pending_tenant_provisioning") && strings.Contains(query, "status = 'pending'"):
		out := &fakeQueueRows{cols: []string{"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier", "audit_record_id"}}
		for _, r := range c.q.rows {
			if r.status == "pending" {
				out.vals = append(out.vals, []driver.Value{r.tenantID, r.ownerUserID, r.ownerEmail, r.workspaceName, r.tier, r.auditRecordID})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("fake queue: unexpected query %q", query)
}

type fakeQueueRows struct {
	cols []string
	vals [][]driver.Value
	i    int
}

func (r *fakeQueueRows) Columns() []string { return r.cols }
func (r *fakeQueueRows) Close() error      { return nil }
func (r *fakeQueueRows) Next(dest []driver.Value) error {
	if r.i >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.i])
	r.i++
	return nil
}
