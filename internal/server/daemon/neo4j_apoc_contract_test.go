// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// fakeNeo4j answers the two queries the probe runs from canned rows, and
// records what it was asked.
type fakeNeo4j struct {
	procedures []string
	allowlist  string
	listErr    error
	asked      []string
}

func (f *fakeNeo4j) run(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
	f.asked = append(f.asked, cypher)
	switch {
	case strings.HasPrefix(cypher, "SHOW PROCEDURES"):
		out := make([]map[string]any, 0, len(f.procedures))
		for _, p := range f.procedures {
			out = append(out, map[string]any{"name": p})
		}
		return out, nil
	case strings.HasPrefix(cypher, "CALL dbms.listConfig"):
		if f.listErr != nil {
			return nil, f.listErr
		}
		return []map[string]any{{"value": f.allowlist}}, nil
	}
	return nil, errors.New("unexpected query " + cypher)
}

func TestVerifyAPOCContract(t *testing.T) {
	ctx := context.Background()
	contract := dataplane.Neo4jProcedureAllowlist // "apoc.merge.node,apoc.merge.relationship"

	t.Run("a Neo4j provisioned to the contract passes", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node", "apoc.merge.relationship"}, allowlist: contract}
		if err := verifyAPOCContract(ctx, f.run); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("allowlist order does not matter", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.relationship", "apoc.merge.node"}, allowlist: "apoc.merge.relationship, apoc.merge.node"}
		if err := verifyAPOCContract(ctx, f.run); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("a missing procedure names the jar path", func(t *testing.T) {
		// The chart's init container copied nothing: the jar glob or the
		// plugins dir drifted from the contract.
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node"}, allowlist: contract}
		err := verifyAPOCContract(ctx, f.run)
		if err == nil || !strings.Contains(err.Error(), "apoc.merge.relationship") || !strings.Contains(err.Error(), dataplane.APOCCoreJarGlob) {
			t.Fatalf("want the missing procedure and the jar glob, got %v", err)
		}
		if len(f.asked) != 1 {
			t.Fatalf("a missing procedure must be reported before the allowlist is read, asked %v", f.asked)
		}
	})
	t.Run("a drifted allowlist is named with both values", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node", "apoc.merge.relationship"}, allowlist: "apoc.merge.node,apoc.merge.relationship,apoc.load.json"}
		err := verifyAPOCContract(ctx, f.run)
		if err == nil || !strings.Contains(err.Error(), "apoc.load.json") || !strings.Contains(err.Error(), contract) {
			t.Fatalf("want both allowlists in the error, got %v", err)
		}
		if errors.Is(err, errAllowlistUnreadable) {
			t.Fatal("a readable, wrong allowlist is a mismatch, not unreadable")
		}
	})
	t.Run("an unreadable allowlist is reported as unreadable, not wrong", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node", "apoc.merge.relationship"}, listErr: errors.New("Neo.ClientError.Security.Forbidden")}
		err := verifyAPOCContract(ctx, f.run)
		if !errors.Is(err, errAllowlistUnreadable) {
			t.Fatalf("want errAllowlistUnreadable, got %v", err)
		}
	})
	t.Run("a query failure is reported", func(t *testing.T) {
		boom := func(context.Context, string, map[string]any) ([]map[string]any, error) {
			return nil, errors.New("down")
		}
		if err := verifyAPOCContract(ctx, boom); err == nil {
			t.Fatal("want an error")
		}
	})
}

// contractCheckWith returns a check whose pool hands out a conn and whose
// queries are answered by f.
func contractCheckWith(f *fakeNeo4j) *apocContractCheck {
	c := newAPOCContractCheck("tenant-a", func() datapool.Pool { return &mockPool{conn: minimalConn()} }, slog.New(slog.DiscardHandler))
	c.rows = func(neo4j.SessionWithContext) cypherRows { return f.run }
	return c
}

// TestAPOCContractCheck_Unverifiable: every state the daemon cannot verify
// stays Healthy and names the reason.
func TestAPOCContractCheck_Unverifiable(t *testing.T) {
	ctx := context.Background()

	t.Run("no install tenant stays healthy and says so", func(t *testing.T) {
		c := newAPOCContractCheck("", func() datapool.Pool { return nil }, slog.New(slog.DiscardHandler))
		st := c.status(ctx)
		if !st.IsHealthy() || !strings.Contains(st.Message, "GIBSON_PLATFORM_TENANT") {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("a malformed install tenant stays healthy and says so", func(t *testing.T) {
		c := newAPOCContractCheck(strings.Repeat("x", 300), func() datapool.Pool { return nil }, slog.New(slog.DiscardHandler))
		if st := c.status(ctx); !st.IsHealthy() || !strings.Contains(st.Message, "not a tenant id") {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("pool not up stays healthy", func(t *testing.T) {
		c := newAPOCContractCheck("tenant-a", func() datapool.Pool { return nil }, slog.New(slog.DiscardHandler))
		if st := c.status(ctx); !st.IsHealthy() || !strings.Contains(st.Message, "pool is not up") {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("an unprovisioned tenant stays healthy", func(t *testing.T) {
		c := newAPOCContractCheck("tenant-a", func() datapool.Pool {
			return &mockPool{err: &datapool.NotProvisionedError{Tenant: "tenant-a", Reason: "no CRD"}}
		}, slog.New(slog.DiscardHandler))
		if st := c.status(ctx); !st.IsHealthy() || !strings.Contains(st.Message, "not provisioned") {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("an unreachable data plane stays healthy and names the error", func(t *testing.T) {
		c := newAPOCContractCheck("tenant-a", func() datapool.Pool { return &mockPool{err: errors.New("bolt refused")} }, slog.New(slog.DiscardHandler))
		if st := c.status(ctx); !st.IsHealthy() || !strings.Contains(st.Message, "bolt refused") {
			t.Fatalf("got %+v", st)
		}
	})
}

// TestAPOCContractCheck_Verified: the answers a live server gives.
func TestAPOCContractCheck_Verified(t *testing.T) {
	ctx := context.Background()
	contract := dataplane.Neo4jProcedureAllowlist

	t.Run("a verified contract is healthy and sticky", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node", "apoc.merge.relationship"}, allowlist: contract}
		c := contractCheckWith(f)
		if st := c.status(ctx); !st.IsHealthy() || !strings.Contains(st.Message, "verified") {
			t.Fatalf("got %+v", st)
		}
		asked := len(f.asked)
		if st := c.status(ctx); !st.IsHealthy() {
			t.Fatalf("second tick got %+v", st)
		}
		if len(f.asked) != asked {
			t.Fatalf("a pass must be sticky, the second tick asked Neo4j again: %v", f.asked)
		}
	})
	t.Run("an unreadable allowlist is healthy with a note", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node", "apoc.merge.relationship"}, listErr: errors.New("Forbidden")}
		c := contractCheckWith(f)
		if st := c.status(ctx); !st.IsHealthy() || !strings.Contains(st.Message, "not readable") {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("a mismatch is degraded and re-checked every tick", func(t *testing.T) {
		f := &fakeNeo4j{procedures: []string{"apoc.merge.node"}, allowlist: contract}
		c := contractCheckWith(f)
		st := c.status(ctx)
		if !st.IsDegraded() || !strings.Contains(st.Message, "apoc.merge.relationship") {
			t.Fatalf("got %+v", st)
		}
		if st.Details["contract"] != dataplane.ContractEnvFile {
			t.Fatalf("details must point at the contract file, got %v", st.Details)
		}
		asked := len(f.asked)
		if st := c.status(ctx); !st.IsDegraded() || len(f.asked) == asked {
			t.Fatalf("a mismatch must be re-checked, got %+v asked %v", st, f.asked)
		}
	})
}

// fakeSession and fakeResult embed the driver interfaces so the unexported
// methods are satisfied, and override the two calls sessionRows makes.
type fakeSession struct {
	neo4j.SessionWithContext
	res    neo4j.ResultWithContext
	runErr error
}

func (s *fakeSession) Run(context.Context, string, map[string]any, ...func(*neo4j.TransactionConfig)) (neo4j.ResultWithContext, error) {
	return s.res, s.runErr
}

type fakeResult struct {
	neo4j.ResultWithContext
	records []*neo4j.Record
	err     error
}

func (r *fakeResult) Collect(context.Context) ([]*neo4j.Record, error) { return r.records, r.err }

func TestSessionRows(t *testing.T) {
	ctx := context.Background()
	t.Run("records become column maps", func(t *testing.T) {
		keys := []string{"name"}
		s := &fakeSession{res: &fakeResult{records: []*neo4j.Record{
			{Keys: keys, Values: []any{"apoc.merge.node"}},
			{Keys: keys, Values: []any{"apoc.merge.relationship"}},
		}}}
		rows, err := sessionRows(s)(ctx, "SHOW PROCEDURES", nil)
		if err != nil || len(rows) != 2 || rows[1]["name"] != "apoc.merge.relationship" {
			t.Fatalf("got %v, %v", rows, err)
		}
	})
	t.Run("a run error is returned", func(t *testing.T) {
		s := &fakeSession{runErr: errors.New("down")}
		if _, err := sessionRows(s)(ctx, "SHOW PROCEDURES", nil); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("a collect error is returned", func(t *testing.T) {
		s := &fakeSession{res: &fakeResult{err: errors.New("cut")}}
		if _, err := sessionRows(s)(ctx, "SHOW PROCEDURES", nil); err == nil {
			t.Fatal("want an error")
		}
	})
}
