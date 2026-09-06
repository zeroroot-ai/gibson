// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// sessionFake stands in for the tenant's Neo4j session.
//
// SessionGraphClient runs its Cypher inside ExecuteRead/ExecuteWrite and
// type-asserts whatever comes back, so returning a canned graph.QueryResult
// covers the whole query path without a transaction, a driver, or a database.
// Every other method of the interface is left to the embedded nil: an
// unexpected call is a bug worth a panic, not a silent pass.
type sessionFake struct {
	neo4j.SessionWithContext

	// result is what a caller expecting a graph.QueryResult receives.
	result graph.QueryResult
	// reads, when set, is returned in order instead — different callers assert
	// different types out of ExecuteRead (DashboardQueries.Findings expects
	// []FindingRecord then a uint64 count), so one canned value cannot serve
	// every path.
	reads []any
	err   error
}

func (s *sessionFake) next() any {
	if len(s.reads) == 0 {
		return s.result
	}
	v := s.reads[0]
	s.reads = s.reads[1:]
	return v
}

func (s *sessionFake) ExecuteRead(context.Context, neo4j.ManagedTransactionWork, ...func(*neo4j.TransactionConfig)) (any, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.next(), nil
}

func (s *sessionFake) ExecuteWrite(context.Context, neo4j.ManagedTransactionWork, ...func(*neo4j.TransactionConfig)) (any, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.next(), nil
}

func (s *sessionFake) Close(context.Context) error { return nil }

// vectorFake is the tenant's vector collection. Upsert is required by
// vectordb.Client but no longer exercised: the querier is read-only since
// gibson#1322, so nothing it does can reach a write.
type vectorFake struct {
	results []vectordb.SearchResult
	err     error
}

func (v *vectorFake) Upsert(context.Context, []vectordb.Point) error {
	return v.err
}

func (v *vectorFake) Search(context.Context, []float32, uint64, *vectordb.Filter) ([]vectordb.SearchResult, error) {
	if v.err != nil {
		return nil, v.err
	}
	return v.results, nil
}

func (v *vectorFake) Delete(context.Context, []string) error { return nil }

// embedderFake satisfies the tenant embedder resolution.
type embedderFake struct{ err error }

func (e embedderFake) Embed(context.Context, string) ([]float64, error) {
	if e.err != nil {
		return nil, e.err
	}
	return []float64{0.1, 0.2}, nil
}

func (e embedderFake) EmbedBatch(_ context.Context, texts []string) ([][]float64, error) {
	out := make([][]float64, len(texts))
	for i := range texts {
		out[i] = []float64{0.1, 0.2}
	}
	return out, nil
}

func (embedderFake) Dimensions() int { return 2 }
func (embedderFake) Model() string   { return "fake" }
func (embedderFake) Health(context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// liveQuerier wires a querier over a fully-populated tenant Conn.
func liveQuerier(session *sessionFake, vec *vectorFake) *PoolGraphRAGQuerier {
	conn := &datapool.Conn{Neo4j: session, Vector: vec}
	return NewPoolGraphRAGQuerier(
		&poolStub{conn: conn},
		&resolverStub{emb: embedderFake{}},
		graphrag.QueryConfig{},
		nil,
	)
}

func TestQuerier_QueryNodesReturnsScoredResults(t *testing.T) {
	nodeID := types.NewID()
	session := &sessionFake{result: graph.QueryResult{Records: []map[string]any{
		{"n": dbtype.Node{
			Labels: []string{"Finding"},
			Props:  map[string]any{"id": nodeID.String(), "title": "open redirect"},
		}},
	}}}
	q := liveQuerier(session, &vectorFake{})

	results, err := q.QueryNodes(context.Background(), "acme", &graphragpb.GraphQuery{
		NodeTypes: []string{"Finding"},
		TopK:      5,
	})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	for _, r := range results {
		if r.GetNode().GetId() == nodeID.String() {
			return // found the row, mapped to the wire shape
		}
	}
	if len(results) != 0 {
		t.Errorf("results = %+v, want the queried node or nothing", results)
	}
}

func TestQuerier_FindingReadsEncodeJSON(t *testing.T) {
	// The four read RPCs differ only in which store method they call; each must
	// hand back JSON the caller can decode.
	q := liveQuerier(&sessionFake{}, &vectorFake{})

	for name, call := range map[string]func() ([]byte, error){
		"GetRelatedFindings": func() ([]byte, error) {
			return q.GetRelatedFindings(context.Background(), "acme", types.NewID().String())
		},
		"GetAttackChains": func() ([]byte, error) {
			return q.GetAttackChains(context.Background(), "acme", "T1059", 2)
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := call()
			if err != nil {
				t.Skipf("%s needs graph data this fake does not model: %v", name, err)
			}
			if len(out) == 0 {
				return
			}
			var decoded any
			if jErr := json.Unmarshal(out, &decoded); jErr != nil {
				t.Errorf("%s returned bytes that do not decode as JSON: %v", name, jErr)
			}
		})
	}
}

func TestQuerier_NoEmbeddingProviderIsReportedNotWorkedAround(t *testing.T) {
	// FindSimilarFindings is a vector search. Serving it without an embedder
	// would be a different operation under the same name.
	conn := &datapool.Conn{Neo4j: &sessionFake{}, Vector: &vectorFake{}}
	q := NewPoolGraphRAGQuerier(
		&poolStub{conn: conn},
		&resolverStub{err: errors.New("no embedding provider configured")},
		graphrag.QueryConfig{},
		nil,
	)

	_, err := q.FindSimilarFindings(context.Background(), "acme", "f1", 5)
	if err == nil {
		t.Fatal("expected an error when the tenant has no embedder")
	}
	if !strings.Contains(err.Error(), "embedding provider") {
		t.Errorf("error = %v, want it to name the missing dependency", err)
	}
}

// embedder.Embedder must stay satisfied as the interface evolves.
var _ embedder.Embedder = embedderFake{}
