// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// graphrag_querier.go implements the GraphRAGQuerier seam over the data-plane
// Pool, so an off-cluster component can read and write the tenant's knowledge
// graph (gibson#1190).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// EmbedderResolver resolves a tenant's configured embedder.
//
// Declared here rather than imported so this package keeps its narrow seam
// shape; the daemon passes tenantembedder.Resolver, which satisfies it.
type EmbedderResolver interface {
	Resolve(ctx context.Context, tenantID string) (embedder.Embedder, error)
}

// PoolGraphRAGQuerier serves the GraphRAG RPCs from the tenant's own Neo4j
// database and vector collection.
//
// EVERY CALL builds its own provider and store from a freshly acquired Conn and
// releases it on return. The alternative — caching a store per tenant — means
// two owners for one session: this cache and the pool's idle eviction. The
// provider is deliberately cheap enough to make per-call construction the right
// answer (see graphrag.LocalGraphRAGProvider).
//
// TENANT SCOPE is structural: per-tenant Neo4j databases and vector collections
// are physically separate, so the Conn IS the boundary and no query carries a
// tenant predicate. There is no code path here that takes a tenant from
// anywhere but the caller's own context.
//
// AN UNAVAILABLE DEPENDENCY IS REPORTED, NOT WORKED AROUND. A tenant with no
// embedding provider configured cannot have semantic search, and answering
// FindSimilarFindings with a lexical match would be a different operation
// wearing the same name. The error says which dependency is missing.
type PoolGraphRAGQuerier struct {
	pool     datapool.Pool
	embedder EmbedderResolver
	config   graphrag.QueryConfig
	logger   *slog.Logger
}

// NewPoolGraphRAGQuerier constructs the querier. pool and embedderResolver are
// both required — without either, the RPCs cannot be served honestly, and the
// daemon should leave the seam nil so they answer Unimplemented instead.
func NewPoolGraphRAGQuerier(
	pool datapool.Pool,
	embedderResolver EmbedderResolver,
	queryConfig graphrag.QueryConfig,
	logger *slog.Logger,
) *PoolGraphRAGQuerier {
	if logger == nil {
		logger = slog.Default()
	}
	queryConfig.ApplyDefaults()
	return &PoolGraphRAGQuerier{pool: pool, embedder: embedderResolver, config: queryConfig, logger: logger}
}

var _ GraphRAGQuerier = (*PoolGraphRAGQuerier)(nil)

// withStore acquires the tenant's data plane, builds a store over it, runs fn,
// and releases. The store never outlives the call.
func (q *PoolGraphRAGQuerier) withStore(
	ctx context.Context, tenant string, fn func(graphrag.GraphRAGStore) error,
) error {
	if q.pool == nil {
		return errors.New("graphrag: no data-plane pool configured")
	}
	tenantID, err := auth.NewTenantID(tenant)
	if err != nil {
		return fmt.Errorf("graphrag: invalid tenant %q: %w", tenant, err)
	}

	conn, err := q.pool.For(ctx, tenantID)
	if err != nil {
		// MapPoolError turns an un-provisioned tenant into a clean status rather
		// than an Internal, so a caller can tell "not ready yet" from "broken".
		return fmt.Errorf("graphrag: acquire tenant data plane: %w", datapool.MapPoolError(err))
	}
	defer conn.Release()

	if conn.Neo4j == nil {
		return fmt.Errorf("graphrag: tenant %s has no graph database provisioned", tenant)
	}
	if conn.Vector == nil {
		return fmt.Errorf("graphrag: tenant %s has no vector collection provisioned", tenant)
	}

	emb, err := q.embedder.Resolve(ctx, tenant)
	if err != nil {
		return fmt.Errorf("graphrag: tenant %s has no usable embedding provider: %w", tenant, err)
	}

	provider := graphrag.NewLocalGraphRAGProvider(graph.NewSessionGraphClient(conn.Neo4j), conn.Vector)
	if initErr := provider.Initialize(ctx); initErr != nil {
		return fmt.Errorf("graphrag: initialize provider for tenant %s: %w", tenant, initErr)
	}

	store, err := graphrag.NewGraphRAGStoreForOwnedProvider(q.config, emb, provider)
	if err != nil {
		return fmt.Errorf("graphrag: build store for tenant %s: %w", tenant, err)
	}
	return fn(store)
}

// QueryNodes runs a hybrid vector + graph query and returns scored results.
func (q *PoolGraphRAGQuerier) QueryNodes(
	ctx context.Context, tenant string, query *graphragpb.GraphQuery,
) ([]*graphragpb.QueryResult, error) {
	var out []*graphragpb.QueryResult
	err := q.withStore(ctx, tenant, func(store graphrag.GraphRAGStore) error {
		results, qErr := store.Query(ctx, protoQueryToStoreQuery(query))
		if qErr != nil {
			return fmt.Errorf("query nodes: %w", qErr)
		}
		out = make([]*graphragpb.QueryResult, 0, len(results))
		for _, r := range results {
			out = append(out, storeResultToProto(r))
		}
		return nil
	})
	return out, err
}

// FindSimilarAttacks returns JSON-encoded []graphrag.AttackPattern.
func (q *PoolGraphRAGQuerier) FindSimilarAttacks(
	ctx context.Context, tenant, content string, topK int,
) ([]byte, error) {
	return q.jsonResult(ctx, tenant, func(store graphrag.GraphRAGStore) (any, error) {
		return store.FindSimilarAttacks(ctx, content, topK)
	})
}

// GetAttackChains returns JSON-encoded []graphrag.AttackChain.
func (q *PoolGraphRAGQuerier) GetAttackChains(
	ctx context.Context, tenant, techniqueID string, maxDepth int,
) ([]byte, error) {
	return q.jsonResult(ctx, tenant, func(store graphrag.GraphRAGStore) (any, error) {
		return store.GetAttackChains(ctx, techniqueID, maxDepth)
	})
}

// FindSimilarFindings returns JSON-encoded []graphrag.FindingNode.
func (q *PoolGraphRAGQuerier) FindSimilarFindings(
	ctx context.Context, tenant, findingID string, topK int,
) ([]byte, error) {
	return q.jsonResult(ctx, tenant, func(store graphrag.GraphRAGStore) (any, error) {
		return store.FindSimilarFindings(ctx, findingID, topK)
	})
}

// GetRelatedFindings returns JSON-encoded []graphrag.FindingNode.
func (q *PoolGraphRAGQuerier) GetRelatedFindings(
	ctx context.Context, tenant, findingID string,
) ([]byte, error) {
	return q.jsonResult(ctx, tenant, func(store graphrag.GraphRAGStore) (any, error) {
		return store.GetRelatedFindings(ctx, findingID)
	})
}

// jsonResult runs a store read and JSON-encodes whatever it returns. The four
// read RPCs differ only in which store method they call.
func (q *PoolGraphRAGQuerier) jsonResult(
	ctx context.Context, tenant string, read func(graphrag.GraphRAGStore) (any, error),
) ([]byte, error) {
	var encoded []byte
	err := q.withStore(ctx, tenant, func(store graphrag.GraphRAGStore) error {
		result, rErr := read(store)
		if rErr != nil {
			return fmt.Errorf("graphrag read: %w", rErr)
		}
		b, mErr := json.Marshal(result)
		if mErr != nil {
			return fmt.Errorf("encode graphrag result: %w", mErr)
		}
		encoded = b
		return nil
	})
	return encoded, err
}

// protoQueryToStoreQuery maps the wire query onto the store's.
//
// A query with neither text nor embedding is left as-is rather than rejected:
// the store treats it as a pure graph filter, which is a legitimate thing to ask
// for and the only way to list by node type.
func protoQueryToStoreQuery(q *graphragpb.GraphQuery) graphrag.GraphRAGQuery {
	if q == nil {
		return graphrag.GraphRAGQuery{}
	}
	out := graphrag.GraphRAGQuery{
		Text:     q.GetText(),
		TopK:     int(q.GetTopK()),
		MinScore: q.GetMinScore(),
	}
	if len(q.GetEmbedding()) > 0 {
		out.Embedding = make([]float64, 0, len(q.GetEmbedding()))
		for _, v := range q.GetEmbedding() {
			out.Embedding = append(out.Embedding, float64(v))
		}
	}
	for _, t := range q.GetNodeTypes() {
		out.NodeTypes = append(out.NodeTypes, graphrag.NodeType(t))
	}
	if id, err := types.ParseID(q.GetMissionId()); err == nil {
		out.MissionID = &id
	}
	return out
}

func storeResultToProto(r graphrag.GraphRAGResult) *graphragpb.QueryResult {
	path := make([]string, 0, len(r.Path))
	for _, id := range r.Path {
		path = append(path, id.String())
	}
	return &graphragpb.QueryResult{
		Node:        storeNodeToProto(r.Node),
		Score:       r.Score,
		VectorScore: r.VectorScore,
		GraphScore:  r.GraphScore,
		Path:        path,
		Distance:    int32(min(r.Distance, math.MaxInt32)), //nolint:gosec // clamped
	}
}

func storeNodeToProto(n graphrag.GraphNode) *graphragpb.GraphNode {
	nodeType := ""
	if len(n.Labels) > 0 {
		nodeType = string(n.Labels[0])
	}
	out := &graphragpb.GraphNode{
		Id:         n.ID.String(),
		Type:       nodeType,
		Properties: map[string]*graphragpb.Value{},
		CreatedAt:  n.CreatedAt.Unix(),
		UpdatedAt:  n.UpdatedAt.Unix(),
	}
	if n.MissionID != nil {
		out.MissionId = n.MissionID.String()
	}
	for k, v := range n.Properties {
		out.Properties[k] = anyToProtoValue(v)
	}
	return out
}

func anyToProtoValue(v any) *graphragpb.Value {
	switch t := v.(type) {
	case string:
		return &graphragpb.Value{Kind: &graphragpb.Value_StringValue{StringValue: t}}
	case bool:
		return &graphragpb.Value{Kind: &graphragpb.Value_BoolValue{BoolValue: t}}
	case float64:
		return &graphragpb.Value{Kind: &graphragpb.Value_DoubleValue{DoubleValue: t}}
	case int64:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: t}}
	case int:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: int64(t)}}
	default:
		// Anything without a Value kind is rendered as its Go formatting rather
		// than dropped: a property the caller can read as text beats a property
		// that silently disappears.
		return &graphragpb.Value{Kind: &graphragpb.Value_StringValue{StringValue: fmt.Sprint(t)}}
	}
}
