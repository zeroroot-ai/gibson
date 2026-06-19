// Package daemon — graph_projector_neo4j.go
//
// neo4jGraphWriter is the Neo4j-backed GraphWriter: it materializes a brain Host
// (and its ports/services) into the tenant's graph as :Host / :Port / :Service
// nodes with HAS_PORT / RUNS_SERVICE edges (the taxonomy containment from
// docs/design/entity-graph-mapping.md). All writes are idempotent MERGEs keyed by
// the host's stable brain id, so re-projection never duplicates.
package daemon

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// neo4jGraphWriter writes World projections to per-tenant Neo4j via the pool.
// The pool is resolved lazily through poolGetter so the projector can be wired at
// brain-registry creation, before the pool is initialized.
type neo4jGraphWriter struct {
	poolGetter func() datapool.Pool
}

func newNeo4jGraphWriter(poolGetter func() datapool.Pool) *neo4jGraphWriter {
	return &neo4jGraphWriter{poolGetter: poolGetter}
}

const upsertHostCypher = `
MERGE (h:Host {brain_id: $id})
  SET h.scope = $scope, h.address = $address, h.ssh_host_key = $ssh_host_key,
      h.cloud_id = $cloud_id, h.belief_juicy = $juicy, h.attention = $attention,
      h.surprise = $surprise, h.updated_at = timestamp()
WITH h
CALL {
  WITH h
  UNWIND $ports AS p
  MERGE (port:Port {brain_host_id: $id, number: p.number})
    SET port.open = true, port.updated_at = timestamp()
  MERGE (h)-[:HAS_PORT]->(port)
  WITH port, p
  WHERE p.has_service
  MERGE (svc:Service {brain_host_id: $id, port: p.number})
    SET svc.protocol = p.protocol, svc.name = p.service,
        svc.product = p.product, svc.version = p.version, svc.updated_at = timestamp()
  MERGE (port)-[:RUNS_SERVICE]->(svc)
}
RETURN h.brain_id`

// UpsertHost idempotently projects one host into the tenant's Neo4j graph.
func (w *neo4jGraphWriter) UpsertHost(ctx context.Context, tenant string, h brain.HostSnapshot) error {
	pool := w.poolGetter()
	if pool == nil {
		return fmt.Errorf("graph projector: pool not ready")
	}
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		return fmt.Errorf("graph projector: invalid tenant %q: %w", tenant, err)
	}
	conn, err := pool.For(ctx, tid)
	if err != nil {
		return fmt.Errorf("graph projector: pool.For(%s): %w", tenant, err)
	}
	defer conn.Release()

	ports := make([]map[string]any, 0, len(h.OpenPorts))
	for _, num := range h.OpenPorts {
		svc, hasService := h.Services[num]
		ports = append(ports, map[string]any{
			"number":      num,
			"has_service": hasService,
			"protocol":    svc.Protocol,
			"service":     svc.Name,
			"product":     svc.Product,
			"version":     svc.Version,
		})
	}

	params := map[string]any{
		"id":           int64(h.ID),
		"scope":        h.ScopeID,
		"address":      h.Address,
		"ssh_host_key": h.SSHHostKey,
		"cloud_id":     h.CloudID,
		"juicy":        h.Belief.Juicy,
		"attention":    h.Attention,
		"surprise":     h.Surprise,
		"ports":        ports,
	}

	_, err = conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, upsertHostCypher, params)
		if txErr != nil {
			return nil, txErr
		}
		return res.Consume(ctx)
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert host %d: %w", h.ID, err)
	}
	return nil
}

// upsertFindingCypher MERGEs a :Finding and, when the affected host is already
// projected, an AFFECTS edge to it (matched by scope+address). The edge is
// conditional so the finding node is always created; a later pass links it once
// the host lands (self-healing).
const upsertFindingCypher = `
MERGE (f:Finding {brain_id: $id})
  SET f.title = $title, f.severity = $severity, f.scope = $scope,
      f.address = $address, f.updated_at = timestamp()
WITH f
OPTIONAL MATCH (h:Host {scope: $scope, address: $address})
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
  MERGE (f)-[:AFFECTS]->(h))
RETURN f.brain_id`

// UpsertFinding idempotently projects one finding into the tenant's graph.
func (w *neo4jGraphWriter) UpsertFinding(ctx context.Context, tenant string, f brain.FindingSnapshot) error {
	pool := w.poolGetter()
	if pool == nil {
		return fmt.Errorf("graph projector: pool not ready")
	}
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		return fmt.Errorf("graph projector: invalid tenant %q: %w", tenant, err)
	}
	conn, err := pool.For(ctx, tid)
	if err != nil {
		return fmt.Errorf("graph projector: pool.For(%s): %w", tenant, err)
	}
	defer conn.Release()

	params := map[string]any{
		"id":       f.ID,
		"title":    f.Title,
		"severity": f.Severity,
		"scope":    f.ScopeID,
		"address":  f.Address,
	}
	_, err = conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, upsertFindingCypher, params)
		if txErr != nil {
			return nil, txErr
		}
		return res.Consume(ctx)
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert finding %s: %w", f.ID, err)
	}
	return nil
}
