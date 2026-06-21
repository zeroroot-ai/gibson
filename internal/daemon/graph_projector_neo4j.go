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
        svc.product = p.product, svc.version = p.version,
        svc.endpoints = p.endpoints, svc.technologies = p.technologies,
        svc.cert_fingerprint = p.cert_fingerprint, svc.cert_subject = p.cert_subject,
        svc.cert_issuer = p.cert_issuer, svc.cert_not_after = p.cert_not_after,
        svc.updated_at = timestamp()
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
		svc, hasSvc := h.Services[num]
		eps := h.Endpoints[num]
		techs := h.Technologies[num]
		cert, hasCert := h.Certificates[num]

		paths := make([]string, 0, len(eps))
		for _, e := range eps {
			paths = append(paths, e.Path)
		}
		techNames := make([]string, 0, len(techs))
		for _, t := range techs {
			if t.Version != "" {
				techNames = append(techNames, t.Name+" "+t.Version)
			} else {
				techNames = append(techNames, t.Name)
			}
		}
		// A :Service node carries all service-attached detail; create it whenever
		// any detail exists (endpoints/technologies/certificate imply a service).
		hasService := hasSvc || len(paths) > 0 || len(techNames) > 0 || hasCert
		ports = append(ports, map[string]any{
			"number":           num,
			"has_service":      hasService,
			"protocol":         svc.Protocol,
			"service":          svc.Name,
			"product":          svc.Product,
			"version":          svc.Version,
			"endpoints":        paths,
			"technologies":     techNames,
			"cert_fingerprint": cert.Fingerprint,
			"cert_subject":     cert.Subject,
			"cert_issuer":      cert.Issuer,
			"cert_not_after":   cert.NotAfter,
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
  SET f.title = $title, f.description = $description, f.severity = $severity,
      f.scope = $scope, f.address = $address, f.updated_at = timestamp()
WITH f
OPTIONAL MATCH (h:Host {scope: $scope, address: $address})
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
  MERGE (f)-[:AFFECTS]->(h))
RETURN f.brain_id`

const upsertDomainCypher = `
MERGE (d:Domain {brain_id: $id})
  SET d.scope = $scope, d.name = $name, d.updated_at = timestamp()
RETURN d.brain_id`

// UpsertDomain idempotently projects one domain into the tenant's graph.
func (w *neo4jGraphWriter) UpsertDomain(ctx context.Context, tenant string, d brain.DomainSnapshot) error {
	return w.exec(ctx, tenant, upsertDomainCypher, map[string]any{
		"id": int64(d.ID), "scope": d.ScopeID, "name": d.Name,
	}, "domain", d.ID)
}

const upsertSubdomainCypher = `
MERGE (s:Subdomain {brain_id: $id})
  SET s.scope = $scope, s.fqdn = $fqdn, s.domain = $domain, s.updated_at = timestamp()
WITH s
OPTIONAL MATCH (d:Domain {scope: $scope, name: $domain})
FOREACH (_ IN CASE WHEN d IS NULL THEN [] ELSE [1] END |
  MERGE (d)-[:HAS_SUBDOMAIN]->(s))
WITH s
UNWIND $addresses AS addr
OPTIONAL MATCH (h:Host {scope: $scope, address: addr})
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
  MERGE (s)-[:RESOLVES_TO]->(h))
RETURN s.brain_id`

// UpsertSubdomain idempotently projects one subdomain, linking it under its parent
// domain (HAS_SUBDOMAIN) and to the hosts it resolves to (RESOLVES_TO) when those
// are already projected; the edges are conditional so the node is always created
// and links self-heal on a later pass.
func (w *neo4jGraphWriter) UpsertSubdomain(ctx context.Context, tenant string, s brain.SubdomainSnapshot) error {
	addrs := s.Addresses
	if addrs == nil {
		addrs = []string{}
	}
	return w.exec(ctx, tenant, upsertSubdomainCypher, map[string]any{
		"id": int64(s.ID), "scope": s.ScopeID, "fqdn": s.FQDN,
		"domain": s.DomainName, "addresses": addrs,
	}, "subdomain", s.ID)
}

const upsertCredentialCypher = `
MERGE (c:Credential {brain_id: $id})
  SET c.scope = $scope, c.secret_hash = $secret_hash, c.username = $username,
      c.kind = $kind, c.updated_at = timestamp()
RETURN c.brain_id`

// UpsertCredential idempotently projects one credential (scope-partitioned).
func (w *neo4jGraphWriter) UpsertCredential(ctx context.Context, tenant string, c brain.CredentialSnapshot) error {
	return w.exec(ctx, tenant, upsertCredentialCypher, map[string]any{
		"id": int64(c.ID), "scope": c.ScopeID, "secret_hash": c.SecretHash,
		"username": c.Username, "kind": c.Kind,
	}, "credential", c.ID)
}

const upsertAccountCypher = `
MERGE (a:Account {brain_id: $id})
  SET a.scope = $scope, a.identifier = $identifier, a.kind = $kind, a.updated_at = timestamp()
RETURN a.brain_id`

// UpsertAccount idempotently projects one account (scope-partitioned).
func (w *neo4jGraphWriter) UpsertAccount(ctx context.Context, tenant string, a brain.AccountSnapshot) error {
	return w.exec(ctx, tenant, upsertAccountCypher, map[string]any{
		"id": int64(a.ID), "scope": a.ScopeID, "identifier": a.Identifier, "kind": a.Kind,
	}, "account", a.ID)
}

// upsertAgentRunCypher MERGEs an :AgentRun (run-provenance, ADR-0007) keyed by the
// harness run id, and — when its parent run is already projected — the DELEGATED_TO
// edge from parent to child. The edge is conditional so the run node is always
// created; a later pass links it once the parent lands (self-healing), mirroring
// the AFFECTS/HAS_SUBDOMAIN projections.
const upsertAgentRunCypher = `
MERGE (r:AgentRun {brain_id: $run_id})
  SET r.agent = $agent, r.scope = $scope, r.updated_at = timestamp()
WITH r
OPTIONAL MATCH (parent:AgentRun {brain_id: $parent_run_id})
FOREACH (_ IN CASE WHEN $parent_run_id = '' OR parent IS NULL THEN [] ELSE [1] END |
  MERGE (parent)-[:DELEGATED_TO]->(r))
RETURN r.brain_id`

// upsertLlmCallCypher MERGEs an :LlmCall (call provenance, ADR-0007/gibson#755)
// keyed by its brain_id (CallID) and conditionally links the issuing :AgentRun
// via ISSUED — the edge appears once the run lands, self-healing on a later tick.
const upsertLlmCallCypher = `
MERGE (c:LlmCall {brain_id: $call_id})
  SET c.model = $model, c.scope = $scope,
      c.prompt_tokens = $prompt_tokens, c.completion_tokens = $completion_tokens,
      c.total_tokens = $total_tokens, c.updated_at = timestamp()
WITH c
OPTIONAL MATCH (r:AgentRun {brain_id: $run_id})
FOREACH (_ IN CASE WHEN $run_id = '' OR r IS NULL THEN [] ELSE [1] END |
  MERGE (r)-[:ISSUED]->(c))
RETURN c.brain_id`

// UpsertAgentRun idempotently projects one agent run and, when its parent run is
// already projected, the DELEGATED_TO edge — replacing the old direct graph write
// in DelegateToAgent so the projector is the sole writer (ADR-0007, #837).
func (w *neo4jGraphWriter) UpsertAgentRun(ctx context.Context, tenant string, r brain.AgentRunSnapshot) error {
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
		"run_id":        r.RunID,
		"parent_run_id": r.ParentRunID,
		"agent":         r.AgentName,
		"scope":         r.ScopeID,
	}
	_, err = conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, upsertAgentRunCypher, params)
		if txErr != nil {
			return nil, txErr
		}
		return res.Consume(ctx)
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert agent_run %s: %w", r.RunID, err)
	}
	return nil
}

// UpsertLlmCall idempotently projects one LLM call and, when its issuing agent
// run is known, links it ISSUED← (gibson#755). String-keyed by CallID, so it
// uses the dedicated writer path rather than the numeric-id exec helper.
func (w *neo4jGraphWriter) UpsertLlmCall(ctx context.Context, tenant string, c brain.LlmCallSnapshot) error {
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
		"call_id":           c.CallID,
		"run_id":            c.RunID,
		"model":             c.Model,
		"scope":             c.ScopeID,
		"prompt_tokens":     c.PromptTokens,
		"completion_tokens": c.CompletionTokens,
		"total_tokens":      c.TotalTokens(),
	}
	_, err = conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, upsertLlmCallCypher, params)
		if txErr != nil {
			return nil, txErr
		}
		return res.Consume(ctx)
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert llm_call %s: %w", c.CallID, err)
	}
	return nil
}

// exec runs an idempotent projection write against the tenant's Neo4j.
func (w *neo4jGraphWriter) exec(ctx context.Context, tenant, cypher string, params map[string]any, kind string, id uint64) error {
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
	_, err = conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, cypher, params)
		if txErr != nil {
			return nil, txErr
		}
		return res.Consume(ctx)
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert %s %d: %w", kind, id, err)
	}
	return nil
}

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
		"id":          f.ID,
		"title":       f.Title,
		"description": f.Description,
		"severity":    f.Severity,
		"scope":       f.ScopeID,
		"address":     f.Address,
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
