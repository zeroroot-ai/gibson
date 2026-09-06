// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"regexp"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// neo4jGraphWriter writes World projections to per-tenant Neo4j via the pool.
// The pool is resolved lazily through poolGetter so the projector can be wired at
// brain-registry creation, before the pool is initialized.
type neo4jGraphWriter struct {
	poolGetter func() datapool.Pool
}

// projectedNodeLabels and projectedRelationshipTypes are the vocabulary this
// writer's Cypher actually materializes. They are declared here so the Taxonomy
// and the projector cannot drift apart unnoticed — which is the same failure
// (Host / HOST / host_v2 diverging silently) that makes the Taxonomy global in
// the first place (ADR-0012).
var projectedNodeLabels = []string{
	"Account", "AgentRun", "Credential", "Domain", "Finding", "Host",
	"LlmCall", "Mission", taxonomy.ObservationLabel, "Port", "Service", "Subdomain",
	// Application lifecycle (gibson#1656): materialised by upsertEntityCypher
	// with the label as a parameter, and Vulnerability also by
	// upsertFindingCypher's INSTANCE_OF merge.
	"Application", "Control", "Deployment", "Image", "MergeRequest", "Package",
	"Pipeline", "Repository", "Vulnerability",
}

var projectedRelationshipTypes = []string{
	"AFFECTS", "DELEGATED_TO", "HAS_PORT", "HAS_SUBDOMAIN", "ISSUED",
	"RESOLVES_TO", "RUNS_SERVICE",
	// Application lifecycle (gibson#1656): INSTANCE_OF is a constant in
	// upsertFindingCypher; the rest travel as the e.type parameter of
	// apoc.merge.relationship in upsertEntityCypher.
	"BUILT_FROM", "CONTAINS", "EXPOSES", "FIXED_BY", "HAS_DEPLOYMENT",
	"HAS_REPOSITORY", "INSTANCE_OF", "MERGED_INTO", "RUNS", "TOUCHES", "VERIFIED_BY",
}

// checkProjectedVocabulary reports every label or relationship type this writer
// emits that the global Taxonomy does not admit. An empty result is the
// invariant: the sole graph writer writes only promoted shapes.
func checkProjectedVocabulary() []string {
	return vocabularyDrift(taxonomy.Global, projectedNodeLabels, projectedRelationshipTypes)
}

// vocabularyDrift is checkProjectedVocabulary against an explicit registry and
// vocabulary. It is separate so the drift branches can be exercised without
// mutating the global Taxonomy — whose invalid states take the package's init
// down and cannot be reached from a test at all.
func vocabularyDrift(reg *taxonomy.Registry, nodeLabels, relationshipTypes []string) []string {
	var drift []string
	for _, label := range nodeLabels {
		if !reg.ClassifyNode(label).InTaxonomy {
			drift = append(drift, fmt.Sprintf("node label %q is projected but not in Taxonomy v%d (admitted: %v)",
				label, reg.Version(), reg.NodeLabels()))
		}
	}
	for _, relType := range relationshipTypes {
		if !reg.ClassifyRelationship(relType).InTaxonomy {
			drift = append(drift, fmt.Sprintf("relationship type %q is projected but not in Taxonomy v%d (admitted: %v)",
				relType, reg.Version(), reg.RelationshipTypes()))
		}
	}
	return drift
}

func newNeo4jGraphWriter(poolGetter func() datapool.Pool) *neo4jGraphWriter {
	// Fail loudly at wiring time rather than writing a shape the Taxonomy does
	// not admit. This is a code-versioned invariant on both sides, so any
	// mismatch is a programming error caught before the first projection tick.
	if drift := checkProjectedVocabulary(); len(drift) > 0 {
		panic("graph projector: vocabulary drifted from the Taxonomy: " + strings.Join(drift, "; "))
	}
	return &neo4jGraphWriter{poolGetter: poolGetter}
}

// safeTaxonomyLabel matches the label names the projector is willing to emit:
// a plain Cypher identifier. See taxonomyLabels for why this exists on top of
// apoc.merge.node rather than instead of it.
var safeTaxonomyLabel = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// taxonomyLabels validates a taxonomy label set at package initialisation and
// returns it. An invalid label is a panic, not an error: the taxonomy is
// global and versioned in code (ADR-0012), so an unsafe entry is a programming
// error that must never reach a running daemon.
//
// # Why this guard exists on top of apoc.merge.node
//
// apoc.merge.node takes labels as runtime arguments, and that IS what makes a
// label data rather than query structure for very nearly every input — a label
// of `; MATCH (n) DETACH DELETE n //` is merged as a badly-named label and
// executes nothing.
//
// It is not sufficient on its own. APOC builds the MERGE by back-quoting each
// label with apoc.util.Util.quote, which as of 5.26 is
//
//	return SourceVersion.isIdentifier(var) && !var.contains("$") ? var : '`' + var + '`';
//
// — it wraps the name in backticks and does NOT escape backticks inside it. A
// label containing one therefore closes the quoting early and the remainder is
// parsed as Cypher. Verified against neo4j:5.26.27-community with APOC Core
// 5.26.27: a label of "Host`) DETACH DELETE (n) //" deletes matching nodes and
// the procedure returns no rows and no error, so the caller sees success.
//
// Nothing in the projector can produce such a label today — the list below is
// a compile-time constant — so this is not a live hole. The guard is here so
// that stays true by construction rather than by inspection, because the
// taxonomy is meant to grow and the failure mode is silent data destruction.
func taxonomyLabels(names ...string) []string {
	for _, n := range names {
		if !safeTaxonomyLabel.MatchString(n) {
			panic(fmt.Sprintf("graph projector: taxonomy label %q is not a plain identifier; "+
				"apoc.merge.node does not escape backticks inside a label name", n))
		}
	}
	return names
}

// hostLabels is the taxonomy label set for a projected host. It reaches Neo4j
// as the $host_labels parameter of apoc.merge.node rather than as query text.
//
// The taxonomy is global and versioned in code, so this is a fixed list today.
// It is passed as a parameter anyway, because the property that matters is
// structural — no code path assembles Cypher from a label — and a write path
// that is safe only because its label happens to be constant loses that
// property the first time a label becomes dynamic.
var hostLabels = taxonomyLabels("Host")

// upsertHostCypher materializes a Host and its ports/services. The Host node
// itself goes through apoc.merge.node with $host_labels as a runtime argument
// (ADR-0012, gibson#1257); the containment subquery below still uses constant
// :Port / :Service labels and is converted separately.
//
// Merge semantics are unchanged from the plain `MERGE (h:Host {brain_id: $id})`
// this replaces: identity is brain_id alone, and the same property map is
// passed as both onCreate and onMatch, which is what the previous unconditional
// SET did. updated_at is stamped after the merge because timestamp() must be
// evaluated by the server, not carried in a parameter map.
//
// This requires APOC Core on the tenant's Neo4j. The operator provisions it
// (operators/tenant/internal/dataplane/neo4j_apoc.go); against a database that
// predates that reconcile the call fails, the projector logs it, and the next
// pass self-heals once the pod has rolled.
const upsertHostCypher = `
CALL apoc.merge.node($host_labels, {brain_id: $id}, $host, $host) YIELD node AS h
SET h.updated_at = timestamp()
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

// hostUpsertParams builds the parameter set for upsertHostCypher. Split out of
// UpsertHost so the labels-are-parameters property is testable without a
// database: everything that varies with the host — including the labels — is
// in this map, and upsertHostCypher is a constant.
func hostUpsertParams(h brain.HostSnapshot) map[string]any {
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

	return map[string]any{
		"host_labels": hostLabels,
		//nolint:gosec // G115: h.ID is a monotonic brain-assigned counter (newHostID, from 1); it never approaches int64 max.
		"id": int64(h.ID),
		"host": map[string]any{
			"scope":        h.ScopeID,
			"address":      h.Address,
			"ssh_host_key": h.SSHHostKey,
			"cloud_id":     h.CloudID,
			"belief_juicy": h.Belief.Juicy,
			"attention":    h.Attention,
			"surprise":     h.Surprise,
		},
		"ports": ports,
	}
}

// UpsertHost idempotently projects one host into the tenant's Neo4j graph.
func (w *neo4jGraphWriter) UpsertHost(ctx context.Context, tenant string, h brain.HostSnapshot) error {
	return w.exec(ctx, tenant, upsertHostCypher, hostUpsertParams(h), "host", h.ID)
}

// upsertFindingCypher MERGEs a :Finding and, when the affected host is already
// projected, an AFFECTS edge to it (matched by scope+address). The edge is
// conditional so the finding node is always created; a later pass links it once
// the host lands (self-healing).
//
// Status and vulnerability_id (gibson#1656): status is SET on every pass, so a
// FindingStatusChanged folded into the World lands on the existing node in
// place. When the Finding names a Vulnerability, the one :Vulnerability node
// per id per tenant is merged by key and linked INSTANCE_OF, so one CVE across
// four Applications is one node with four edges.
const upsertFindingCypher = `
MERGE (f:Finding {brain_id: $id})
  ON CREATE SET f.created_at = datetime()
  SET f.title = $title, f.description = $description, f.severity = $severity,
      f.scope = $scope, f.address = $address, f.status = $status,
      f.vulnerability_id = $vulnerability_id, f.updated_at = timestamp()
WITH f
FOREACH (_ IN CASE WHEN $status = $verified_status AND f.verified_at IS NULL THEN [1] ELSE [] END |
  SET f.verified_at = datetime())
WITH f
OPTIONAL MATCH (h:Host {scope: $scope, address: $address})
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
  MERGE (f)-[:AFFECTS]->(h))
WITH f
FOREACH (_ IN CASE WHEN $vulnerability_id = '' THEN [] ELSE [1] END |
  MERGE (v:Vulnerability {key: $vulnerability_id})
    SET v.updated_at = timestamp()
  MERGE (f)-[:INSTANCE_OF]->(v))
RETURN f.brain_id`

// upsertEntityCypher materialises one typed application-lifecycle entity
// (gibson#1656). The label reaches Neo4j as the $label parameter of
// apoc.merge.node and every edge type as e.type of apoc.merge.relationship —
// the two procedures the tenant allowlist admits
// (pkg/platform/dataplane Neo4jProcedureAllowlist) — never as query text.
//
// Identity travels as the $ident PARAMETER MAP rather than a literal
// {key: $key}, because a label's identity property is a property of the LABEL,
// not of this write path (gibson#1669). A Finding raised by the normal path
// merges on brain_id; if an entity write merged the same label on key it would
// create a SECOND :Finding beside the real one, and every priority or status an
// agent wrote would land on a node nothing else references. Building the map in
// Go keeps that decision in one table (entityIdentityProperty) and still puts
// nothing but parameters on the wire.
//
// The same property map is both onCreate and onMatch, so a later sighting
// enriches the node in place. The target of an edge is merged the same way, so
// the edge lands even when the target has not been projected on its own yet,
// and the target's own pass fills it in.
const upsertEntityCypher = `
CALL apoc.merge.node([$label], $ident, $props, $props) YIELD node AS n
SET n.scope = $scope, n.taxonomy_version = $taxonomy_version, n.updated_at = timestamp()
WITH n
UNWIND $edges AS e
CALL apoc.merge.node([e.label], e.ident, {}, {}) YIELD node AS t
CALL apoc.merge.relationship(n, e.type, {}, {}, t, {}) YIELD rel
RETURN count(rel)`

// entityIdentityProperty is the property each label is identified by.
//
// Most application-lifecycle labels are owned by the entity path and are
// identified by their natural key — a CVE id, an image digest, a repository
// path. The labels listed here are NOT: they have a first-class projection of
// their own, and that projection has always merged them on the property named
// below. An entity write for one of those labels has to use the SAME property,
// or the two writers of one label diverge into two nodes (gibson#1669).
//
// Mission is deliberately absent. It is identified by (id, tenant_id) — a
// composite no single-property merge can express — and an agent has no reason
// to write one, so an entity write naming Mission is refused rather than
// half-matched.
var entityIdentityProperty = map[string]string{
	// First-class projections keyed by the World entity id.
	"Account":    "brain_id",
	"AgentRun":   "brain_id",
	"Credential": "brain_id",
	"Domain":     "brain_id",
	"Finding":    "brain_id",
	"Host":       "brain_id",
	"LlmCall":    "brain_id",
	"Subdomain":  "brain_id",
	// The observation escape hatch is keyed by the event that carried it.
	taxonomy.ObservationLabel: "event_id",
}

// entityIdentityRefused are labels an entity write may not address at all,
// because their first-class projection identifies them by a composite key that
// a single-property merge cannot express. Refusing is the honest answer: a
// partial match would silently write to the wrong node.
var entityIdentityRefused = map[string]struct{}{
	"Mission": {},
	// Port and Service are identified by (brain_host_id, number/port): they
	// belong to a Host and are projected with it.
	"Port":    {},
	"Service": {},
}

// entityIdentity builds the identity map for one label, or reports that the
// label may not be addressed this way.
func entityIdentity(label, key string) (map[string]any, error) {
	if _, refused := entityIdentityRefused[label]; refused {
		return nil, fmt.Errorf("graph projector: %s is identified by a composite key and cannot be addressed by an entity write", label)
	}
	prop := entityIdentityProperty[label]
	if prop == "" {
		prop = "key"
	}
	return map[string]any{prop: key}, nil
}

// entityReservedProps are the node properties upsertEntityCypher owns. A
// payload key with one of these names is dropped so an emitter cannot rewrite
// the node's identity or its bookkeeping through the property map.
// Every identity property is reserved, not just "key": once a label can be
// identified by brain_id or event_id, an emitter that could set those through
// the property map could re-point a node at another node's identity
// (gibson#1669).
var entityReservedProps = map[string]struct{}{
	"key": {}, "scope": {}, "taxonomy_version": {}, "updated_at": {},
	"brain_id": {}, "event_id": {}, "brain_host_id": {},
}

// entityUpsertParams builds the parameter set for upsertEntityCypher. Split
// out so the labels-and-types-are-parameters property, the reserved-property
// filter and the Taxonomy re-check on every label and edge type are testable
// without a database.
//
// The re-check is belt and braces: the ingest already admitted these, but the
// projector is the sole writer and the last line before Neo4j, so it refuses
// on its own authority. An entity whose label is not admitted returns an
// error; an edge whose type or target label is not admitted is dropped.
func entityUpsertParams(e brain.EntitySnapshot) (map[string]any, error) {
	if !taxonomy.Global.ClassifyNode(e.Label).InTaxonomy {
		return nil, fmt.Errorf("graph projector: entity label %q is not in Taxonomy v%d", e.Label, taxonomy.Version)
	}
	if e.Key == "" {
		return nil, fmt.Errorf("graph projector: entity %s has no key", e.Label)
	}
	props := make(map[string]any, len(e.Props))
	for k, v := range e.Props {
		if _, reserved := entityReservedProps[k]; reserved {
			continue
		}
		if !safeTaxonomyLabel.MatchString(k) {
			continue
		}
		props[k] = v
	}
	ident, err := entityIdentity(e.Label, e.Key)
	if err != nil {
		return nil, err
	}
	edges := make([]map[string]any, 0, len(e.Edges))
	for _, edge := range e.Edges {
		if !taxonomy.Global.ClassifyRelationship(edge.Type).InTaxonomy {
			continue
		}
		if !taxonomy.Global.ClassifyNode(edge.TargetLabel).InTaxonomy || edge.TargetKey == "" {
			continue
		}
		// An edge target is merged by its OWN label's identity property, for the
		// same reason the entity is: an edge to a Finding must land on the
		// Finding, not on a second node wearing the label (gibson#1669). A target
		// whose label cannot be addressed this way is dropped, not guessed at.
		targetIdent, identErr := entityIdentity(edge.TargetLabel, edge.TargetKey)
		if identErr != nil {
			continue
		}
		edges = append(edges, map[string]any{
			"type": edge.Type, "label": edge.TargetLabel, "ident": targetIdent,
		})
	}
	return map[string]any{
		"label":            e.Label,
		"ident":            ident,
		"scope":            e.ScopeID,
		"taxonomy_version": taxonomy.Version,
		"props":            props,
		"edges":            edges,
	}, nil
}

// UpsertEntity idempotently projects one typed lifecycle entity and its edges.
func (w *neo4jGraphWriter) UpsertEntity(ctx context.Context, tenant string, e brain.EntitySnapshot) error {
	params, err := entityUpsertParams(e)
	if err != nil {
		return err
	}
	return w.exec(ctx, tenant, upsertEntityCypher, params, "entity", e.Label+":"+e.Key)
}

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

// upsertMissionCypher MERGEs a :Mission node keyed by (id, tenant_id). It moved
// here verbatim from the CreateMission RPC handler, which used to run it inline
// against a pool connection — a second writer the graph is not supposed to have
// (ADR-0012). `created_at` is re-stamped on every merge, as it was before; the
// move is behaviour-preserving, not a fix.
const upsertMissionCypher = `
MERGE (m:Mission { id: $id, tenant_id: $tenant })
SET m.name = $name,
    m.target = $target,
    m.status = $status,
    m.created_by = $created_by,
    m.created_at = datetime()
RETURN m
`

// UpsertMission materializes one :Mission node into the tenant's graph. It runs
// off the CreateMission RPC rather than the projection tick, but goes through
// the same write path as every other projection so the projector stays the one
// place a Neo4j write transaction is opened.
func (w *neo4jGraphWriter) UpsertMission(ctx context.Context, tenant string, m MissionProjection) error {
	return w.exec(ctx, tenant, upsertMissionCypher, map[string]any{
		"id":         m.ID,
		"tenant":     tenant,
		"name":       m.Name,
		"target":     m.TargetID,
		"status":     m.Status,
		"created_by": m.CreatedBy,
	}, "mission", m.ID)
}

// exec runs an idempotent projection write against the tenant's Neo4j.
func (w *neo4jGraphWriter) exec(ctx context.Context, tenant, cypher string, params map[string]any, kind string, id any) error {
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
	if conn.Neo4j == nil {
		// Neo4j is not configured for this tenant; there is nothing to project
		// into. Not an error — this is what the CreateMission handler did before
		// its MERGE moved here, and it is the right answer for every projection.
		return nil
	}
	_, err = conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, cypher, params)
		if txErr != nil {
			return nil, txErr
		}
		return res.Consume(ctx)
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert %s %v: %w", kind, id, err)
	}
	return nil
}

// findingUpsertParams builds the parameter set for upsertFindingCypher. A
// Finding with no status in the World projects as open, so a node never
// carries an empty status; an empty vulnerability id disables the INSTANCE_OF
// merge in the Cypher.
func findingUpsertParams(f brain.FindingSnapshot) map[string]any {
	status := f.Status
	if !brain.ValidFindingStatus(status) {
		status = brain.FindingStatusOpen
	}
	return map[string]any{
		"id":               f.ID,
		"title":            f.Title,
		"description":      f.Description,
		"severity":         f.Severity,
		"scope":            f.ScopeID,
		"address":          f.Address,
		"status":           status,
		"vulnerability_id": f.VulnerabilityID,
		// The terminal status travels as a parameter like every other value, so
		// the Cypher stays a constant and the definition of "verified" stays in
		// one place (brain.FindingStatusVerified).
		"verified_status": brain.FindingStatusVerified,
	}
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

	params := findingUpsertParams(f)
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

// upsertObservationCypher MERGEs an :Observation — the node every
// out-of-taxonomy shape lands on (ADR-0012).
//
// Three things are load-bearing here:
//
//   - The label is the compile-time constant `Observation`, never the shape the
//     agent asked for. The requested shape rides along as a property *value*, so
//     it is data and cannot become structure. This is why no APOC is needed on
//     this path, and why it is safe even though the shape is attacker-influenced.
//   - Identity is the Timeline event id, so re-projection converges and two
//     sightings of the same fact at different times remain distinct nodes.
//   - The residue is applied with `SET o += $payload`, Cypher's map-append. The
//     keys arrive as map entries in a parameter, never spliced into the query
//     text — which is what makes unbounded keys a schema-sprawl concern rather
//     than an injection one (the caps in ADR-0012's "Bounded" paragraph are what
//     address the sprawl).
//
// Residue keys are prefixed by the caller so they can never collide with, or
// overwrite, the reserved properties set above them.
const upsertObservationCypher = `
MERGE (o:Observation {event_id: $event_id})
  SET o.brain_id = $id, o.shape = $shape, o.content_hash = $content_hash,
      o.scope = $scope, o.mission_id = $mission_id, o.observed_at = $observed_at,
      o.taxonomy_version = $taxonomy_version, o.updated_at = timestamp()
  SET o += $payload
RETURN o.event_id`

// observationPayloadPrefix namespaces the unschematized residue so it cannot
// shadow a reserved property. `SET o += $payload` would happily overwrite
// o.shape or o.event_id otherwise, which would let a payload key rewrite the
// node's own identity.
const observationPayloadPrefix = "p_"

// UpsertObservation idempotently projects one out-of-taxonomy observation.
func (w *neo4jGraphWriter) UpsertObservation(ctx context.Context, tenant string, o brain.ObservationSnapshot) error {
	return w.exec(ctx, tenant, upsertObservationCypher, observationParams(o), "observation", o.ID)
}

// observationParams builds the parameter map for upsertObservationCypher. It is
// separate from the write so the namespacing of the residue — the thing that
// keeps a payload key from rewriting the node's own identity — can be asserted
// without a live Neo4j.
func observationParams(o brain.ObservationSnapshot) map[string]any {
	payload := make(map[string]any, len(o.Payload))
	for k, v := range o.Payload {
		payload[observationPayloadPrefix+k] = v
	}
	return map[string]any{
		"event_id": o.EventID,
		//nolint:gosec // G115: o.ID is a monotonic brain-assigned counter; it never approaches int64 max.
		"id":               int64(o.ID),
		"shape":            o.Shape,
		"content_hash":     o.ContentHash,
		"scope":            o.ScopeID,
		"mission_id":       o.MissionID,
		"observed_at":      o.ObservedAt,
		"taxonomy_version": int64(taxonomy.Global.Version()),
		"payload":          payload,
	}
}
