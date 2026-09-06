// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package component — lifecycle_reads.go serves the one graph question an
// application-lifecycle agent has to be able to ask and could not: for this Application, what is
// still open, and does anything actually run the code it is in (gibson#1669).
//
// The existing agent-facing read is hybrid vector-and-graph SEARCH — text or
// embedding, a node-type filter, top-k. Reachability is not a search, it is a
// traversal: is this Package inside an Image that a Deployment of this
// Application runs, and does that Deployment expose a Host. No amount of
// top-k over a node-type filter answers it.
//
// It matters more than a missing convenience because of what an agent does with
// the unknown answer. A triage rule table reads "not reachable" as "nothing
// runs this" and sends the finding to the bottom of the queue, so an
// unanswerable question does not surface as an error — it silently ranks a
// whole backlog as harmless. That is the exact failure ErrKnowledgeUnavailable
// exists to prevent, which is why this read reports unavailability and never
// returns an empty list with a nil error.
//
// It is deliberately ONE bounded question rather than a Cypher surface. An
// agent that could send arbitrary Cypher would be a second, unaudited write and
// read path into the tenant graph, and the traversal it needs is knowable in
// advance.
package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// ApplicationFinding is one open Finding of an Application, with the lifecycle
// context that decides how much it matters.
type ApplicationFinding struct {
	// FindingID is the Finding's brain_id — the same identity every other
	// surface uses, so an agent can write back to the node it read.
	FindingID string `json:"finding_id"`
	// Status is the Finding's lifecycle status: open, fixing, fixed, verified.
	Status string `json:"status"`
	// Severity is the Finding's severity as recorded when it was raised.
	Severity string `json:"severity"`
	// VulnerabilityID is the identity of the weakness this Finding is an
	// instance of (a CVE, a GHSA, or a platform id). Empty when the Finding
	// names no public identifier — a source finding, say — which is a fact
	// about the Finding, not a failure of the read.
	VulnerabilityID string `json:"vulnerability_id,omitempty"`
	// PlaceLabel and PlaceKey are what the Finding affects: a Package in an
	// image, a Repository, or a Service on a host.
	PlaceLabel string `json:"place_label,omitempty"`
	PlaceKey   string `json:"place_key,omitempty"`
	// Reachable reports that the affected place is inside an Image that a
	// Deployment of this Application runs. False means nothing this Application
	// deploys contains it.
	Reachable bool `json:"reachable"`
	// Exposed reports that the Deployment which reaches it also exposes a Host.
	// Exposed is only ever true when Reachable is.
	Exposed bool `json:"exposed"`
	// DeploymentKey and ImageKey name the route that made it reachable, so an
	// agent can say WHY in its reason rather than asserting it.
	DeploymentKey string `json:"deployment_key,omitempty"`
	ImageKey      string `json:"image_key,omitempty"`
	// Priority, PriorityRule and PriorityReason are what a previous triage pass
	// decided about this Finding, written back by the agent and returned here so
	// the next pass can read its own history (gibson#1684).
	//
	// Two behaviours depend on them, and both are dark while they are empty. A
	// triage rule that keeps the previous priority when EPSS or KEV is
	// unavailable — so an outage never re-ranks a Finding on severity alone —
	// has nothing to keep. And a pass that explains only what changed sees every
	// decision as a change, so model cost scales with the backlog rather than
	// with what actually happened.
	//
	// Empty means no pass has decided yet, which is a fact about the Finding and
	// not a failure of the read. The reader must not read empty as "unimportant".
	Priority       string `json:"priority,omitempty"`
	PriorityRule   string `json:"priority_rule,omitempty"`
	PriorityReason string `json:"priority_reason,omitempty"`
}

// applicationFindingsCypher walks one Application's lifecycle subgraph.
//
// A Finding reaches an Application by one of the routes the Taxonomy admits: a
// Package in an Image built from or run by the Application, the Application's
// own Repository, or a Service on a Host one of its Deployments exposes. The
// EXISTS filters keep the row set to this Application; the OPTIONAL MATCHes
// below then say, for each surviving Finding, whether a running Deployment
// actually contains it and whether that Deployment is exposed.
//
// Reachability is answered by the presence of the deployment route, not by a
// property anyone writes: a property could go stale the moment a deployment
// rolls, and a stale "not reachable" is the silent false negative this read
// exists to prevent.
const applicationFindingsCypher = `
MATCH (app:Application {key: $application})
MATCH (f:Finding)-[:AFFECTS]->(place)
WHERE ($statuses = [] OR f.status IN $statuses)
  AND (
    EXISTS { (app)-[:HAS_DEPLOYMENT]->(:Deployment)-[:RUNS]->(:Image)-[:CONTAINS]->(place) }
    OR EXISTS { (app)-[:HAS_REPOSITORY]->(:Repository)<-[:BUILT_FROM]-(:Image)-[:CONTAINS]->(place) }
    OR EXISTS { (app)-[:HAS_REPOSITORY]->(place) }
    OR EXISTS { (app)-[:HAS_DEPLOYMENT]->(:Deployment)-[:EXPOSES]->(:Host)-[:RUNS_SERVICE]->(place) }
  )
WITH app, f, place
OPTIONAL MATCH (f)-[:INSTANCE_OF]->(v:Vulnerability)
OPTIONAL MATCH (app)-[:HAS_DEPLOYMENT]->(dep:Deployment)-[:RUNS]->(img:Image)-[:CONTAINS]->(place)
WITH app, f, place, v, dep, img
OPTIONAL MATCH (dep)-[:EXPOSES]->(host:Host)
WITH f, place, v, dep, img, host
RETURN
  f.brain_id                       AS finding_id,
  coalesce(f.status, '')           AS status,
  coalesce(f.severity, '')         AS severity,
  coalesce(v.key, '')              AS vulnerability_id,
  head(labels(place))              AS place_label,
  coalesce(place.key, place.brain_id, '') AS place_key,
  dep IS NOT NULL                  AS reachable,
  host IS NOT NULL                 AS exposed,
  coalesce(dep.key, '')            AS deployment_key,
  coalesce(img.key, '')            AS image_key,
  coalesce(f.priority, '')         AS priority,
  coalesce(f.priority_rule, '')    AS priority_rule,
  coalesce(f.priority_reason, '')  AS priority_reason
ORDER BY finding_id
LIMIT $limit`

// defaultApplicationFindingsLimit bounds one read. A triage pass over an
// application is tens to hundreds of findings; a cap keeps one call from
// walking an entire tenant graph, and the caller can raise it deliberately.
const defaultApplicationFindingsLimit = 500

// ApplicationFindings returns the Findings of one Application with their
// reachability and exposure.
//
// statuses filters by lifecycle status; empty means every status. The tenant is
// the caller's, resolved by the pool — this method never reads a tenant from a
// payload.
func (q *PoolGraphRAGQuerier) ApplicationFindings(
	ctx context.Context, tenant, application string, statuses []string, limit int,
) ([]byte, error) {
	if application == "" {
		return nil, errors.New("graphrag: application findings: application key is required")
	}
	if limit <= 0 || limit > defaultApplicationFindingsLimit {
		limit = defaultApplicationFindingsLimit
	}
	if statuses == nil {
		statuses = []string{}
	}

	rows, err := q.readGraph(ctx, tenant, applicationFindingsCypher, map[string]any{
		"application": application,
		"statuses":    statuses,
		"limit":       int64(limit),
	})
	if err != nil {
		return nil, err
	}

	return encodeApplicationFindings(rows)
}

// encodeApplicationFindings maps graph rows onto the wire shape.
//
// It is separated from the query so the mapping — which carries the contract
// between the RETURN aliases of applicationFindingsCypher and the JSON an agent
// parses — can be exercised without a graph. A row missing a column, or holding
// one of the wrong type, yields that field's zero value rather than failing the
// read: a Finding that names no CVE is a fact about the Finding, and losing the
// other nine fields over it would be worse than reporting it as it is.
func encodeApplicationFindings(rows []map[string]any) ([]byte, error) {
	out := make([]ApplicationFinding, 0, len(rows))
	for _, r := range rows {
		out = append(out, ApplicationFinding{
			FindingID:       stringField(r, "finding_id"),
			Status:          stringField(r, "status"),
			Severity:        stringField(r, "severity"),
			VulnerabilityID: stringField(r, "vulnerability_id"),
			PlaceLabel:      stringField(r, "place_label"),
			PlaceKey:        stringField(r, "place_key"),
			Reachable:       boolField(r, "reachable"),
			Exposed:         boolField(r, "exposed"),
			DeploymentKey:   stringField(r, "deployment_key"),
			ImageKey:        stringField(r, "image_key"),
			Priority:        stringField(r, "priority"),
			PriorityRule:    stringField(r, "priority_rule"),
			PriorityReason:  stringField(r, "priority_reason"),
		})
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("graphrag: application findings: encode: %w", err)
	}
	return encoded, nil
}

// readGraph runs a read-only Cypher query on the tenant's graph.
//
// It deliberately does NOT go through withStore. That path also requires a
// vector collection and a resolved embedding provider, which a pure traversal
// has no use for — routing this read through it would make reachability
// unreadable on any tenant that has not configured an embedder, which is
// exactly the silent-unknown this read exists to remove.
func (q *PoolGraphRAGQuerier) readGraph(
	ctx context.Context, tenant, cypher string, params map[string]any,
) ([]map[string]any, error) {
	if q.pool == nil {
		return nil, errors.New("graphrag: no data-plane pool configured")
	}
	tenantID, err := auth.NewTenantID(tenant)
	if err != nil {
		return nil, fmt.Errorf("graphrag: invalid tenant %q: %w", tenant, err)
	}
	conn, err := q.pool.For(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("graphrag: acquire tenant data plane: %w", datapool.MapPoolError(err))
	}
	defer conn.Release()

	// An unprovisioned graph is reported, never answered with an empty list: an
	// agent that cannot tell "nothing is reachable" from "I could not look"
	// would rank a whole backlog as harmless.
	if conn.Neo4j == nil {
		return nil, fmt.Errorf("graphrag: tenant %s has no graph database provisioned", tenant)
	}

	result, err := conn.Neo4j.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, cypher, params)
		if txErr != nil {
			return nil, fmt.Errorf("graphrag: run read query: %w", txErr)
		}
		records, colErr := res.Collect(ctx)
		if colErr != nil {
			return nil, fmt.Errorf("graphrag: collect read result: %w", colErr)
		}
		return recordsToRows(records), nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphrag: application findings: %w", err)
	}
	return rowsFromResult(result), nil
}

// recordsToRows flattens driver records to plain maps.
//
// A record with no values yields an empty map rather than being dropped, so the
// row count out equals the row count the query returned — a caller counting
// findings must not silently lose one to a malformed row.
func recordsToRows(records []*neo4j.Record) []map[string]any {
	rows := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		if rec == nil {
			continue
		}
		rows = append(rows, rec.AsMap())
	}
	return rows
}

// rowsFromResult narrows what ExecuteRead returns as `any`.
//
// A failed assertion yields no rows rather than a panic, but it can only happen
// if the closure above stops returning []map[string]any — so it is a guard on a
// refactor, not on the driver.
func rowsFromResult(result any) []map[string]any {
	rows, _ := result.([]map[string]any)
	return rows
}

func stringField(row map[string]any, key string) string {
	if v, ok := row[key].(string); ok {
		return v
	}
	return ""
}

func boolField(row map[string]any, key string) bool {
	if v, ok := row[key].(bool); ok {
		return v
	}
	return false
}
