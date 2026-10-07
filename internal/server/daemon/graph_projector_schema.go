// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — graph_schema_neo4j.go
//
// The tenant graph schema (constraints, indexes and the schema version) is
// ensured by the projector, the graph's only writer, once per tenant before
// that tenant's first write (gibson#469).
//
// The projector owns this and the tenant operator does not, because the
// operator imports internal/infra and internal/platform and never
// internal/engine, and the label vocabulary lives in internal/engine/taxonomy.
// The constraint set is derived from taxonomy.Global.NodeLabels(), so a label
// added to the taxonomy gets a constraint with no second edit.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// schemaVersionLabel and schemaVersionName name the singleton node that records
// which taxonomy version the tenant database was prepared for. The tenant
// operator reads it with
//
//	MATCH (v:_SchemaVersion) RETURN v.version AS version LIMIT 1
//
// (operators/tenant/internal/dataplane/migration_versions.go) and accepts an
// integer, so version is written as an int64.
const (
	schemaVersionLabel = "_SchemaVersion"
	schemaVersionName  = "taxonomy"
)

// labelIdentity is how the projector identifies a node of one label. It mirrors
// the MERGE keys of the Cypher in graph_projector_neo4j.go.
type labelIdentity struct {
	props  []string
	unique bool // true: uniqueness constraint on props[0]; false: composite lookup index
}

// identityForLabel returns the identity of a taxonomy label.
//
// Not every label is keyed on brain_id. Port and Service are identified by a
// composite (brain_host_id, number|port) that a uniqueness constraint cannot
// express on Community Edition, so they get a composite index. Mission is
// MERGEd on (id, tenant_id) and tenant_id is constant inside a per-tenant
// database, so id is unique. Observation is keyed by event_id. Entity labels
// without a first-class projection are keyed by key (see entityIdentity).
//
// MissionNode, MissionRun and Target are keyed on `id` for the same reason as
// Mission: each writer MERGEs on it, and inside a per-tenant database that is
// unique. They are listed here rather than left to the default, because the
// default resolves an unlisted label to `key` — and a constraint on `key`
// covers no node any of these three writers creates, which is the exact defect
// this file exists to prevent (gibson#550).
func identityForLabel(label string) labelIdentity {
	switch label {
	case "Port":
		return labelIdentity{props: []string{"brain_host_id", "number"}}
	case "Service":
		return labelIdentity{props: []string{"brain_host_id", "port"}}
	case "Mission", "MissionNode", "MissionRun", "Target":
		return labelIdentity{props: []string{"id"}, unique: true}
	}
	// identityPropertyFor is the ONE resolver, shared with entityIdentity in
	// graph_projector_neo4j.go. The schema constrains the property the projector
	// merges on; if the two disagree the constraint covers no node the projector
	// writes, which is the defect this file exists to fix, inverted.
	//
	// It used to be two copies of the same three lines, held together by this
	// comment telling the next reader to keep them in step. They did not stay in
	// step: both defaulted a runtime-promoted label to `key` while the promotion
	// registry and the ontology pack an import carries both declared it as
	// brain_id (gibson#515). One function cannot drift from itself.
	return labelIdentity{props: []string{identityPropertyFor(label)}, unique: true}
}

// lookupIndexes are the indexes the read and match paths need beyond node
// identity. Each names the query it serves. An index no query uses is not
// added here.
var lookupIndexes = []struct {
	label string
	props []string
	why   string
}{
	// upsertFindingCypher and upsertSubdomainCypher: OPTIONAL MATCH (h:Host {scope: $scope, address: ...}).
	{"Host", []string{"scope", "address"}, "upsertFindingCypher / upsertSubdomainCypher match a Host by scope+address"},
	// upsertSubdomainCypher: OPTIONAL MATCH (d:Domain {scope: $scope, name: $domain}).
	{"Domain", []string{"scope", "name"}, "upsertSubdomainCypher matches the parent Domain by scope+name"},
	// applicationFindingsCypher (internal/platform/component/lifecycle_reads.go):
	// WHERE f.status IN $statuses over (f:Finding)-[:AFFECTS]->(place).
	{"Finding", []string{"status"}, "applicationFindingsCypher filters Findings by status"},
}

// schemaStatement is one statement of the tenant schema. Neo4j DDL takes no
// parameter for a label or a property, so a statement holds their text, the
// one place in the projector where Cypher holds a name (ADR-0112). A
// statement that is not a constant comes only from ddlUniqueConstraint or
// ddlIndex, which refuse a label or a property that is not a plain
// identifier. The gibsoncheck analyzer projectorcypher keeps it so.
type schemaStatement string

// validSchemaNames refuses a label or a property that is not a plain
// identifier, so no other text reaches a statement.
func validSchemaNames(label string, props []string) error {
	if err := taxonomy.ValidIdentifier(label); err != nil {
		return fmt.Errorf("schema label %q: %w", label, err)
	}
	for _, p := range props {
		if err := taxonomy.ValidIdentifier(p); err != nil {
			return fmt.Errorf("schema property %q of %s: %w", p, label, err)
		}
	}
	return nil
}

// ddlUniqueConstraint is the uniqueness constraint on prop of label.
func ddlUniqueConstraint(label, prop string) (schemaStatement, error) {
	if err := validSchemaNames(label, []string{prop}); err != nil {
		return "", err
	}
	return schemaStatement(fmt.Sprintf(
		"CREATE CONSTRAINT %s IF NOT EXISTS FOR (n:%s) REQUIRE n.%s IS UNIQUE",
		schemaIdent(label, []string{prop})+"_unique", label, prop)), nil
}

// ddlIndex is the index on props of label.
func ddlIndex(label string, props []string) (schemaStatement, error) {
	if err := validSchemaNames(label, props); err != nil {
		return "", err
	}
	return schemaStatement(fmt.Sprintf(
		"CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (%s)",
		schemaIdent(label, props), label, propList(props))), nil
}

func schemaIdent(label string, props []string) string {
	return "gibson_" + strings.ToLower(label) + "_" + strings.Join(props, "_")
}

func propList(props []string) string {
	parts := make([]string, len(props))
	for i, p := range props {
		parts[i] = "n." + p
	}
	return strings.Join(parts, ", ")
}

// constraintStatements returns one DDL statement per label of reg: a uniqueness
// constraint on the label's identity, or a composite index when the identity is
// composite. Labels are PascalCase exactly as the projector writes them. Neo4j
// labels are case sensitive, so a lower-case label constrains no node.
func constraintStatements(reg *taxonomy.Registry) ([]schemaStatement, error) {
	labels := reg.NodeLabels()
	sort.Strings(labels)
	out := make([]schemaStatement, 0, len(labels))
	for _, label := range labels {
		id := identityForLabel(label)
		var stmt schemaStatement
		var err error
		if id.unique {
			stmt, err = ddlUniqueConstraint(label, id.props[0])
		} else {
			stmt, err = ddlIndex(label, id.props)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, stmt)
	}
	return out, nil
}

// indexStatements returns the lookup index DDL.
func indexStatements() ([]schemaStatement, error) {
	out := make([]schemaStatement, 0, len(lookupIndexes))
	for _, ix := range lookupIndexes {
		stmt, err := ddlIndex(ix.label, ix.props)
		if err != nil {
			return nil, err
		}
		out = append(out, stmt)
	}
	return out, nil
}

// versionConstraint keeps the :_SchemaVersion node a singleton under
// concurrent first touches from more than one daemon replica.
const versionConstraint schemaStatement = "CREATE CONSTRAINT gibson_schemaversion_name_unique IF NOT EXISTS FOR (n:" +
	schemaVersionLabel + ") REQUIRE n.name IS UNIQUE"

// versionCypher records the taxonomy version. The property shape matches what
// cmd/gibson-migrate wrote and the tenant operator reads.
const versionCypher schemaStatement = "MERGE (v:" + schemaVersionLabel +
	" {name: $name}) SET v.version = $version, v.applied_at = datetime()"

// schemaDDL is every statement ensureSchema runs, in order, for reg.
func schemaDDL(reg *taxonomy.Registry) ([]schemaStatement, error) {
	ddl, err := constraintStatements(reg)
	if err != nil {
		return nil, err
	}
	indexes, err := indexStatements()
	if err != nil {
		return nil, err
	}
	ddl = append(ddl, indexes...)
	return append(ddl, versionConstraint), nil
}

// cypherExec runs one statement in its own transaction. DDL cannot share a
// transaction with a data write, and Neo4j allows one schema change per
// transaction.
type cypherExec func(ctx context.Context, stmt schemaStatement, params map[string]any) error

// constraintDataViolationCode is the Neo4j code of a constraint that cannot be
// created because the data already violates it, for example two nodes with one
// identity.
const constraintDataViolationCode = "Neo.ClientError.Schema.ConstraintCreationFailed"

// isConstraintDataViolation reports whether err is a constraint creation that
// failed for a data reason. The same statement fails again until a person
// changes the data, so a retry is a loop.
func isConstraintDataViolation(err error) bool {
	var nerr *neo4j.Neo4jError
	return errors.As(err, &nerr) && nerr.Code == constraintDataViolationCode
}

// schemaBlockedError reports the statements that the data of the tenant
// violates. Each entry holds the statement and the text of Neo4j, which names
// the duplicate nodes.
type schemaBlockedError struct {
	violations []string
}

func (e *schemaBlockedError) Error() string {
	return "graph schema blocked by the tenant data: " + strings.Join(e.violations, "; ")
}

// applySchema runs the schema DDL for reg and then records the version. Every
// statement is IF NOT EXISTS or a MERGE, so running it again is safe.
//
// A constraint that the data violates does not stop the other statements. When
// one or more fail for that reason, applySchema records no version and returns
// a *schemaBlockedError that names each one (gibson#487).
func applySchema(ctx context.Context, reg *taxonomy.Registry, run cypherExec) error {
	ddl, err := schemaDDL(reg)
	if err != nil {
		return fmt.Errorf("build schema: %w", err)
	}
	var blocked []string
	for _, stmt := range ddl {
		if err := run(ctx, stmt, nil); err != nil {
			if isConstraintDataViolation(err) {
				blocked = append(blocked, fmt.Sprintf("%s: %v", stmt, err))
				continue
			}
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	if len(blocked) > 0 {
		return &schemaBlockedError{violations: blocked}
	}
	if err := run(ctx, versionCypher, map[string]any{
		"name":    schemaVersionName,
		"version": int64(reg.Version()),
	}); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	return nil
}

// sessionExec adapts a tenant session to cypherExec.
func sessionExec(sess neo4j.SessionWithContext) cypherExec {
	return func(ctx context.Context, stmt schemaStatement, params map[string]any) error {
		_, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			res, txErr := tx.Run(ctx, string(stmt), params)
			if txErr != nil {
				return nil, fmt.Errorf("run schema statement: %w", txErr)
			}
			summary, consumeErr := res.Consume(ctx)
			if consumeErr != nil {
				return nil, fmt.Errorf("consume schema statement result: %w", consumeErr)
			}
			return summary, nil
		})
		if err != nil {
			return fmt.Errorf("apply schema statement: %w", err)
		}
		return nil
	}
}

// graphSchemaBlocked is 1 for a tenant whose graph data violates a schema
// constraint, and 0 after the schema applies. An operator reads it without the
// daemon log (gibson#487).
var graphSchemaBlocked = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gibson_graph_schema_blocked",
	Help: "1 when the graph data of the tenant violates a schema constraint, so the constraint is missing.",
}, []string{"tenant"})

// schemaTracker remembers which tenants have had their schema ensured, so the
// DDL does not run on every projection tick. Each tenant has its own lock: two
// concurrent first touches for one tenant serialize, and the second sees the
// first's result.
//
// A transient failure is not remembered, so the next write retries. A failure
// for a data reason is remembered: the tenant is blocked, the gauge reports it
// once, and the DDL does not run again until invalidate. Writes continue
// without the missing constraint, because the projection is still correct
// data and stopping it hides more than it protects.
type schemaTracker struct {
	mu      sync.Mutex
	tenants map[string]*tenantSchema
}

type tenantSchema struct {
	mu      sync.Mutex
	done    bool
	blocked *schemaBlockedError
}

func (t *schemaTracker) entry(tenant string) *tenantSchema {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tenants == nil {
		t.tenants = make(map[string]*tenantSchema)
	}
	e, ok := t.tenants[tenant]
	if !ok {
		e = &tenantSchema{}
		t.tenants[tenant] = e
	}
	return e
}

// ensure runs apply once per tenant. It returns nil without calling apply when
// an earlier call already succeeded or found the tenant blocked.
func (t *schemaTracker) ensure(tenant string, apply func() error) error {
	e := t.entry(tenant)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done || e.blocked != nil {
		return nil
	}
	err := apply()
	var blocked *schemaBlockedError
	if errors.As(err, &blocked) {
		e.blocked = blocked
		graphSchemaBlocked.WithLabelValues(tenant).Set(1)
		slog.Warn("graph projector: the tenant graph data violates the schema, so a constraint is missing",
			"tenant", tenant, "error", blocked.Error())
		return nil
	}
	if err != nil {
		return err
	}
	e.done = true
	graphSchemaBlocked.WithLabelValues(tenant).Set(0)
	return nil
}

// ensureSchema prepares the tenant's graph for its first projection write.
func (w *neo4jGraphWriter) ensureSchema(ctx context.Context, tenant string, sess neo4j.SessionWithContext) error {
	return w.schema.ensure(tenant, func() error {
		if err := applySchema(ctx, taxonomy.Global, sessionExec(sess)); err != nil {
			return fmt.Errorf("graph projector: ensure schema for %s: %w", tenant, err)
		}
		return nil
	})
}

// invalidate forgets that every tenant's schema was ensured, so the next
// projection tick runs the DDL again.
//
// It is called when a node label is promoted at run time. A promoted label needs
// a uniqueness constraint it did not have when the DDL last ran, and the tracker
// exists precisely to stop the DDL running again — so without this, a promoted
// label never gets its constraint on a daemon that has already projected once,
// and the duplicate-node defect the constraint prevents is back for that label.
//
// Every tenant, not the promoting one: promotion is process-wide
// (taxonomy.promotedIdentities is a package global and the registry does not vary
// by tenant), so the label becomes writable in every tenant's graph at once.
//
// The DDL is idempotent — every statement is IF NOT EXISTS — so re-running it
// costs one round trip per tenant that writes again, and nothing else. A
// blocked tenant is cleared too, so its DDL runs one more time.
func (t *schemaTracker) invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.tenants {
		e.mu.Lock()
		e.done = false
		e.blocked = nil
		e.mu.Unlock()
	}
}
