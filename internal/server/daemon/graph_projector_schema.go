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
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
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
func identityForLabel(label string) labelIdentity {
	switch label {
	case "Port":
		return labelIdentity{props: []string{"brain_host_id", "number"}}
	case "Service":
		return labelIdentity{props: []string{"brain_host_id", "port"}}
	case "Mission":
		return labelIdentity{props: []string{"id"}, unique: true}
	}
	// This MUST mirror entityIdentity in graph_projector_neo4j.go. The schema
	// constrains the property the projector merges on; if the two disagree the
	// constraint covers no node the projector writes, which is the defect this
	// file exists to fix, inverted.
	//
	// So a runtime-promoted label (taxonomy discovery, gibson#484/#489) is keyed
	// on brain_id by REGISTERING it in entityIdentityProperty, never by
	// defaulting here: a default that said brain_id while the projector still
	// merged on key would recreate exactly that mismatch.
	prop := entityIdentityProperty[label]
	if prop == "" {
		prop = "key"
	}
	return labelIdentity{props: []string{prop}, unique: true}
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
func constraintStatements(reg *taxonomy.Registry) []string {
	labels := reg.NodeLabels()
	sort.Strings(labels)
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		id := identityForLabel(label)
		if id.unique {
			out = append(out, fmt.Sprintf(
				"CREATE CONSTRAINT %s IF NOT EXISTS FOR (n:%s) REQUIRE n.%s IS UNIQUE",
				schemaIdent(label, id.props)+"_unique", label, id.props[0]))
			continue
		}
		out = append(out, fmt.Sprintf(
			"CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (%s)",
			schemaIdent(label, id.props), label, propList(id.props)))
	}
	return out
}

// indexStatements returns the lookup index DDL.
func indexStatements() []string {
	out := make([]string, 0, len(lookupIndexes))
	for _, ix := range lookupIndexes {
		out = append(out, fmt.Sprintf(
			"CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (%s)",
			schemaIdent(ix.label, ix.props), ix.label, propList(ix.props)))
	}
	return out
}

// versionConstraint keeps the :_SchemaVersion node a singleton under
// concurrent first touches from more than one daemon replica.
var versionConstraint = fmt.Sprintf(
	"CREATE CONSTRAINT gibson_schemaversion_name_unique IF NOT EXISTS FOR (n:%s) REQUIRE n.name IS UNIQUE",
	schemaVersionLabel)

// versionCypher records the taxonomy version. The property shape matches what
// cmd/gibson-migrate wrote and the tenant operator reads.
var versionCypher = fmt.Sprintf(
	"MERGE (v:%s {name: $name}) SET v.version = $version, v.applied_at = datetime()",
	schemaVersionLabel)

// schemaDDL is every statement ensureSchema runs, in order, for reg.
func schemaDDL(reg *taxonomy.Registry) []string {
	ddl := constraintStatements(reg)
	ddl = append(ddl, indexStatements()...)
	return append(ddl, versionConstraint)
}

// cypherExec runs one statement in its own transaction. DDL cannot share a
// transaction with a data write, and Neo4j allows one schema change per
// transaction.
type cypherExec func(ctx context.Context, cypher string, params map[string]any) error

// applySchema runs the schema DDL for reg and then records the version. Every
// statement is IF NOT EXISTS or a MERGE, so running it again is safe.
func applySchema(ctx context.Context, reg *taxonomy.Registry, run cypherExec) error {
	for _, stmt := range schemaDDL(reg) {
		if err := run(ctx, stmt, nil); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
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
	return func(ctx context.Context, cypher string, params map[string]any) error {
		_, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			res, txErr := tx.Run(ctx, cypher, params)
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

// schemaTracker remembers which tenants have had their schema ensured, so the
// DDL does not run on every projection tick. Each tenant has its own lock: two
// concurrent first touches for one tenant serialize, and the second sees the
// first's result. A failure is not remembered, so the next write retries.
type schemaTracker struct {
	mu      sync.Mutex
	tenants map[string]*tenantSchema
}

type tenantSchema struct {
	mu   sync.Mutex
	done bool
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
// an earlier call already succeeded.
func (t *schemaTracker) ensure(tenant string, apply func() error) error {
	e := t.entry(tenant)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done {
		return nil
	}
	if err := apply(); err != nil {
		return err
	}
	e.done = true
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
