// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon is the analysistest fixture of the projectorcypher analyzer.
// Its import path ends with internal/server/daemon, and this file name starts
// with graph_projector, so the rule applies here.
package daemon

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const upsertHostCypher = "MERGE (h:Host {brain_id: $id})"

type schemaStatement string

// ddlIndex is a designated constructor: it may make a statement from text.
func ddlIndex(label string) (schemaStatement, error) {
	return schemaStatement(fmt.Sprintf("CREATE INDEX FOR (n:%s) ON (n.id)", label)), nil
}

const versionCypher schemaStatement = "MERGE (v:_SchemaVersion {name: $name})"

type writer struct{ tx neo4j.ManagedTransaction }

// exec forwards its cypher parameter to the driver. Each call of exec is
// checked instead.
func (w *writer) exec(ctx context.Context, cypher string, params map[string]any) error {
	_, err := w.tx.Run(ctx, cypher, params)
	return err
}

func (w *writer) good(ctx context.Context, id string) {
	_ = w.exec(ctx, upsertHostCypher, map[string]any{"id": id})
	_, _ = w.tx.Run(ctx, "MATCH (n) RETURN n", nil)
	_, _ = w.tx.Run(ctx, string(versionCypher), nil)
	stmt, _ := ddlIndex("Host")
	_, _ = w.tx.Run(ctx, string(stmt), nil)
	_, _ = neo4j.ExecuteQuery(ctx, upsertHostCypher, nil)
}

func (w *writer) bad(ctx context.Context, label string) {
	q := fmt.Sprintf("MERGE (n:%s {id: $id})", label)
	_ = w.exec(ctx, q, nil)                                            // want `Cypher text that is not a constant \(q\)`
	_, _ = w.tx.Run(ctx, "MERGE (n:"+label+")", nil)                   // want `Cypher text that is not a constant`
	_, _ = neo4j.ExecuteQuery(ctx, q, nil)                             // want `Cypher text that is not a constant \(q\)`
	_ = schemaStatement(fmt.Sprintf("CREATE INDEX FOR (n:%s)", label)) // want `schemaStatement is made from text that is not a constant`
}
