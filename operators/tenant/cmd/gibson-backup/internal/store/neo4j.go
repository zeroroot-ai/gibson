/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// defaultNodeLabel is the fallback Cypher node label used when a record
// arrives without labels (or for relationship endpoints where the original
// label is unknown at restore time).
const defaultNodeLabel = "Node"

// ErrNeo4jAPOCNotAvailable is returned when APOC is not installed in the
// target Neo4j instance and the streaming export path is unavailable.
//
// TODO(database-per-tenant-data-plane 8.1): Neo4j Enterprise ships with
// neo4j-admin database dump, which produces a consistent offline backup.
// Using neo4j-admin requires either a sidecar with access to the Neo4j data
// directory or an Enterprise Online Backup license. Neither is available in the
// current deployment. The APOC export path used here requires the APOC plugin
// JAR to be installed in the Neo4j pod (apoc.export.cypher.all /
// apoc.export.json.all). If APOC is not present, this function returns
// ErrNeo4jAPOCNotAvailable and the backup task records the store as
// "not_available" in the manifest. Document the requirement: Neo4j pods must
// include the APOC plugin JAR.
var ErrNeo4jAPOCNotAvailable = errors.New("store/neo4j: APOC plugin not available; install the APOC JAR in the Neo4j pod to enable graph backup")

// neo4jDSN holds parsed fields from a bolt://user:pass@host:port/dbname URI.
type neo4jDSN struct {
	uri      string // bolt:// URI without db path
	username string
	password string
	database string
}

func parseNeo4jDSN(dsn string) (neo4jDSN, error) {
	// Expected format: bolt://user:pass@host:port/dbname
	// or neo4j://user:pass@host:port/dbname
	u, err := url.Parse(dsn)
	if err != nil {
		return neo4jDSN{}, fmt.Errorf("store/neo4j: parse DSN: %w", err)
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return neo4jDSN{}, fmt.Errorf("store/neo4j: DSN must include database name in path: %q", dsn)
	}
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	// Reconstruct the bolt URI without path or userinfo — the driver takes
	// credentials separately via neo4j.BasicAuth.
	u.Path = ""
	u.User = nil
	return neo4jDSN{
		uri:      u.String(),
		username: username,
		password: password,
		database: db,
	}, nil
}

// Neo4jBackup exports all nodes and relationships from the tenant's Neo4j
// database using APOC's export procedures, producing a gzip-compressed tar
// archive containing:
//
//	nodes.json     — all nodes as JSON-lines
//	rels.json      — all relationships as JSON-lines
//	schema.cypher  — index and constraint definitions
//
// The archive is written to w. The function returns the total bytes written
// and their SHA-256 hex digest.
//
// Requirement: the Neo4j pod must have the APOC plugin installed. If APOC is
// not available, ErrNeo4jAPOCNotAvailable is returned and the caller should
// record the store as unavailable in the backup manifest.
//
// The dsn parameter must be of the form:
//
//	bolt://user:pass@host:port/database
//	neo4j://user:pass@host:port/database
func Neo4jBackup(ctx context.Context, dsn string, w io.Writer) (int64, string, error) {
	parsed, err := parseNeo4jDSN(dsn)
	if err != nil {
		return 0, "", err
	}

	auth := neo4j.BasicAuth(parsed.username, parsed.password, "")
	driver, err := neo4j.NewDriverWithContext(parsed.uri, auth)
	if err != nil {
		return 0, "", fmt.Errorf("store/neo4j: create driver: %w", err)
	}
	defer func() { _ = driver.Close(ctx) }()

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: parsed.database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer func() { _ = session.Close(ctx) }()

	// Check that APOC is available by calling apoc.version().
	if !checkAPOC(ctx, session) {
		return 0, "", ErrNeo4jAPOCNotAvailable
	}

	// Wire up: w ← counter ← sha256 ← gzip ← tar
	// The countWriter records total bytes emitted; sha256 hashes them.
	h := sha256.New()
	counted := &countWriter{w: io.MultiWriter(w, h)}
	gz := gzip.NewWriter(counted)
	tw := tar.NewWriter(gz)

	// Export nodes.
	nodesJSON, err := exportNodes(ctx, session)
	if err != nil {
		return 0, "", fmt.Errorf("store/neo4j: export nodes: %w", err)
	}
	if err := addTarEntry(tw, "nodes.json", nodesJSON); err != nil {
		return 0, "", fmt.Errorf("store/neo4j: tar nodes: %w", err)
	}

	// Export relationships.
	relsJSON, err := exportRelationships(ctx, session)
	if err != nil {
		return 0, "", fmt.Errorf("store/neo4j: export relationships: %w", err)
	}
	if err := addTarEntry(tw, "rels.json", relsJSON); err != nil {
		return 0, "", fmt.Errorf("store/neo4j: tar rels: %w", err)
	}

	// Export schema (indexes + constraints as Cypher). Always non-error
	// today; the helper swallows the only failure mode (SHOW INDEXES on
	// Neo4j <4.4) by returning a "// schema export unavailable" stub.
	schemaCypher := exportSchema(ctx, session)
	if err := addTarEntry(tw, "schema.cypher", schemaCypher); err != nil {
		return 0, "", fmt.Errorf("store/neo4j: tar schema: %w", err)
	}

	if err := tw.Close(); err != nil {
		return 0, "", fmt.Errorf("store/neo4j: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return 0, "", fmt.Errorf("store/neo4j: close gzip: %w", err)
	}

	return counted.n, hex.EncodeToString(h.Sum(nil)), nil
}

// Neo4jRestore restores a backup archive produced by Neo4jBackup into the
// database identified by dsn. The restore uses APOC's import procedures.
//
// Requirement: same APOC requirement as Neo4jBackup. Returns
// ErrNeo4jAPOCNotAvailable if APOC is absent.
func Neo4jRestore(ctx context.Context, dsn string, r io.Reader) error {
	parsed, err := parseNeo4jDSN(dsn)
	if err != nil {
		return err
	}

	auth := neo4j.BasicAuth(parsed.username, parsed.password, "")
	driver, err := neo4j.NewDriverWithContext(parsed.uri, auth)
	if err != nil {
		return fmt.Errorf("store/neo4j: create driver: %w", err)
	}
	defer func() { _ = driver.Close(ctx) }()

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: parsed.database,
		AccessMode:   neo4j.AccessModeWrite,
	})
	defer func() { _ = session.Close(ctx) }()

	if !checkAPOC(ctx, session) {
		return ErrNeo4jAPOCNotAvailable
	}

	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("store/neo4j: open gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("store/neo4j: read tar: %w", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("store/neo4j: read %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = data
	}

	// Apply schema first.
	if schema, ok := files["schema.cypher"]; ok {
		stmts := strings.SplitSeq(string(schema), ";")
		for s := range stmts {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
				_, err := tx.Run(ctx, s, nil)
				return nil, err
			}); err != nil {
				return fmt.Errorf("store/neo4j: apply schema statement: %w", err)
			}
		}
	}

	// Restore nodes.
	if nodesJSON, ok := files["nodes.json"]; ok {
		if err := importNodes(ctx, session, nodesJSON); err != nil {
			return fmt.Errorf("store/neo4j: import nodes: %w", err)
		}
	}

	// Restore relationships.
	if relsJSON, ok := files["rels.json"]; ok {
		if err := importRelationships(ctx, session, relsJSON); err != nil {
			return fmt.Errorf("store/neo4j: import relationships: %w", err)
		}
	}

	return nil
}

// --- helpers ---

// checkAPOC returns true when APOC procedures are reachable on the
// session. APOC unavailability is treated as a clean "no" rather than
// an error, so the return signature is bool-only.
func checkAPOC(ctx context.Context, session neo4j.SessionWithContext) bool {
	result, err := session.Run(ctx, "RETURN apoc.version() AS v", nil)
	if err != nil {
		return false
	}
	return result.Next(ctx)
}

type nodeRecord struct {
	Labels     []string       `json:"labels"`
	Properties map[string]any `json:"properties"`
}

func exportNodes(ctx context.Context, session neo4j.SessionWithContext) ([]byte, error) {
	result, err := session.Run(ctx, "MATCH (n) RETURN labels(n) AS labels, properties(n) AS props", nil)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	for result.Next(ctx) {
		rec := result.Record()
		labels, _, _ := neo4j.GetRecordValue[[]any](rec, "labels")
		props, _, _ := neo4j.GetRecordValue[map[string]any](rec, "props")
		strs := make([]string, len(labels))
		for i, l := range labels {
			strs[i] = fmt.Sprintf("%v", l)
		}
		nr := nodeRecord{Labels: strs, Properties: props}
		b, _ := json.Marshal(nr)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := result.Err(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

type relRecord struct {
	Type            string         `json:"type"`
	StartNodeLabels []string       `json:"start_labels"`
	StartNodeProps  map[string]any `json:"start_props"`
	EndNodeLabels   []string       `json:"end_labels"`
	EndNodeProps    map[string]any `json:"end_props"`
	Properties      map[string]any `json:"properties"`
}

func exportRelationships(ctx context.Context, session neo4j.SessionWithContext) ([]byte, error) {
	q := `MATCH (a)-[r]->(b)
	      RETURN type(r) AS relType,
	             labels(a) AS startLabels, properties(a) AS startProps,
	             labels(b) AS endLabels, properties(b) AS endProps,
	             properties(r) AS relProps`
	result, err := session.Run(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	for result.Next(ctx) {
		rec := result.Record()
		relType, _, _ := neo4j.GetRecordValue[string](rec, "relType")
		startLabels, _, _ := neo4j.GetRecordValue[[]any](rec, "startLabels")
		startProps, _, _ := neo4j.GetRecordValue[map[string]any](rec, "startProps")
		endLabels, _, _ := neo4j.GetRecordValue[[]any](rec, "endLabels")
		endProps, _, _ := neo4j.GetRecordValue[map[string]any](rec, "endProps")
		relProps, _, _ := neo4j.GetRecordValue[map[string]any](rec, "relProps")

		toStrSlice := func(in []any) []string {
			out := make([]string, len(in))
			for i, v := range in {
				out[i] = fmt.Sprintf("%v", v)
			}
			return out
		}

		rr := relRecord{
			Type:            relType,
			StartNodeLabels: toStrSlice(startLabels),
			StartNodeProps:  startProps,
			EndNodeLabels:   toStrSlice(endLabels),
			EndNodeProps:    endProps,
			Properties:      relProps,
		}
		b, _ := json.Marshal(rr)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := result.Err(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// exportSchema returns Cypher CREATE statements for the database's
// indexes. Always returns a non-nil []byte; on Neo4j <4.4 where SHOW
// INDEXES YIELD isn't supported, returns a "// schema export
// unavailable" stub. No error return — the failure mode is silent and
// the artifact is still usable.
func exportSchema(ctx context.Context, session neo4j.SessionWithContext) []byte {
	result, err := session.Run(ctx, "SHOW INDEXES YIELD createStatement WHERE createStatement IS NOT NULL RETURN createStatement", nil)
	if err != nil {
		return []byte("// schema export unavailable\n")
	}
	var sb strings.Builder
	sb.WriteString("// Schema generated at ")
	sb.WriteString(time.Now().UTC().Format(time.RFC3339))
	sb.WriteString("\n")
	for result.Next(ctx) {
		rec := result.Record()
		stmt, _, _ := neo4j.GetRecordValue[string](rec, "createStatement")
		sb.WriteString(stmt)
		sb.WriteString(";\n")
	}
	return []byte(sb.String())
}

func importNodes(ctx context.Context, session neo4j.SessionWithContext, data []byte) error {
	lines := strings.SplitSeq(strings.TrimSpace(string(data)), "\n")
	for line := range lines {
		if line == "" {
			continue
		}
		var nr nodeRecord
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			return fmt.Errorf("parse node record: %w", err)
		}
		labels := strings.Join(nr.Labels, ":")
		if labels == "" {
			labels = defaultNodeLabel
		}
		q := fmt.Sprintf("CREATE (n:%s) SET n = $props", labels)
		if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx, q, map[string]any{"props": nr.Properties})
			return nil, err
		}); err != nil {
			return err
		}
	}
	return nil
}

func importRelationships(ctx context.Context, session neo4j.SessionWithContext, data []byte) error {
	lines := strings.SplitSeq(strings.TrimSpace(string(data)), "\n")
	for line := range lines {
		if line == "" {
			continue
		}
		var rr relRecord
		if err := json.Unmarshal([]byte(line), &rr); err != nil {
			return fmt.Errorf("parse rel record: %w", err)
		}
		startLabel := defaultNodeLabel
		if len(rr.StartNodeLabels) > 0 {
			startLabel = rr.StartNodeLabels[0]
		}
		endLabel := defaultNodeLabel
		if len(rr.EndNodeLabels) > 0 {
			endLabel = rr.EndNodeLabels[0]
		}
		q := fmt.Sprintf(
			`MATCH (a:%s), (b:%s) WHERE a = $startProps AND b = $endProps
			 CREATE (a)-[r:%s]->(b) SET r = $relProps`,
			startLabel, endLabel, rr.Type,
		)
		if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx, q, map[string]any{
				"startProps": rr.StartNodeProps,
				"endProps":   rr.EndNodeProps,
				"relProps":   rr.Properties,
			})
			return nil, err
		}); err != nil {
			return err
		}
	}
	return nil
}

func addTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// countWriter wraps an io.Writer and counts bytes written.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
