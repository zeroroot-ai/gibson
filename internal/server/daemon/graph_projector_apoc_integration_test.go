// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package daemon

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// Host projection against a real Neo4j provisioned the way the tenant operator
// provisions one (ADR-0012, gibson#1257).
//
// The unit tests next door can only say the label is passed as a parameter.
// Whether Neo4j then treats it as a label NAME rather than as Cypher, and
// whether the allowlist really keeps apoc.export.* out of the database, are
// properties of the server — so they are asserted against the server.
//
// The container is configured from the same constants the operator renders
// into the StatefulSet (pkg/platform/dataplane/apoc.go), so this cannot pass
// against a configuration the operator does not actually produce.

const apocTestPassword = "PtestApocPassword1"

// startProvisionedNeo4j starts a Neo4j configured exactly as a tenant's is:
// APOC Core copied out of the image's labs directory, the merge-only procedure
// allowlist, and no NEO4J_PLUGINS (which would make the entrypoint set
// dbms.security.procedures.unrestricted=apoc.* behind our back).
func startProvisionedNeo4j(t *testing.T, ctx context.Context) neo4j.DriverWithContext {
	t.Helper()

	if _, err := testcontainers.ProviderDocker.GetProvider(); err != nil {
		t.Skipf("Docker unavailable (%v) — skipping; CI runs this in the integration lane", err)
	}

	env := map[string]string{"NEO4J_AUTH": "neo4j/" + apocTestPassword}
	for _, setting := range pdataplane.Neo4jSettingNames() {
		env[pdataplane.Neo4jSettingEnvVar(setting)] = pdataplane.Neo4jSecuritySettings()[setting]
	}

	// The operator installs the jar with an init container writing into a
	// shared emptyDir. A single container has no init container, so the same
	// install command runs ahead of the image's own entrypoint, into the
	// image's default plugins directory.
	install := pdataplane.APOCInstallCommand("/var/lib/neo4j/plugins")

	req := testcontainers.ContainerRequest{
		Image:        "neo4j:5.26-community",
		ExposedPorts: []string{"7687/tcp"},
		Env:          env,
		Entrypoint:   []string{"sh", "-c", install + " && exec /startup/docker-entrypoint.sh neo4j"},
		WaitingFor:   wait.ForLog("Started.").WithStartupTimeout(180 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("start neo4j: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "7687")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	drv, err := neo4j.NewDriverWithContext(
		fmt.Sprintf("bolt://%s:%s", host, port.Port()),
		neo4j.BasicAuth("neo4j", apocTestPassword, ""),
	)
	if err != nil {
		t.Fatalf("neo4j driver: %v", err)
	}
	t.Cleanup(func() { _ = drv.Close(context.Background()) })
	if err := drv.VerifyConnectivity(ctx); err != nil {
		t.Fatalf("neo4j connectivity: %v", err)
	}
	return drv
}

// runWrite executes cypher in a write transaction and returns the records.
func runWrite(t *testing.T, ctx context.Context, drv neo4j.DriverWithContext, cypher string, params map[string]any) []*neo4j.Record {
	t.Helper()
	sess := drv.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer func() { _ = sess.Close(ctx) }()
	out, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		return res.Collect(ctx)
	})
	if err != nil {
		t.Fatalf("write %q: %v", cypher, err)
	}
	return out.([]*neo4j.Record)
}

// TestProvisionedNeo4jLoadsOnlyTheMergeProcedures asks the database itself
// which APOC procedures exist. A widened allowlist, or an accidental
// NEO4J_PLUGINS, changes the answer.
func TestProvisionedNeo4jLoadsOnlyTheMergeProcedures(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	recs := runWrite(t, ctx, drv,
		"SHOW PROCEDURES YIELD name WHERE name STARTS WITH 'apoc' RETURN name ORDER BY name", nil)
	var loaded []string
	for _, r := range recs {
		name, _ := r.Get("name")
		loaded = append(loaded, name.(string))
	}
	want := []string{"apoc.merge.node", "apoc.merge.relationship"}
	sort.Strings(loaded)
	if len(loaded) != len(want) {
		t.Fatalf("APOC procedures registered = %v, want exactly %v", loaded, want)
	}
	for i := range want {
		if loaded[i] != want[i] {
			t.Fatalf("APOC procedures registered = %v, want exactly %v", loaded, want)
		}
	}

	// And the dangerous ones are absent rather than merely unprivileged:
	// calling one is a "no such procedure" error, so there is nothing to
	// escalate into.
	for _, proc := range []string{
		"CALL apoc.export.cypher.all(null,{}) YIELD file RETURN file",
		"CALL apoc.load.json('http://169.254.169.254/latest/meta-data/') YIELD value RETURN value",
		"CALL apoc.cypher.runFile('/etc/passwd')",
	} {
		sess := drv.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
		_, err := sess.Run(ctx, proc, nil)
		if err == nil {
			// Some errors only surface on consume.
			_, err = sess.Run(ctx, proc, nil)
		}
		_ = sess.Close(ctx)
		if err == nil {
			t.Errorf("%s succeeded; the allowlist must keep file and network procedures out of the database", proc)
		}
	}
}

// TestProvisionedNeo4jNeverRunsUnrestricted reads the setting back off the
// live server. This is the assertion that catches NEO4J_PLUGINS='["apoc"]',
// whose only visible symptom is this value silently becoming apoc.*.
func TestProvisionedNeo4jNeverRunsUnrestricted(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	recs := runWrite(t, ctx, drv,
		"SHOW SETTINGS YIELD name, value WHERE name IN "+
			"['dbms.security.procedures.allowlist','dbms.security.procedures.unrestricted'] "+
			"RETURN name, value", nil)
	got := map[string]string{}
	for _, r := range recs {
		name, _ := r.Get("name")
		value, _ := r.Get("value")
		got[name.(string)] = value.(string)
	}
	if got["dbms.security.procedures.unrestricted"] != "" {
		t.Errorf("dbms.security.procedures.unrestricted = %q on the running server, want unset — "+
			"Community has no in-database RBAC, so this grants filesystem and network reach to "+
			"every holder of the bolt credential", got["dbms.security.procedures.unrestricted"])
	}
	if got["dbms.security.procedures.allowlist"] != pdataplane.Neo4jProcedureAllowlist {
		t.Errorf("dbms.security.procedures.allowlist = %q, want %q",
			got["dbms.security.procedures.allowlist"], pdataplane.Neo4jProcedureAllowlist)
	}

	// Built-in procedures are not extensions and keep working; if they ever
	// stopped, the allowlist would have taken the platform down with it.
	if len(runWrite(t, ctx, drv, "CALL dbms.components() YIELD name RETURN name", nil)) == 0 {
		t.Error("built-in dbms.components() returned nothing; the allowlist has caught built-ins")
	}
}

// TestHostProjectionTreatsALabelAsData runs the PRODUCTION query and
// parameters, then replaces the label with one made of Cypher, and asserts the
// server stored it as a label name and executed nothing.
//
// The canary node is the whole test: the injected label is a DETACH DELETE
// over every node in the database, so if the label were interpolated into
// Cypher the canary would be gone.
func TestHostProjectionTreatsALabelAsData(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	runWrite(t, ctx, drv, "CREATE (:Canary {id: 1})", nil)

	host := brain.HostSnapshot{
		ID: 7, ScopeID: "scope-1", Address: "10.0.0.7",
		Belief: brain.Belief{Juicy: 0.5}, Attention: 0.25,
		OpenPorts: []int{443},
		Services:  map[int]brain.ServiceInfo{443: {Name: "https", Protocol: "tcp"}},
	}

	// 1. The real projection, unmodified: it must work on a database
	//    provisioned this way at all.
	runWrite(t, ctx, drv, upsertHostCypher, hostUpsertParams(host))
	recs := runWrite(t, ctx, drv,
		"MATCH (h:Host {brain_id: 7})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service) "+
			"RETURN h.address AS address, p.number AS port, s.name AS service", nil)
	if len(recs) != 1 {
		t.Fatalf("Host/Port/Service projection produced %d rows, want 1", len(recs))
	}
	if addr, _ := recs[0].Get("address"); addr != "10.0.0.7" {
		t.Errorf("projected address = %v, want 10.0.0.7", addr)
	}

	// 2. Idempotent: a second pass converges rather than duplicating.
	runWrite(t, ctx, drv, upsertHostCypher, hostUpsertParams(host))
	countRecs := runWrite(t, ctx, drv, "MATCH (h:Host) RETURN count(h) AS n", nil)
	if n, _ := countRecs[0].Get("n"); n != int64(1) {
		t.Errorf("re-projection produced %v Host nodes, want 1", n)
	}

	// 3. The property under test, run through the production query: a label
	//    made of Cypher is a bad name, not a query.
	//
	//    Note what this label does NOT contain: a backtick. APOC quotes a
	//    label by wrapping it in backticks without escaping any inside it
	//    (apoc.util.Util.quote), so a backtick label escapes the quoting and
	//    the remainder executes. That case is excluded here because the
	//    projector's taxonomy guard rejects it before it can reach a query —
	//    see the loop below, and taxonomyLabels for the detail.
	const injected = "Host; MATCH (n) DETACH DELETE n //"
	params := hostUpsertParams(host)
	params["host_labels"] = []string{injected}
	params["id"] = int64(8)
	runWrite(t, ctx, drv, upsertHostCypher, params)

	labelRecs := runWrite(t, ctx, drv,
		"MATCH (n {brain_id: 8}) RETURN labels(n) AS labels", nil)
	if len(labelRecs) != 1 {
		t.Fatalf("merged %d nodes for the injected label, want 1", len(labelRecs))
	}
	labels, _ := labelRecs[0].Get("labels")
	got, _ := labels.([]any)
	if len(got) != 1 || got[0] != injected {
		t.Errorf("labels = %v, want the literal [%q] — the label must be stored, not executed", got, injected)
	}

	canary := runWrite(t, ctx, drv, "MATCH (c:Canary) RETURN count(c) AS n", nil)
	if n, _ := canary[0].Get("n"); n != int64(1) {
		t.Fatalf("the canary node is gone (count %v): the label was executed as Cypher", n)
	}

	// 4. Every label the projector can actually emit survives the round trip
	//    as a literal label. This is the invariant that matters: the guard
	//    and the procedure together, over the real taxonomy.
	for i, label := range hostLabels {
		p := hostUpsertParams(host)
		p["host_labels"] = []string{label}
		p["id"] = int64(100 + i)
		runWrite(t, ctx, drv, upsertHostCypher, p)

		recs := runWrite(t, ctx, drv,
			"MATCH (n {brain_id: $id}) RETURN labels(n) AS labels", map[string]any{"id": int64(100 + i)})
		if len(recs) != 1 {
			t.Fatalf("taxonomy label %q merged %d nodes, want 1", label, len(recs))
		}
		l, _ := recs[0].Get("labels")
		names, _ := l.([]any)
		if len(names) != 1 || names[0] != label {
			t.Errorf("taxonomy label %q stored as %v", label, names)
		}
	}
	canary = runWrite(t, ctx, drv, "MATCH (c:Canary) RETURN count(c) AS n", nil)
	if n, _ := canary[0].Get("n"); n != int64(1) {
		t.Fatalf("the canary node is gone (count %v) after projecting the real taxonomy", n)
	}
}
