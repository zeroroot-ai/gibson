// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/migrations"
)

// operatorVersionQuery is the exact query the tenant operator runs to read the
// schema version (operators/tenant/internal/dataplane/migration_versions.go).
// The test below checks the projector writes a node that this query returns.
const operatorVersionQuery = "MATCH (v:_SchemaVersion) RETURN v.version AS version LIMIT 1"

// extendedRegistry is the Global taxonomy plus one label, built test-locally so
// the global registry is never mutated.
func extendedRegistry(t *testing.T, extra string) *taxonomy.Registry {
	t.Helper()
	reg, err := taxonomy.New(taxonomy.Version, append(taxonomy.Global.NodeLabels(), extra), taxonomy.Global.RelationshipTypes())
	if err != nil {
		t.Fatalf("taxonomy.New: %v", err)
	}
	return reg
}

// TestConstraintStatements_CoverEveryTaxonomyLabel is the drift guard: every
// label the taxonomy admits has a constraint or index in the generated set.
func TestConstraintStatements_CoverEveryTaxonomyLabel(t *testing.T) {
	if gaps := constraintGaps(taxonomy.Global, schemaDDL(taxonomy.Global)); len(gaps) > 0 {
		t.Fatalf("taxonomy labels with no constraint or index: %v", gaps)
	}
}

// TestConstraintGaps_FixtureCatchesNewLabel proves the guard can fail. A label
// added to a test-local registry has no statement in a set generated before it
// existed, and the guard must name it. The same registry run through the
// generator must then be clean, so a label added to the taxonomy gets its
// constraint with no second edit.
func TestConstraintGaps_FixtureCatchesNewLabel(t *testing.T) {
	const added = "Zz9Probe"
	reg := extendedRegistry(t, added)

	stale := schemaDDL(taxonomy.Global)
	gaps := constraintGaps(reg, stale)
	if len(gaps) != 1 || gaps[0] != added {
		t.Fatalf("constraintGaps over a stale set = %v, want [%s]", gaps, added)
	}
	if gaps := constraintGaps(reg, schemaDDL(reg)); len(gaps) != 0 {
		t.Fatalf("generated set for the extended registry still has gaps: %v", gaps)
	}
}

// TestConstraintStatements_KeyedOnProjectorIdentity asserts the property each
// constraint is keyed on is the property the projector MERGEs on.
func TestConstraintStatements_KeyedOnProjectorIdentity(t *testing.T) {
	want := map[string]string{
		"Host":          "(n:Host) REQUIRE n.brain_id IS UNIQUE",
		"Finding":       "(n:Finding) REQUIRE n.brain_id IS UNIQUE",
		"Domain":        "(n:Domain) REQUIRE n.brain_id IS UNIQUE",
		"AgentRun":      "(n:AgentRun) REQUIRE n.brain_id IS UNIQUE",
		"Mission":       "(n:Mission) REQUIRE n.id IS UNIQUE",
		"Observation":   "(n:Observation) REQUIRE n.event_id IS UNIQUE",
		"Vulnerability": "(n:Vulnerability) REQUIRE n.key IS UNIQUE",
		"Port":          "(n:Port) ON (n.brain_host_id, n.number)",
		"Service":       "(n:Service) ON (n.brain_host_id, n.port)",
	}
	ddl := strings.Join(constraintStatements(taxonomy.Global), "\n")
	for label, frag := range want {
		if !strings.Contains(ddl, frag) {
			t.Errorf("%s: generated DDL lacks %q", label, frag)
		}
	}
}

// TestSchemaDDL_PascalCaseNotLegacyLowercase is the regression for the defect:
// the deleted migration constrained :mission, :finding and :host, which match
// no node because Neo4j labels are case sensitive.
func TestSchemaDDL_PascalCaseNotLegacyLowercase(t *testing.T) {
	ddl := strings.Join(schemaDDL(taxonomy.Global), "\n")
	for _, legacy := range []string{":mission", ":finding", ":host", ":port", ":service", ":domain"} {
		if strings.Contains(ddl, legacy) {
			t.Errorf("DDL contains lower-case label %q", legacy)
		}
	}
	for _, label := range taxonomy.Global.NodeLabels() {
		if !strings.Contains(ddl, "(n:"+label+")") {
			t.Errorf("DDL does not mention label %s in PascalCase", label)
		}
	}
}

// TestLookupIndexes_NameTheirQuery stops an index from being added without a
// stated reason, and checks each named query still filters on those properties.
func TestLookupIndexes_NameTheirQuery(t *testing.T) {
	queries := map[string]string{
		"Host":    upsertFindingCypher + upsertSubdomainCypher,
		"Domain":  upsertSubdomainCypher,
		"Finding": "f.status IN $statuses", // internal/platform/component/lifecycle_reads.go
	}
	for _, ix := range lookupIndexes {
		if strings.TrimSpace(ix.why) == "" {
			t.Errorf("index on %s%v has no justification", ix.label, ix.props)
		}
		q := queries[ix.label]
		if q == "" {
			t.Errorf("index on %s%v names no query", ix.label, ix.props)
			continue
		}
		for _, p := range ix.props {
			if !strings.Contains(q, p) {
				t.Errorf("index on %s.%s: the query it claims to serve does not use %q", ix.label, p, p)
			}
		}
	}
}

// fakeStore behaves like Neo4j for the statements ensureSchema issues: a
// CREATE without IF NOT EXISTS fails when the object exists, as it does there.
type fakeStore struct {
	mu      sync.Mutex
	created map[string]bool
	log     []string
	version map[string]any
	delay   time.Duration
	failOn  string
}

func newFakeStore() *fakeStore { return &fakeStore{created: map[string]bool{}} }

var ddlName = regexp.MustCompile(`^CREATE (?:CONSTRAINT|INDEX) (\S+)`)

func (f *fakeStore) run(_ context.Context, cypher string, params map[string]any) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && strings.Contains(cypher, f.failOn) {
		return errors.New("simulated failure")
	}
	f.log = append(f.log, cypher)
	if m := ddlName.FindStringSubmatch(cypher); m != nil {
		if f.created[m[1]] && !strings.Contains(cypher, "IF NOT EXISTS") {
			return fmt.Errorf("already exists: %s", m[1])
		}
		f.created[m[1]] = true
		return nil
	}
	if strings.Contains(cypher, "_SchemaVersion") {
		f.version = params
	}
	return nil
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.log)
}

func TestApplySchema_Idempotent(t *testing.T) {
	store := newFakeStore()
	for i := 0; i < 2; i++ {
		if err := applySchema(context.Background(), taxonomy.Global, store.run); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	if want := 2 * (len(schemaDDL(taxonomy.Global)) + 1); store.count() != want {
		t.Fatalf("issued %d statements over two runs, want %d", store.count(), want)
	}
}

func TestApplySchema_RecordsVersionInOperatorShape(t *testing.T) {
	store := newFakeStore()
	if err := applySchema(context.Background(), taxonomy.Global, store.run); err != nil {
		t.Fatal(err)
	}
	// The operator type-switches on int64 and float64 only. A string or int
	// reads as 0.
	v, ok := store.version["version"].(int64)
	if !ok {
		t.Fatalf("version param is %T, the operator reader accepts int64", store.version["version"])
	}
	if v != int64(taxonomy.Version) {
		t.Fatalf("version = %d, want taxonomy.Version %d", v, taxonomy.Version)
	}
	// The write must target the node and property the operator's query reads.
	if !strings.Contains(operatorVersionQuery, "(v:"+schemaVersionLabel+")") ||
		!strings.Contains(operatorVersionQuery, "v.version") {
		t.Fatalf("operator query drifted: %s", operatorVersionQuery)
	}
	if !strings.Contains(versionCypher, "(v:"+schemaVersionLabel+" ") || !strings.Contains(versionCypher, "SET v.version = $version") {
		t.Fatalf("version write does not set v.version on :%s: %s", schemaVersionLabel, versionCypher)
	}
}

// TestNeo4jSchemaVersionMatchesTaxonomy keeps the operator-visible expected
// version in step with the taxonomy. The migrations package cannot import the
// taxonomy, so this test is the link.
func TestNeo4jSchemaVersionMatchesTaxonomy(t *testing.T) {
	got, err := migrations.LatestNeo4jVersion()
	if err != nil {
		t.Fatal(err)
	}
	if int(got) != taxonomy.Version {
		t.Fatalf("migrations.Neo4jSchemaVersion = %d, taxonomy.Version = %d: bump both together", got, taxonomy.Version)
	}
}

func TestSchemaTracker_ConcurrentFirstTouchRunsOnce(t *testing.T) {
	var tr schemaTracker
	store := newFakeStore()
	store.delay = time.Millisecond
	var applied atomic.Int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := tr.ensure("acme", func() error {
				applied.Add(1)
				return applySchema(context.Background(), taxonomy.Global, store.run)
			})
			if err != nil {
				t.Errorf("ensure: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if applied.Load() != 1 {
		t.Fatalf("schema applied %d times for one tenant, want 1", applied.Load())
	}
	if want := len(schemaDDL(taxonomy.Global)) + 1; store.count() != want {
		t.Fatalf("issued %d statements, want %d", store.count(), want)
	}
}

func TestSchemaTracker_FailureIsRetriedAndTenantsAreIndependent(t *testing.T) {
	var tr schemaTracker
	store := newFakeStore()
	store.failOn = "_SchemaVersion {name"

	if err := tr.ensure("acme", func() error { return applySchema(context.Background(), taxonomy.Global, store.run) }); err == nil {
		t.Fatal("expected the failure to surface")
	}
	store.mu.Lock()
	store.failOn = ""
	store.mu.Unlock()

	var calls int
	apply := func() error { calls++; return applySchema(context.Background(), taxonomy.Global, store.run) }
	if err := tr.ensure("acme", apply); err != nil || calls != 1 {
		t.Fatalf("retry after failure: err=%v calls=%d, want nil and 1", err, calls)
	}
	if err := tr.ensure("acme", apply); err != nil || calls != 1 {
		t.Fatalf("second call after success re-ran apply: err=%v calls=%d", err, calls)
	}
	if err := tr.ensure("globex", apply); err != nil || calls != 2 {
		t.Fatalf("a second tenant must run its own ensure: err=%v calls=%d", err, calls)
	}
}

// recordingSession runs each transaction against a fake ManagedTransaction and
// records the Cypher text, so the writer's ordering can be observed.
type recordingSession struct {
	neo4j.SessionWithContext
	mu  sync.Mutex
	log []string
}

type recordingTx struct {
	neo4j.ManagedTransaction
	s *recordingSession
}

type consumeResult struct{ neo4j.ResultWithContext }

func (consumeResult) Consume(context.Context) (neo4j.ResultSummary, error) { return nil, nil }

func (t recordingTx) Run(_ context.Context, cypher string, _ map[string]any) (neo4j.ResultWithContext, error) {
	t.s.mu.Lock()
	t.s.log = append(t.s.log, cypher)
	t.s.mu.Unlock()
	return consumeResult{}, nil
}

func (s *recordingSession) ExecuteWrite(_ context.Context, work neo4j.ManagedTransactionWork, _ ...func(*neo4j.TransactionConfig)) (any, error) {
	return work(recordingTx{s: s})
}

func (*recordingSession) Close(context.Context) error { return nil }

// TestNeo4jGraphWriter_EnsuresSchemaOnceBeforeFirstWrite drives the real
// writer: the first projection for a tenant issues the schema before the data
// write, and the second issues only the data write.
func TestNeo4jGraphWriter_EnsuresSchemaOnceBeforeFirstWrite(t *testing.T) {
	sess := &recordingSession{}
	pool := &mockPool{conn: &datapool.Conn{Neo4j: sess}}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	for i := 0; i < 2; i++ {
		if err := w.UpsertMission(context.Background(), "acme", MissionProjection{ID: "m1"}); err != nil {
			t.Fatalf("UpsertMission %d: %v", i+1, err)
		}
	}

	ddl := len(schemaDDL(taxonomy.Global)) + 1 // plus the version write
	if want := ddl + 2; len(sess.log) != want {
		t.Fatalf("issued %d statements, want %d (schema once, two data writes)", len(sess.log), want)
	}
	if !strings.HasPrefix(sess.log[0], "CREATE") {
		t.Errorf("first statement is %q, want schema DDL before the first write", sess.log[0])
	}
	if sess.log[ddl] != upsertMissionCypher || sess.log[ddl+1] != upsertMissionCypher {
		t.Errorf("statements after the schema are not the two data writes")
	}
}
