package daemon

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// TestInitOntologyReasoner verifies that the reasoner is constructed and
// usable via the assembled Infrastructure's SemanticQuerier factory.
//
// This is a pure in-process unit test: no Redis, no Neo4j, no Docker.
func TestInitOntologyReasoner(t *testing.T) {
	t.Parallel()

	// Use an isolated registry so tests don't collide with prometheus.DefaultRegisterer.
	reg := prometheus.NewRegistry()

	cfg := minimalCfg()
	d, err := New(cfg, WithMetricsRegisterer(reg))
	require.NoError(t, err)

	di := d.(*daemonImpl)
	ctx := context.Background()

	// --- Step 1: construct reasoner directly via initOntologyReasoner ---
	reasoner, err := di.initOntologyReasoner(ctx)
	require.NoError(t, err, "initOntologyReasoner should not error")
	require.NotNil(t, reasoner, "reasoner must not be nil")
	di.reasoner = reasoner

	t.Run("RegisterExtension/Descendants roundtrip", func(t *testing.T) {
		// Register a minimal extension and verify the descendant expansion works.
		ext := sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"mitre": "https://attack.mitre.org/techniques/"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{Label: "mitre:T1059", SubClassOf: "mitre:TA0002"},
				{Label: "mitre:T1059.001", SubClassOf: "mitre:T1059"},
			},
		}
		require.NoError(t, reasoner.RegisterExtension("test-ext", ext))

		// TA0002 should now include T1059 and T1059.001 as descendants.
		desc := reasoner.Descendants("mitre:TA0002")
		assert.Contains(t, desc, "mitre:T1059", "T1059 should be a descendant of TA0002")
		assert.Contains(t, desc, "mitre:T1059.001", "T1059.001 should be a transitive descendant of TA0002")
	})

	t.Run("SemanticQuerier factory via Infrastructure", func(t *testing.T) {
		// Build the SemanticQuerier factory the same way newInfrastructure does.
		r := di.reasoner
		sqFactory := func(client graph.GraphClient) *graphrag.SemanticQuerier {
			return graphrag.NewSemanticQuerier(client, r)
		}

		infra := &Infrastructure{
			semanticQuerierFactory: sqFactory,
			reasoner:               r,
		}

		// SemanticQuerier() must be non-nil when a client is supplied.
		sq := infra.SemanticQuerier((*graph.SessionGraphClient)(nil))
		require.NotNil(t, sq, "SemanticQuerier must not be nil when factory is wired")
	})

	t.Run("SemanticQuerier returns nil when factory absent", func(t *testing.T) {
		infra := &Infrastructure{} // factory not wired
		sq := infra.SemanticQuerier((*graph.SessionGraphClient)(nil))
		assert.Nil(t, sq, "SemanticQuerier should return nil when factory is not wired")
	})
}

// TestInitOntologyReasoner_DuplicateRegistration verifies that calling
// initOntologyReasoner twice with the same Prometheus registry returns an error
// rather than silently double-registering metrics.
func TestInitOntologyReasoner_DuplicateRegistration(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	cfg := minimalCfg()

	d, err := New(cfg, WithMetricsRegisterer(reg))
	require.NoError(t, err)
	di := d.(*daemonImpl)
	ctx := context.Background()

	_, err = di.initOntologyReasoner(ctx)
	require.NoError(t, err, "first call must succeed")

	_, err = di.initOntologyReasoner(ctx)
	require.Error(t, err, "second call with the same registry must fail (duplicate metric)")
	assert.Contains(t, err.Error(), "ontology: register prometheus metrics")
}
