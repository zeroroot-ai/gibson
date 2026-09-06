// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// TestInitOntologyReasoner verifies that the reasoner is constructed, loads
// the core vocabulary, accepts extensions, and is reachable via Infrastructure.
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

	t.Run("reasoner reachable via Infrastructure", func(t *testing.T) {
		infra := &Infrastructure{reasoner: di.reasoner}
		require.NotNil(t, infra.reasoner, "Infrastructure must carry the live reasoner singleton")
		assert.Contains(t, infra.reasoner.Descendants("mitre:TA0002"), "mitre:T1059",
			"the Infrastructure-held reasoner must be the same one extensions registered against")
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
