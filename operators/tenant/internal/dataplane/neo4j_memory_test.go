// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// TestNeo4jMemoryEnv_PinsHeapAndPageCacheInsideTheLimit pins the rule that
// the per-tenant Neo4j never sizes its own memory. Left unset, Neo4j computes
// heap and page cache from DETECTED memory, and inside a kind node on a
// GitHub-hosted runner that detection lies: the computed sizes exceeded the
// container limit, every start failed with "Invalid memory configuration -
// exceeds physical memory", the data plane stayed Failed, and the Tenant CR
// never reached Ready (deploy#1766).
//
// The env values must fit the tier limit with more than half left for JVM
// native overhead and APOC, on every tier.
func TestNeo4jMemoryEnv_PinsHeapAndPageCacheInsideTheLimit(t *testing.T) {
	for _, tier := range []string{"team", "org", "enterprise"} {
		_, _, mem := tierDefaults(tier)
		env := neo4jMemoryEnv(mem)
		if len(env) != 3 {
			t.Fatalf("tier %s: want 3 memory env vars, got %d", tier, len(env))
		}
		byName := map[string]string{}
		for _, e := range env {
			byName[e.Name] = e.Value
		}
		for _, setting := range []string{
			"server.memory.heap.initial_size",
			"server.memory.heap.max_size",
			"server.memory.pagecache.size",
		} {
			name := pdataplane.Neo4jSettingEnvVar(setting)
			if byName[name] == "" {
				t.Fatalf("tier %s: env %s (setting %s) is missing or empty", tier, name, setting)
			}
		}
		limitQ := resource.MustParse(mem)
		limit := limitQ.Value()
		heap := mustNeo4jBytes(t, byName[pdataplane.Neo4jSettingEnvVar("server.memory.heap.max_size")])
		cache := mustNeo4jBytes(t, byName[pdataplane.Neo4jSettingEnvVar("server.memory.pagecache.size")])
		if heap+cache >= limit/2 {
			t.Fatalf("tier %s: heap(%d)+pagecache(%d) take %d of the %d limit — less than half must be used, the rest is JVM native overhead", tier, heap, cache, heap+cache, limit)
		}
		initialHeap := byName[pdataplane.Neo4jSettingEnvVar("server.memory.heap.initial_size")]
		maxHeap := byName[pdataplane.Neo4jSettingEnvVar("server.memory.heap.max_size")]
		if initialHeap != maxHeap {
			t.Fatalf("tier %s: initial heap %q must equal max heap %q so the JVM never resizes across the limit", tier, initialHeap, maxHeap)
		}
	}
}

// mustNeo4jBytes parses Neo4j's memory notation ("256m", "1g") into bytes.
func mustNeo4jBytes(t *testing.T, v string) int64 {
	t.Helper()
	last := v[len(v)-1]
	n := v[:len(v)-1]
	q := resource.MustParse(n)
	qv := q.Value()
	switch last {
	case 'm':
		return qv * 1024 * 1024
	case 'g':
		return qv * 1024 * 1024 * 1024
	default:
		t.Fatalf("unexpected Neo4j memory notation %q", v)
		return 0
	}
}
