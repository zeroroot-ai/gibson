// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// Without DATAPLANE_REDIS_ADDR the operator does not start (gibson#681).
func TestBuildStorePipeline_RequiresTheRedisAddress(t *testing.T) {
	_, err := buildStorePipeline(dataplane.PipelineConfig{}, envOf(nil), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "DATAPLANE_REDIS_ADDR") {
		t.Fatalf("err = %v, want the DATAPLANE_REDIS_ADDR error", err)
	}
}

// With the Redis address, the builder adds the Redis, vector and KEK steps.
// The pipeline still refuses the stores that the caller did not give it.
func TestBuildStorePipeline_AddsTheRedisSteps(t *testing.T) {
	_, err := buildStorePipeline(dataplane.PipelineConfig{}, envOf(map[string]string{"DATAPLANE_REDIS_ADDR": "127.0.0.1:1"}), nil, nil)
	if err == nil {
		t.Fatal("a pipeline with no Postgres and no Neo4j was built")
	}
	for _, name := range []string{"Redis", "Vector", "KEK"} {
		if strings.Contains(err.Error(), name) && !strings.Contains(err.Error(), "provisioner") {
			t.Errorf("the pipeline still needs %s: %v", name, err)
		}
	}
	if !strings.Contains(err.Error(), "Postgres") {
		t.Errorf("err = %v, want the missing Postgres named", err)
	}
}
