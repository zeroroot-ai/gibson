// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
	dataplaneclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
	"github.com/zeroroot-ai/sdk/auth"
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

// nopVault is a Vault admin client that the constructors accept. The test
// never provisions, so no method is called.
type nopVault struct{ vaultadmin.AdminClient }

// nopKEK is a KEK deriver that the constructors accept.
type nopKEK struct{}

func (nopKEK) DeriveTenantKEK(context.Context, auth.TenantID) ([]byte, error) { return nil, nil }

// With every store, the builder returns the pipeline.
func TestBuildStorePipeline_BuildsThePipeline(t *testing.T) {
	scheme := runtime.NewScheme()
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	pg, err := dataplane.NewPostgresProvisioner(dataplane.PostgresConfig{AdminDSN: "postgres://nobody@127.0.0.1:1/postgres", KEKDeriver: nopKEK{}, VaultClient: nopVault{}})
	if err != nil {
		t.Fatal(err)
	}
	n4j, err := dataplane.NewNeo4jProvisioner(dataplane.Neo4jConfig{
		K8sClient: dataplaneclient.New(k8s, "gibson"), VaultClient: nopVault{},
		Image: "ghcr.io/zeroroot-ai/mirror/neo4j:5.26.0-community@sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := dataplane.PipelineConfig{Postgres: pg, Neo4j: n4j, K8sClient: k8s, Recorder: events.NewFakeRecorder(10)}
	p, err := buildStorePipeline(cfg, envOf(map[string]string{"DATAPLANE_REDIS_ADDR": "127.0.0.1:1"}), nopVault{}, nopKEK{})
	if err != nil || p == nil {
		t.Fatalf("buildStorePipeline = %v, %v", p, err)
	}
}
