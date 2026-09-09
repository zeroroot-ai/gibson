// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// TestDeriveNeo4jPassword_NeverStartsWithDash regression-guards
// tenant-operator#67. base64-url's alphabet contains `-`; without the
// leading "P" prefix the Neo4j docker image's entrypoint passes the
// generated password to `neo4j-admin dbms set-initial-password
// "$password"` and a `-`-leading password is parsed as an unknown
// flag, crashlooping the container with
// "Missing required parameter: '<password>'".
//
// 1000 fresh-provision rolls is enough that an underlying regression
// (e.g. someone reverts the "P" prefix) would flake within one run.
func TestDeriveNeo4jPassword_NeverStartsWithDash(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()

	// operatorNamespace="" — the wrapper's guard is permissively disabled
	// for tests that only exercise password derivation; per-tenant-ns
	// assertion behaviour is covered in internal/dataplane/client.
	n := &Neo4jProvisioner{cfg: Neo4jConfig{K8sClient: dpclient.New(k8s, ""), VaultClient: &storeVault{}}}

	for i := range 1000 {
		pw, err := n.deriveNeo4jPassword(context.Background(), "acme", "tenant-acme")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if pw == "" {
			t.Fatalf("iter %d: empty password", i)
		}
		if strings.HasPrefix(pw, "-") {
			t.Fatalf("iter %d: password starts with '-' (would crashloop neo4j-admin): %q", i, pw[:4]+"...")
		}
	}
}

// storeVault answers ReadInfraNeo4jCredentials from a map and nothing
// else: the interface is embedded so the compiler is satisfied and any
// other call panics, which is the point (deriveNeo4jPassword must only
// READ).
type storeVault struct {
	vaultadmin.AdminClient
	creds map[string]pdataplane.Neo4jCredentials
	err   error
}

func (s *storeVault) ReadInfraNeo4jCredentials(_ context.Context, tenantID string) (pdataplane.Neo4jCredentials, bool, error) {
	if s.err != nil {
		return pdataplane.Neo4jCredentials{}, false, s.err
	}
	c, ok := s.creds[tenantID]
	return c, ok, nil
}

// A restore brings the OpenBao volume back and no Secret. The password the
// restored Neo4j data directory was initialised with is the one at
// infra/neo4j, and the operator must use it, never mint a new one
// (hosted run 34377075123, 2026-09-09: every client failed and Neo4j
// rate-limited the user).
func TestDeriveNeo4jPassword_RestoredStoreWinsOverAFreshDraw(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	store := &storeVault{creds: map[string]pdataplane.Neo4jCredentials{"acme": {Username: "neo4j", Password: "PrestoredPassword123"}}}
	n := &Neo4jProvisioner{cfg: Neo4jConfig{K8sClient: dpclient.New(k8s, ""), VaultClient: store}}

	pw, err := n.deriveNeo4jPassword(context.Background(), "acme", "tenant-acme")
	if err != nil {
		t.Fatal(err)
	}
	if pw != "PrestoredPassword123" {
		t.Fatalf("a restored store must supply the password; got %q", pw)
	}

	// Nothing in the store: a fresh draw, argument-safe.
	pw, err = n.deriveNeo4jPassword(context.Background(), "fresh", "tenant-fresh")
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 20 || strings.HasPrefix(pw, "-") {
		t.Fatalf("fresh draw is wrong: %q", pw)
	}

	// The store cannot be read: refuse, never mint over an unknown state.
	broken := &Neo4jProvisioner{cfg: Neo4jConfig{K8sClient: dpclient.New(k8s, ""), VaultClient: &storeVault{err: errors.New("sealed")}}}
	if _, err := broken.deriveNeo4jPassword(context.Background(), "acme", "tenant-acme"); err == nil {
		t.Fatal("a store that cannot be read must be an error, not a fresh password")
	}
}
