// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
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
	n := &Neo4jProvisioner{cfg: Neo4jConfig{K8sClient: dpclient.New(k8s, "")}}

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
