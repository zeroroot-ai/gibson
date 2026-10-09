// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// testNeo4jImage is a mirror reference with a digest, the shape the chart sets.
var testNeo4jImage = "ghcr.io/zeroroot-ai/mirror/neo4j:5.26.0-community@sha256:" + strings.Repeat("a", 64)

// The provisioner refuses a tenant Neo4j image that is empty or has no
// digest (gibson#1051). Before, the image was the Docker Hub tag
// neo4j:5.26.0-community, which an air-gapped install cannot pull.
func TestNewNeo4jProvisioner_ImageNeedsADigest(t *testing.T) {
	k8s := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	for _, image := range []string{
		"",
		"neo4j:5.26.0-community",
		"ghcr.io/zeroroot-ai/mirror/neo4j:5.26.0-community",
		"ghcr.io/zeroroot-ai/mirror/neo4j@sha256:abc",
	} {
		_, err := NewNeo4jProvisioner(Neo4jConfig{
			K8sClient: dpclient.New(k8s, ""), VaultClient: newRecordingVaultAdmin(), Image: image,
		})
		if err == nil {
			t.Errorf("image %q: accepted, want an error", image)
		}
	}
	if _, err := NewNeo4jProvisioner(Neo4jConfig{
		K8sClient: dpclient.New(k8s, ""), VaultClient: newRecordingVaultAdmin(), Image: testNeo4jImage,
	}); err != nil {
		t.Fatalf("image with a digest: %v", err)
	}
}

// Both containers of the tenant Neo4j pod run the configured image, so the
// APOC Core jar matches the server.
func TestNeo4jStatefulSet_RunsTheConfiguredImage(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, networkingv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	names, err := tenantNames(testTenantID)
	if err != nil {
		t.Fatalf("tenantNames: %v", err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	n := &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(k8s, ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
		Image:             testNeo4jImage,
	}}
	ctx := context.Background()
	if err := n.applyResources(ctx, testTenantID, testTenantID, "team", testTenantNS, "pw"); err != nil {
		t.Fatalf("applyResources: %v", err)
	}
	got := &appsv1.StatefulSet{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: testTenantNS, Name: names.Neo4jStatefulSet()}, got); err != nil {
		t.Fatalf("get StatefulSet: %v", err)
	}
	spec := got.Spec.Template.Spec
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		if c.Image != testNeo4jImage {
			t.Errorf("container %s runs %q, want %q", c.Name, c.Image, testNeo4jImage)
		}
	}
}
