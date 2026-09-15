// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// The chart owns the per-tier sizing and this operator owns the shape.
//
// Before this path existed the ConfigMap was read and its content thrown
// away, so the inline table was not a fallback — it was the only path, and
// STAGING AND PRODUCTION ran the dev-shaped team sizing while the chart
// carried a tier table nothing rendered and nothing read.

const chartTiers = `
team:
  storage: 10Gi
  cpu: 250m
  memory: 2Gi
org:
  storage: 50Gi
  cpu: 500m
  memory: 4Gi
enterprise:
  storage: 200Gi
  cpu: "1"
  memory: 8Gi
`

func newTierTestProvisioner(t *testing.T, cmData map[string]string) *Neo4jProvisioner {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme)
	if cmData != nil {
		b = b.WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      neo4jTemplateConfigMapName,
				Namespace: neo4jTemplateNamespace,
			},
			Data: cmData,
		})
	}
	return &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(b.Build(), ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
	}}
}

// sizes reads back what the build path actually applied, off the objects it
// produced, so a change that stops plumbing a value fails here rather than
// passing against a number the test wrote itself.
func sizes(t *testing.T, n *Neo4jProvisioner, tier string) (storage, cpu, mem string) {
	t.Helper()
	sts, _, pvc, _, _, err := n.buildResources(context.Background(), testTenantID, testTenantID, tier, testTenantNS, "pw")
	if err != nil {
		t.Fatalf("buildResources(%s): %v", tier, err)
	}
	c := sts.Spec.Template.Spec.Containers[0]
	q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	return q.String(),
		c.Resources.Requests.Cpu().String(),
		c.Resources.Requests.Memory().String()
}

func TestChartTiersWinOverTheInlineDefaults(t *testing.T) {
	n := newTierTestProvisioner(t, map[string]string{neo4jTiersKey: chartTiers})
	storage, cpu, mem := sizes(t, n, "team")
	// The inline default for team is 100m/1Gi. The chart says 250m/2Gi.
	if cpu != "250m" || mem != "2Gi" {
		t.Errorf("chart sizing did not win: cpu=%s memory=%s, want 250m/2Gi", cpu, mem)
	}
	if storage != "10Gi" {
		t.Errorf("storage = %s, want 10Gi", storage)
	}
}

func TestWithNoConfigMapTheInlineDefaultsApply(t *testing.T) {
	// A cluster with no chart. This is the one legitimate fallback.
	n := newTierTestProvisioner(t, nil)
	_, cpu, mem := sizes(t, n, "team")
	if cpu != "100m" || mem != "1Gi" {
		t.Errorf("cpu=%s memory=%s, want the inline 100m/1Gi", cpu, mem)
	}
}

func TestATierTheChartDoesNotNameKeepsTheInlineAliasing(t *testing.T) {
	// Legacy ids the migrate job will rewrite still resolve.
	n := newTierTestProvisioner(t, map[string]string{neo4jTiersKey: chartTiers})
	_, cpu, mem := sizes(t, n, "public-sector")
	if cpu != "1" || mem != "8Gi" {
		t.Errorf("cpu=%s memory=%s, want the inline enterprise 1/8Gi", cpu, mem)
	}
}

// FAILING FIXTURE. A malformed table must FAIL the provision, never fall
// through to the dev defaults — falling through is the defect this closes:
// production quietly running dev sizes while everything reports healthy.
func TestAMalformedTableFailsRatherThanUsingDevSizes(t *testing.T) {
	for name, data := range map[string]string{
		"not yaml":            "{{{",
		"empty":               "",
		"missing a tier":      "team:\n  storage: 10Gi\n  cpu: 250m\n  memory: 2Gi\n",
		"unparseable cpu":     strings.Replace(chartTiers, "cpu: 250m", "cpu: 250mm", 1),
		"a tier with no size": "team: {}\norg: {}\nenterprise: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			n := newTierTestProvisioner(t, map[string]string{neo4jTiersKey: data})
			_, _, _, _, _, err := n.buildResources(context.Background(), testTenantID, testTenantID, "team", testTenantNS, "pw")
			if err == nil {
				t.Fatal("a malformed tier table was accepted; production would silently run dev sizes")
			}
		})
	}
}

// resource.MustParse PANICS on a bad quantity, and the apply path calls it.
// Parsing every value up front is what keeps a typo in a values file from
// crashing the operator instead of being reported.
func TestABadQuantityIsReportedNotPanicked(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a bad quantity panicked instead of erroring: %v", r)
		}
	}()
	if _, err := parseTierSizes(strings.Replace(chartTiers, "memory: 8Gi", "memory: 8Gigabytes", 1)); err == nil {
		t.Fatal("an unparseable memory quantity was accepted")
	}
}
