// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// The chart owns the default size of a tenant Neo4j and a Tenant can set its
// own size. No plan is an input: nothing in this file gives the provisioner a
// plan, and the provisioner has no parameter that takes one.

// chartSize is a default that differs from the built-in size in each field,
// so a test that reads the built-in size by mistake fails.
func chartSize() map[string]string {
	return map[string]string{
		neo4jSizeStorageKey: "20Gi",
		neo4jSizeCPUKey:     "250m",
		neo4jSizeMemoryKey:  "2Gi",
	}
}

func newSizeTestProvisioner(t *testing.T, cmData map[string]string, objs ...client.Object) *Neo4jProvisioner {
	t.Helper()
	if cmData != nil {
		objs = append(objs, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      neo4jSizeConfigMapName,
				Namespace: neo4jTemplateNamespace,
			},
			Data: cmData,
		})
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, networkingv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(c, ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
		Image:             testNeo4jImage,
	}}
}

// applied reads the size back from the objects the apply path wrote, so a
// change that stops the plumbing of a value fails here.
func applied(t *testing.T, n *Neo4jProvisioner) (storage, cpu, mem, heap string) {
	t.Helper()
	ctx := context.Background()
	names, err := tenantNames(testTenantID)
	if err != nil {
		t.Fatalf("tenantNames: %v", err)
	}
	var sts appsv1.StatefulSet
	stsKey := types.NamespacedName{Name: names.Neo4jStatefulSet(), Namespace: testTenantNS}
	if err := n.cfg.K8sClient.Get(ctx, stsKey, &sts); err != nil {
		t.Fatalf("get StatefulSet: %v", err)
	}
	var pvc corev1.PersistentVolumeClaim
	pvcKey := types.NamespacedName{Name: "data-" + names.Neo4jStatefulSet() + "-0", Namespace: testTenantNS}
	if err := n.cfg.K8sClient.Get(ctx, pvcKey, &pvc); err != nil {
		t.Fatalf("get PVC: %v", err)
	}
	c := sts.Spec.Template.Spec.Containers[0]
	if lim := c.Resources.Limits[corev1.ResourceMemory]; lim.Cmp(c.Resources.Requests[corev1.ResourceMemory]) != 0 {
		t.Errorf("memory limit %s differs from the request", lim.String())
	}
	for _, e := range c.Env {
		if e.Name == pdataplane.Neo4jSettingEnvVar("server.memory.heap.max_size") {
			heap = e.Value
		}
	}
	q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	return q.String(), c.Resources.Requests.Cpu().String(), c.Resources.Requests.Memory().String(), heap
}

func qty(s string) *resource.Quantity {
	q := resource.MustParse(s)
	return &q
}

func TestATenantWithNoSizeGetsTheChartDefault(t *testing.T) {
	n := newSizeTestProvisioner(t, chartSize())
	if err := n.applyResources(context.Background(), testTenantID, testTenantNS, "pw", nil); err != nil {
		t.Fatalf("applyResources: %v", err)
	}
	storage, cpu, mem, heap := applied(t, n)
	if storage != "20Gi" || cpu != "250m" || mem != "2Gi" {
		t.Errorf("size = %s/%s/%s, want the chart default 20Gi/250m/2Gi", storage, cpu, mem)
	}
	if heap != "512m" {
		t.Errorf("heap = %q, want 512m (a quarter of 2Gi)", heap)
	}
}

func TestATenantWithASizeGetsThatSize(t *testing.T) {
	n := newSizeTestProvisioner(t, chartSize())
	override := &gibsonv1alpha1.TenantNeo4jResources{Storage: qty("50Gi"), CPU: qty("500m"), Memory: qty("4Gi")}
	if err := n.applyResources(context.Background(), testTenantID, testTenantNS, "pw", override); err != nil {
		t.Fatalf("applyResources: %v", err)
	}
	storage, cpu, mem, heap := applied(t, n)
	if storage != "50Gi" || cpu != "500m" || mem != "4Gi" {
		t.Errorf("size = %s/%s/%s, want the Tenant size 50Gi/500m/4Gi", storage, cpu, mem)
	}
	if heap != "1024m" {
		t.Errorf("heap = %q, want 1024m (a quarter of 4Gi)", heap)
	}
}

func TestAFieldTheTenantDoesNotSetKeepsTheChartDefault(t *testing.T) {
	n := newSizeTestProvisioner(t, chartSize())
	override := &gibsonv1alpha1.TenantNeo4jResources{Memory: qty("4Gi")}
	if err := n.applyResources(context.Background(), testTenantID, testTenantNS, "pw", override); err != nil {
		t.Fatalf("applyResources: %v", err)
	}
	if storage, cpu, mem, _ := applied(t, n); storage != "20Gi" || cpu != "250m" || mem != "4Gi" {
		t.Errorf("size = %s/%s/%s, want 20Gi/250m/4Gi", storage, cpu, mem)
	}
}

func TestWithNoConfigMapTheBuiltInSizeApplies(t *testing.T) {
	// A cluster with no chart. This is the one legitimate fallback.
	n := newSizeTestProvisioner(t, nil)
	if err := n.applyResources(context.Background(), testTenantID, testTenantNS, "pw", nil); err != nil {
		t.Fatalf("applyResources: %v", err)
	}
	if storage, cpu, mem, _ := applied(t, n); storage != "10Gi" || cpu != "100m" || mem != "1Gi" {
		t.Errorf("size = %s/%s/%s, want the built-in 10Gi/100m/1Gi", storage, cpu, mem)
	}
}

// FAILING FIXTURE. A ConfigMap that is present and wrong must FAIL the
// provision. A fall-through to the built-in size would let an install run a
// size its values do not say while everything reports healthy.
func TestAMalformedChartSizeFailsTheProvision(t *testing.T) {
	with := func(key, value string) map[string]string {
		m := chartSize()
		if value == "" {
			delete(m, key)
		} else {
			m[key] = value
		}
		return m
	}
	for name, data := range map[string]map[string]string{
		"empty":              {},
		"no storage":         with(neo4jSizeStorageKey, ""),
		"no cpu":             with(neo4jSizeCPUKey, ""),
		"no memory":          with(neo4jSizeMemoryKey, ""),
		"unparseable cpu":    with(neo4jSizeCPUKey, "250mm"),
		"unparseable memory": with(neo4jSizeMemoryKey, "8Gigabytes"),
		"zero storage":       with(neo4jSizeStorageKey, "0"),
		"memory too small":   with(neo4jSizeMemoryKey, "4Mi"),
		// The table of the chart before gibson#1526, keyed by plan.
		"a plan table": {"tiers.yaml": "team:\n  storage: 10Gi\n  cpu: 100m\n  memory: 1Gi\n"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a bad size panicked and did not return an error: %v", r)
				}
			}()
			n := newSizeTestProvisioner(t, data)
			if err := n.applyResources(context.Background(), testTenantID, testTenantNS, "pw", nil); err == nil {
				t.Fatal("applyResources accepted a malformed chart size")
			}
		})
	}
}

// FAILING FIXTURE. A Tenant size the operator cannot apply is an error.
// TenantDataPlane has no admission webhook, so the provisioner checks it.
func TestABadTenantSizeFailsTheProvision(t *testing.T) {
	for name, override := range map[string]*gibsonv1alpha1.TenantNeo4jResources{
		"zero cpu":         {CPU: qty("0")},
		"negative storage": {Storage: qty("-1Gi")},
		"memory too small": {Memory: qty("4Mi")},
	} {
		t.Run(name, func(t *testing.T) {
			n := newSizeTestProvisioner(t, chartSize())
			if err := n.applyResources(context.Background(), testTenantID, testTenantNS, "pw", override); err == nil {
				t.Fatal("applyResources accepted a size the operator cannot apply")
			}
		})
	}
}

// An instance that a plan sized (4Gi of memory, a 50Gi volume) exists when the
// chart default becomes 2Gi and 20Gi. The reconcile must not take CPU or
// memory away from it and must not touch its volume: Kubernetes refuses a
// smaller PVC request and a change of the claim template of a StatefulSet.
func TestASmallerDefaultDoesNotShrinkARunningInstance(t *testing.T) {
	ctx := context.Background()
	n := newSizeTestProvisioner(t, map[string]string{
		neo4jSizeStorageKey: "50Gi", neo4jSizeCPUKey: "500m", neo4jSizeMemoryKey: "4Gi",
	})
	if err := n.applyResources(ctx, testTenantID, testTenantNS, "pw", nil); err != nil {
		t.Fatalf("first applyResources: %v", err)
	}

	// The same cluster, and now the chart default is smaller.
	var cm corev1.ConfigMap
	key := types.NamespacedName{Name: neo4jSizeConfigMapName, Namespace: neo4jTemplateNamespace}
	if err := n.cfg.K8sClient.Unscoped().Get(ctx, key, &cm); err != nil {
		t.Fatalf("get ConfigMap: %v", err)
	}
	cm.Data = chartSize()
	if err := n.cfg.K8sClient.Unscoped().Update(ctx, &cm); err != nil {
		t.Fatalf("update ConfigMap: %v", err)
	}
	if err := n.applyResources(ctx, testTenantID, testTenantNS, "pw", nil); err != nil {
		t.Fatalf("second applyResources: %v", err)
	}
	storage, cpu, mem, heap := applied(t, n)
	if storage != "50Gi" || cpu != "500m" || mem != "4Gi" || heap != "1024m" {
		t.Errorf("size = %s/%s/%s heap %s, want the running 50Gi/500m/4Gi heap 1024m", storage, cpu, mem, heap)
	}
	names, _ := tenantNames(testTenantID)
	var sts appsv1.StatefulSet
	stsKey := types.NamespacedName{Name: names.Neo4jStatefulSet(), Namespace: testTenantNS}
	if err := n.cfg.K8sClient.Get(ctx, stsKey, &sts); err != nil {
		t.Fatalf("get StatefulSet: %v", err)
	}
	if got := sts.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage]; got.String() != "50Gi" {
		t.Errorf("claim template storage = %s, want 50Gi: a StatefulSet claim template is immutable", got.String())
	}

	// A size the Tenant sets applies as written, so a deliberate reduction
	// of CPU and memory stays possible. The volume still does not change.
	override := &gibsonv1alpha1.TenantNeo4jResources{Storage: qty("10Gi"), CPU: qty("200m"), Memory: qty("1Gi")}
	if err := n.applyResources(ctx, testTenantID, testTenantNS, "pw", override); err != nil {
		t.Fatalf("third applyResources: %v", err)
	}
	if storage, cpu, mem, _ := applied(t, n); storage != "50Gi" || cpu != "200m" || mem != "1Gi" {
		t.Errorf("size = %s/%s/%s, want 50Gi/200m/1Gi", storage, cpu, mem)
	}
}

func TestALargerDefaultRaisesARunningInstance(t *testing.T) {
	ctx := context.Background()
	n := newSizeTestProvisioner(t, nil)
	if err := n.applyResources(ctx, testTenantID, testTenantNS, "pw", nil); err != nil {
		t.Fatalf("first applyResources: %v", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: neo4jSizeConfigMapName, Namespace: neo4jTemplateNamespace},
		Data:       chartSize(),
	}
	if err := n.cfg.K8sClient.Unscoped().Create(ctx, cm); err != nil {
		t.Fatalf("create ConfigMap: %v", err)
	}
	if err := n.applyResources(ctx, testTenantID, testTenantNS, "pw", nil); err != nil {
		t.Fatalf("second applyResources: %v", err)
	}
	if storage, cpu, mem, _ := applied(t, n); storage != "10Gi" || cpu != "250m" || mem != "2Gi" {
		t.Errorf("size = %s/%s/%s, want 10Gi/250m/2Gi", storage, cpu, mem)
	}
}

func TestLimitsFromCarriesTheNeo4jSize(t *testing.T) {
	got := LimitsFrom(&gibsonv1alpha1.TenantDataPlaneResources{
		Neo4j: &gibsonv1alpha1.TenantNeo4jResources{Memory: qty("4Gi")},
	})
	if got.Neo4j == nil || got.Neo4j.Memory == nil || got.Neo4j.Memory.String() != "4Gi" {
		t.Fatalf("LimitsFrom = %+v, want the Neo4j memory 4Gi", got)
	}
}
