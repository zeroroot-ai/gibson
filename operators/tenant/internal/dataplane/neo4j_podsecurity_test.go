// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// restrictedViolations applies the rules of the Kubernetes Pod Security
// Standard "restricted" that a pod spec can break, and returns one line for
// each broken rule. It reads the fields as the API server reads them: a
// container value wins over the pod value. The test below feeds it a pod
// that breaks every rule, so an evaluator that finds nothing fails too.
func restrictedViolations(pod corev1.PodSpec) []string {
	var out []string
	if pod.HostNetwork || pod.HostPID || pod.HostIPC {
		out = append(out, "pod uses a host namespace")
	}
	for _, v := range pod.Volumes {
		if v.HostPath != nil {
			out = append(out, "volume "+v.Name+" is a hostPath")
		}
	}
	psc := pod.SecurityContext
	if psc == nil {
		psc = &corev1.PodSecurityContext{}
	}
	all := append(append([]corev1.Container{}, pod.InitContainers...), pod.Containers...)
	for _, c := range all {
		sc := c.SecurityContext
		if sc == nil {
			sc = &corev1.SecurityContext{}
		}
		out = append(out, privilegeViolations(c.Name, sc)...)
		out = append(out, identityViolations(c.Name, psc, sc)...)
	}
	return out
}

// privilegeViolations checks the rules about privilege and capabilities for
// one container.
func privilegeViolations(name string, sc *corev1.SecurityContext) []string {
	var out []string
	if sc.Privileged != nil && *sc.Privileged {
		out = append(out, name+": privileged")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		out = append(out, name+": allowPrivilegeEscalation is not false")
	}
	dropsAll := false
	if sc.Capabilities != nil {
		for _, d := range sc.Capabilities.Drop {
			dropsAll = dropsAll || d == "ALL"
		}
		for _, a := range sc.Capabilities.Add {
			if a != "NET_BIND_SERVICE" {
				out = append(out, name+": adds capability "+string(a))
			}
		}
	}
	if !dropsAll {
		out = append(out, name+": does not drop ALL capabilities")
	}
	return out
}

// identityViolations checks the rules about the user and the seccomp profile
// for one container. A container value wins over the pod value.
func identityViolations(name string, psc *corev1.PodSecurityContext, sc *corev1.SecurityContext) []string {
	var out []string
	nonRoot := psc.RunAsNonRoot
	if sc.RunAsNonRoot != nil {
		nonRoot = sc.RunAsNonRoot
	}
	if nonRoot == nil || !*nonRoot {
		out = append(out, name+": runAsNonRoot is not true")
	}
	uid := psc.RunAsUser
	if sc.RunAsUser != nil {
		uid = sc.RunAsUser
	}
	if uid != nil && *uid == 0 {
		out = append(out, name+": runAsUser is 0")
	}
	seccomp := psc.SeccompProfile
	if sc.SeccompProfile != nil {
		seccomp = sc.SeccompProfile
	}
	if seccomp == nil ||
		(seccomp.Type != corev1.SeccompProfileTypeRuntimeDefault && seccomp.Type != corev1.SeccompProfileTypeLocalhost) {
		out = append(out, name+": seccomp profile is not RuntimeDefault or Localhost")
	}
	return out
}

// The evaluator must be able to fail. A pod with no security context breaks
// four rules for its one container.
func TestRestrictedViolations_FindsABarePod(t *testing.T) {
	t.Parallel()
	bare := corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}
	if got := restrictedViolations(bare); len(got) != 4 {
		t.Fatalf("a bare pod breaks %d rules, want 4: %v", len(got), got)
	}
	yes, root := true, int64(0)
	bad := corev1.PodSpec{
		HostNetwork: true,
		Volumes: []corev1.Volume{{
			Name:         "h",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{}},
		}},
		Containers: []corev1.Container{{Name: "c", SecurityContext: &corev1.SecurityContext{
			Privileged:   &yes,
			RunAsUser:    &root,
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}},
		}}},
	}
	if got := restrictedViolations(bad); len(got) != 9 {
		t.Fatalf("the bad pod breaks %d rules, want 9: %v", len(got), got)
	}
}

// The tenant namespace gets the restricted Pod Security label (ADR-0165), so
// the API server refuses a tenant Neo4j pod that breaks a rule. The pod must
// name a numeric user that is not root, because the image names its user by
// name and the kubelet cannot prove that a named user is not root.
func TestTenantNeo4jPodMeetsRestricted(t *testing.T) {
	t.Parallel()
	sts, _ := buildTestNeo4j(t)
	pod := sts.Spec.Template.Spec
	if len(pod.InitContainers) == 0 || len(pod.Containers) == 0 {
		t.Fatal("the pod has no init container or no container, so the check would cover nothing")
	}
	for _, v := range restrictedViolations(pod) {
		t.Error(v)
	}
	psc := pod.SecurityContext
	if psc == nil || psc.RunAsUser == nil || *psc.RunAsUser != neo4jUID {
		t.Fatalf("the pod does not run as the numeric neo4j user %d", neo4jUID)
	}
	if psc.FSGroup == nil || *psc.FSGroup != neo4jUID {
		t.Errorf("fsGroup is not %d, so the neo4j user cannot write the data volume", neo4jUID)
	}
}

// A tenant that was provisioned before this change has a StatefulSet with no
// security context. The provisioner must reconcile the pod template, or the
// API server refuses the next pod of that tenant.
func TestTenantNeo4jRestrictedReachesProvisionedTenants(t *testing.T) {
	t.Parallel()
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
	stsName := names.Neo4jStatefulSet()

	// The template of today, with each security context removed.
	desired, _ := buildTestNeo4j(t)
	legacy := desired.DeepCopy()
	legacy.ObjectMeta = metav1.ObjectMeta{Name: stsName, Namespace: testTenantNS}
	legacy.Spec.Template.Spec.SecurityContext = nil
	for i := range legacy.Spec.Template.Spec.InitContainers {
		legacy.Spec.Template.Spec.InitContainers[i].SecurityContext = nil
	}
	for i := range legacy.Spec.Template.Spec.Containers {
		legacy.Spec.Template.Spec.Containers[i].SecurityContext = nil
	}
	if len(restrictedViolations(legacy.Spec.Template.Spec)) == 0 {
		t.Fatal("the legacy fixture already meets restricted, so this test would prove nothing")
	}

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(legacy).Build()
	n := &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(k8s, ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
	}}
	ctx := context.Background()
	if err := n.applyResources(ctx, testTenantID, testTenantID, "team", testTenantNS, "pw"); err != nil {
		t.Fatalf("applyResources over an existing StatefulSet: %v", err)
	}
	got := &appsv1.StatefulSet{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: testTenantNS, Name: stsName}, got); err != nil {
		t.Fatalf("get StatefulSet: %v", err)
	}
	for _, v := range restrictedViolations(got.Spec.Template.Spec) {
		t.Error("after the reconcile: " + v)
	}
}
