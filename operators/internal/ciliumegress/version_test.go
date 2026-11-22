// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ciliumegress

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A version below the fixed release of its minor line is refused. The fixed
// release and every later one pass.
func TestCheckVersion(t *testing.T) {
	cases := []struct {
		version string
		ok      bool
	}{
		{"v1.14.15", false},
		{"v1.14.16", true},
		{"v1.15.9", false},
		{"v1.15.10", true},
		{"1.16.2", false},
		{"1.16.3", true},
		{"v1.16.3-rc.1", false},
		{"v1.16.4-rc.1", true},
		{"v1.17.0", true},
		{"v2.0.0", true},
		{"v1.13.20", false},
		{"v0.9.0", false},
		{"latest", false},
		{"v1.15", false},
		{"v1.x.3", false},
		{"v1.-2.3", false},
		{"", false},
	}
	for _, c := range cases {
		err := CheckVersion(c.version)
		if c.ok && err != nil {
			t.Errorf("CheckVersion(%q) = %v, want nil", c.version, err)
		}
		if !c.ok && !errors.Is(err, ErrCiliumVersion) {
			t.Errorf("CheckVersion(%q) = %v, want ErrCiliumVersion", c.version, err)
		}
	}
}

func TestImageVersion(t *testing.T) {
	for image, want := range map[string]string{
		"quay.io/cilium/cilium:v1.15.10":               "v1.15.10",
		"quay.io/cilium/cilium:v1.15.10@sha256:abcdef": "v1.15.10",
		"registry:5000/cilium/cilium:v1.16.3":          "v1.16.3",
	} {
		got, err := ImageVersion(image)
		if err != nil || got != want {
			t.Errorf("ImageVersion(%q) = %q, %v, want %q", image, got, err, want)
		}
	}
	for _, image := range []string{"quay.io/cilium/cilium", "quay.io/cilium/cilium@sha256:abcdef", "registry:5000/cilium", "cilium:"} {
		if _, err := ImageVersion(image); !errors.Is(err, ErrCiliumVersion) {
			t.Errorf("ImageVersion(%q) err = %v, want ErrCiliumVersion", image, err)
		}
	}
}

func daemonSet(container, image string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultDaemonSetNamespace, Name: DefaultDaemonSetName},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: container, Image: image}}},
		}},
	}
}

// The start check refuses below the minimum, and it fails closed when it
// cannot read the version: no DaemonSet, no agent container, no tag.
func TestRequireFixedVersion(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ds   *appsv1.DaemonSet
		want string
	}{
		{name: "fixed", ds: daemonSet("cilium-agent", "quay.io/cilium/cilium:v1.15.10@sha256:ab")},
		{name: "a distro build suffix is below the release", ds: daemonSet("cilium-agent", "quay.io/isovalent/cilium:v1.15.10-cee.1"), want: "-cee.1"},
		{name: "below the minimum", ds: daemonSet("cilium-agent", "quay.io/cilium/cilium:v1.15.9"), want: "below 1.15.10"},
		{name: "no DaemonSet", want: "read the DaemonSet"},
		{name: "no agent container", ds: daemonSet("other", "quay.io/cilium/cilium:v1.16.3"), want: "no container"},
		{name: "no tag", ds: daemonSet("cilium-agent", "quay.io/cilium/cilium@sha256:ab"), want: "no tag"},
	}
	for _, c := range cases {
		b := fake.NewClientBuilder().WithScheme(scheme)
		if c.ds != nil {
			b = b.WithObjects(c.ds)
		}
		err := RequireFixedVersion(context.Background(), b.Build(), DaemonSetFromEnv(func(string) string { return "" }))
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: err = %v, want nil", c.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrCiliumVersion) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want ErrCiliumVersion with %q", c.name, err, c.want)
		}
	}
}

// The cluster ranges come from a comma list. A missing value and a bad range
// fail the start (review B3, R7).
func TestParseClusterCIDRs(t *testing.T) {
	got, err := ParseClusterCIDRs("X_CIDRS", " 10.244.0.0/16, 10.96.0.0/12 ")
	if err != nil || len(got) != 2 || got[0] != "10.244.0.0/16" || got[1] != "10.96.0.0/12" {
		t.Fatalf("ranges = %v, %v", got, err)
	}
	if _, err := ParseClusterCIDRs("X_CIDRS", ""); err == nil || !strings.Contains(err.Error(), "X_CIDRS is required") {
		t.Fatalf("empty: err = %v, want the required error", err)
	}
	if _, err := ParseClusterCIDRs("X_CIDRS", "10.244.0.0/16,nope"); err == nil {
		t.Fatal("a bad range was accepted")
	}
}

func twoContainerDaemonSet(agentImage string) *appsv1.DaemonSet {
	ds := daemonSet("config", "busybox:1.36")
	ds.Spec.Template.Spec.Containers = append(ds.Spec.Template.Spec.Containers,
		corev1.Container{Name: "cilium-agent", Image: agentImage})
	return ds
}

func agentPod(name, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultDaemonSetNamespace, Name: name, Labels: map[string]string{"k8s-app": "cilium"}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "sidecar", Image: "busybox:1.36"},
			{Name: "cilium-agent", Image: image},
		}},
	}
}

// The agent is the second container of the DaemonSet, and a running pod can still
// hold an old agent after a rollout. Any running agent below the minimum refuses.
func TestRequireFixedVersion_ChecksTheAgentContainerAndTheRunningPods(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ref := DaemonSetFromEnv(func(string) string { return "" })
	run := func(objs ...client.Object) error {
		return RequireFixedVersion(context.Background(), fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(), ref)
	}
	good := "quay.io/cilium/cilium:v1.16.3"
	if err := run(twoContainerDaemonSet(good), agentPod("a", good), agentPod("b", good)); err != nil {
		t.Fatalf("fixed agent in the second container and in each pod: %v", err)
	}
	if err := run(twoContainerDaemonSet("quay.io/cilium/cilium:v1.16.2")); !errors.Is(err, ErrCiliumVersion) {
		t.Fatalf("an old agent in the second container: err = %v", err)
	}
	err := run(twoContainerDaemonSet(good), agentPod("a", good), agentPod("old", "quay.io/cilium/cilium:v1.15.9"))
	if !errors.Is(err, ErrCiliumVersion) || !strings.Contains(err.Error(), "old") {
		t.Fatalf("a running pod with an old agent: err = %v, want a refusal that names the pod", err)
	}
	// A pod of another application in the namespace is not an agent.
	other := agentPod("other", "quay.io/cilium/cilium:v1.14.0")
	other.Labels = map[string]string{"k8s-app": "kube-dns"}
	if err := run(twoContainerDaemonSet(good), other); err != nil {
		t.Fatalf("a pod that is no agent refused the start: %v", err)
	}
}

// The name and the namespace come from the environment, and the Get is by
// that name, in that namespace.
func TestRequireFixedVersion_ReadsTheDaemonSetThatTheSettingsName(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ds := daemonSet("cilium-agent", "quay.io/cilium/cilium:v1.16.3")
	ds.Namespace, ds.Name = "net", "cni"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ds).Build()
	env := map[string]string{EnvDaemonSetNamespace: " net ", EnvDaemonSetName: "cni"}
	ref := DaemonSetFromEnv(func(k string) string { return env[k] })
	if ref != (DaemonSetRef{Namespace: "net", Name: "cni"}) {
		t.Fatalf("ref = %+v", ref)
	}
	if err := RequireFixedVersion(context.Background(), c, ref); err != nil {
		t.Fatalf("the DaemonSet of the settings: %v", err)
	}
	if err := RequireFixedVersion(context.Background(), c, DaemonSetFromEnv(func(string) string { return "" })); !errors.Is(err, ErrCiliumVersion) {
		t.Fatalf("the default name must not find the DaemonSet of the settings: %v", err)
	}
	if def := DaemonSetFromEnv(func(string) string { return "" }); def != (DaemonSetRef{Namespace: "kube-system", Name: "cilium"}) {
		t.Fatalf("default = %+v", def)
	}
}

// Both operators call RequireFixedVersion in main, with the settings of the
// environment. The scan reads the syntax tree, so a rename or a removal fails.
func TestMainsCallRequireFixedVersion(t *testing.T) {
	for _, path := range []string{"../../connector/cmd/main.go", "../../tenant/cmd/main.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		calls := 0
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RequireFixedVersion" && len(call.Args) == 3 {
					calls++
				}
			}
			return true
		})
		if calls != 1 {
			t.Errorf("%s: RequireFixedVersion is called %d times, want 1", path, calls)
		}
	}
}
