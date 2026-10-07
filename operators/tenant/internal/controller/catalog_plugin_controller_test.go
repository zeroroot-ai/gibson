// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	"github.com/zeroroot-ai/gibson/operators/internal/ciliumegress"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

const (
	cpTenant = "acme"
	cpPlugin = "github"
	cpImage  = "ghcr.io/zeroroot-ai/plugins/github@sha256:" +
		"0000000000000000000000000000000000000000000000000000000000000001"
	cpNamespace = "tenant-acme-plugins"
)

type cpReport struct{ tenant, plugin, phase, lastError string }

// fakeCatalogPluginDaemon is the daemon of a test: a fixed answer for the
// pull, and a record of each report.
type fakeCatalogPluginDaemon struct {
	desired []provision.DesiredCatalogPlugin
	listErr error
	reports []cpReport
}

func (f *fakeCatalogPluginDaemon) ListDesiredCatalogPlugins(context.Context) ([]provision.DesiredCatalogPlugin, error) {
	return f.desired, f.listErr
}

func (f *fakeCatalogPluginDaemon) ReportCatalogPluginStatus(_ context.Context, tenant, plugin, phase, lastError string) error {
	f.reports = append(f.reports, cpReport{tenant, plugin, phase, lastError})
	return nil
}

func (f *fakeCatalogPluginDaemon) lastReport(t *testing.T) cpReport {
	t.Helper()
	if len(f.reports) == 0 {
		t.Fatal("the loop sent no report")
	}
	return f.reports[len(f.reports)-1]
}

func cpConfig() CatalogPluginConfig {
	return CatalogPluginConfig{
		SpireClassName:         "gibson-spire",
		TrustDomain:            "install.example",
		GibsonURL:              "https://api.install.example",
		EnvoyCAFile:            "/etc/gibson/edge-ca/ca.crt",
		WaitForSpireImage:      "registry.example/busybox@sha256:1",
		OperatorServiceAccount: "gibson-tenant-operator",
		OperatorNamespace:      "gibson",
	}
}

func cpScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, networkingv1.AddToScheme, rbacv1.AddToScheme, gibsonv1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	return s
}

func cpTenantObject(name string) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func cpWish(tenant, plugin string) provision.DesiredCatalogPlugin {
	return provision.DesiredCatalogPlugin{TenantID: tenant, PluginID: plugin, Image: cpImage, EgressAllow: []string{"api.github.com:443"}}
}

func newCatalogPluginLoop(t *testing.T, d *fakeCatalogPluginDaemon, objs ...client.Object) (*CatalogPluginRunnable, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(cpScheme(t)).WithObjects(objs...).Build()
	return &CatalogPluginRunnable{
		Client:   c,
		Daemon:   d,
		Config:   cpConfig(),
		Audit:    (&audittest.Sink{}).Emitter(t),
		readFile: func(string) ([]byte, error) { return []byte("PEM"), nil },
	}, c
}

func cpGet(t *testing.T, c client.Client, key client.ObjectKey, obj client.Object) {
	t.Helper()
	if err := c.Get(context.Background(), key, obj); err != nil {
		t.Fatalf("get %T %s: %v", obj, key, err)
	}
}

func cpExists(t *testing.T, c client.Client, key client.ObjectKey, obj client.Object) bool {
	t.Helper()
	err := c.Get(context.Background(), key, obj)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get %T %s: %v", obj, key, err)
	}
	return true
}

func cpIdentity(name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(clusterSPIFFEIDGVK)
	u.SetName(name)
	return u
}

// convergedInstance runs one pass for the one wish (acme, github) and returns
// the loop, its client and its daemon.
func convergedInstance(t *testing.T) (*CatalogPluginRunnable, client.Client, *fakeCatalogPluginDaemon) {
	t.Helper()
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	return r, c, d
}

// The tests below check each object of an instance against the contract with
// the chart (gibson#815).

func TestCatalogPlugins_NamespaceOfTheContract(t *testing.T) {
	_, c, _ := convergedInstance(t)

	var ns corev1.Namespace
	cpGet(t, c, client.ObjectKey{Name: cpNamespace}, &ns)
	wantNS := map[string]string{
		"app.kubernetes.io/managed-by":           "gibson-tenant-operator",
		"gibson.zeroroot.ai/tenant":              cpTenant,
		"gibson.zeroroot.ai/plugin-namespace-of": cpTenant,
		"pod-security.kubernetes.io/enforce":     "restricted",
	}
	if !reflect.DeepEqual(ns.Labels, wantNS) {
		t.Errorf("namespace labels = %v, want %v", ns.Labels, wantNS)
	}

	var rb rbacv1.RoleBinding
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-tenant-operator-plugins"}, &rb)
	if rb.RoleRef.Kind != "ClusterRole" || rb.RoleRef.Name != "gibson-tenant-operator-plugin-namespace" {
		t.Errorf("RoleBinding roleRef = %+v", rb.RoleRef)
	}
	wantSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "gibson-tenant-operator", Namespace: "gibson"}}
	if !reflect.DeepEqual(rb.Subjects, wantSubjects) {
		t.Errorf("RoleBinding subjects = %+v, want %+v", rb.Subjects, wantSubjects)
	}

	var deny networkingv1.NetworkPolicy
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "default-deny"}, &deny)
	wantDeny := networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
	}
	if !reflect.DeepEqual(deny.Spec, wantDeny) {
		t.Errorf("default-deny spec = %+v, want %+v", deny.Spec, wantDeny)
	}

	var cm corev1.ConfigMap
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-envoy-ca"}, &cm)
	if cm.Data["ca.crt"] != "PEM" {
		t.Errorf("CA ConfigMap data = %v", cm.Data)
	}
}

func TestCatalogPlugins_IdentityOfTheContract(t *testing.T) {
	_, c, _ := convergedInstance(t)

	var sa corev1.ServiceAccount
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &sa)

	id := cpIdentity("gibson-plugin-github-acme")
	cpGet(t, c, client.ObjectKey{Name: id.GetName()}, id)
	wantSpec := map[string]any{
		"className":        "gibson-spire",
		"spiffeIDTemplate": "spiffe://install.example/plugin/github/acme",
		"namespaceSelector": map[string]any{
			"matchLabels": map[string]any{"kubernetes.io/metadata.name": cpNamespace},
		},
		"podSelector": map[string]any{
			"matchLabels": map[string]any{"app.kubernetes.io/component": "plugin", "gibson.zeroroot.ai/plugin": "github"},
		},
		"workloadSelectorTemplates": []any{"k8s:ns:" + cpNamespace, "k8s:sa:gibson-plugin-github"},
	}
	if !reflect.DeepEqual(id.Object["spec"], wantSpec) {
		t.Errorf("ClusterSPIFFEID spec =\n %v\nwant\n %v", id.Object["spec"], wantSpec)
	}
	wantIDLabels := map[string]string{
		"app.kubernetes.io/managed-by": "gibson-tenant-operator",
		"gibson.zeroroot.ai/tenant":    cpTenant,
		"gibson.zeroroot.ai/plugin":    cpPlugin,
	}
	if !reflect.DeepEqual(id.GetLabels(), wantIDLabels) {
		t.Errorf("ClusterSPIFFEID labels = %v, want %v", id.GetLabels(), wantIDLabels)
	}
}

func TestCatalogPlugins_PodOfTheContract(t *testing.T) {
	_, c, _ := convergedInstance(t)

	var np networkingv1.NetworkPolicy
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &np)
	if len(np.Spec.Ingress) != 1 || len(np.Spec.Ingress[0].Ports) != 1 || np.Spec.Ingress[0].Ports[0].Port.IntValue() != 8080 {
		t.Errorf("plugin NetworkPolicy ingress = %+v", np.Spec.Ingress)
	}

	var dep appsv1.Deployment
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &dep)
	wantPod := map[string]string{
		"app.kubernetes.io/name":      "gibson-plugin-github",
		"app.kubernetes.io/component": "plugin",
		"gibson.zeroroot.ai/plugin":   cpPlugin,
		"gibson.zeroroot.ai/tenant":   cpTenant,
	}
	if !reflect.DeepEqual(dep.Spec.Template.Labels, wantPod) {
		t.Errorf("pod labels = %v, want %v", dep.Spec.Template.Labels, wantPod)
	}
	pod := dep.Spec.Template.Spec
	if pod.ServiceAccountName != "gibson-plugin-github" {
		t.Errorf("serviceAccountName = %q", pod.ServiceAccountName)
	}
	if len(pod.Containers) != 1 || pod.Containers[0].Image != cpImage {
		t.Fatalf("containers = %+v, want one container with the catalog image", pod.Containers)
	}
	env := map[string]string{}
	for _, e := range pod.Containers[0].Env {
		env[e.Name] = e.Value
	}
	wantEnv := map[string]string{
		"HOME":                   "/home/nonroot",
		"GIBSON_URL":             "https://api.install.example",
		"GIBSON_DAEMON_TLS":      "1",
		"GIBSON_PLUGIN_RUNTIME":  "pod",
		"GIBSON_PLUGIN_MANIFEST": "/etc/gibson/plugin.yaml",
		"SSL_CERT_DIR":           "/etc/ssl/certs:/etc/ssl/envoy-ca",
		"SPIFFE_ENDPOINT_SOCKET": "unix:///run/spire/sockets/api.sock",
	}
	if !reflect.DeepEqual(env, wantEnv) {
		t.Errorf("plugin env = %v, want %v", env, wantEnv)
	}
	if len(pod.InitContainers) != 1 || pod.InitContainers[0].Image != "registry.example/busybox@sha256:1" {
		t.Errorf("init containers = %+v", pod.InitContainers)
	}
	for _, v := range restrictedPodViolations(pod) {
		t.Errorf("the plugin pod breaks the restricted standard: %s", v)
	}
}

// The loop reports Provisioning until the Deployment is available, then Ready.
// cpEgressPolicy reads the CiliumNetworkPolicy of an instance.
func cpEgressPolicy(namespace, name string) *unstructured.Unstructured {
	u := ciliumegress.NewPolicy()
	u.SetNamespace(namespace)
	u.SetName(name)
	return u
}

// TestCatalogPlugins_EgressIsTheHostList: the plugin NetworkPolicy has no
// egress rule, and the CiliumNetworkPolicy of the instance permits DNS, each
// host of the catalog entry and the edge of the platform, and nothing else
// (ADR-0136, D76).
func TestCatalogPlugins_EgressIsTheHostList(t *testing.T) {
	_, c, _ := convergedInstance(t)

	var np networkingv1.NetworkPolicy
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &np)
	if len(np.Spec.Egress) != 0 {
		t.Errorf("plugin NetworkPolicy egress = %+v, want no rule", np.Spec.Egress)
	}

	cnp := cpEgressPolicy(cpNamespace, "gibson-plugin-github-egress")
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: cnp.GetName()}, cnp)
	selector, _, _ := unstructured.NestedStringMap(cnp.Object, "spec", "endpointSelector", "matchLabels")
	if selector[labelAppName] != "gibson-plugin-github" || selector[labelAppComponent] != pluginComponent {
		t.Errorf("endpointSelector = %v", selector)
	}
	egress, _, _ := unstructured.NestedSlice(cnp.Object, "spec", "egress")
	want, err := ciliumegress.Rules([]string{"api.github.com:443", "api.install.example:443"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(egress, want) {
		t.Errorf("egress = %v, want %v", egress, want)
	}
	if cnp.GetLabels()[labelManagedBy] != catalogPluginManagedBy {
		t.Errorf("labels = %v, want the label of the loop", cnp.GetLabels())
	}
}

// TestCatalogPlugins_ABadHostIsRefused: an entry that is not host or
// host:port makes no instance, so no pod runs with a list that the policy
// cannot state.
func TestCatalogPlugins_ABadHostIsRefused(t *testing.T) {
	wish := cpWish(cpTenant, cpPlugin)
	wish.EgressAllow = []string{"https://api.github.com/path"}
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{wish}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	_ = r.converge(context.Background())
	if cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &appsv1.Deployment{}) {
		t.Error("a plugin with a bad host list got a Deployment")
	}
}

func TestCatalogPlugins_ReportsThePhase(t *testing.T) {
	r, c, d := convergedInstance(t)
	if got := d.lastReport(t); got != (cpReport{cpTenant, cpPlugin, "Provisioning", ""}) {
		t.Errorf("report = %+v, want Provisioning", got)
	}

	var dep appsv1.Deployment
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &dep)
	dep.Status.AvailableReplicas = 1
	if err := c.Status().Update(context.Background(), &dep); err != nil {
		t.Fatalf("set Deployment status: %v", err)
	}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("second converge: %v", err)
	}
	if got := d.lastReport(t); got.phase != "Ready" {
		t.Errorf("report after the Deployment is available = %+v, want Ready", got)
	}
}

// restrictedPodViolations lists the rules of the Pod Security Standard
// "restricted" that the pod breaks.
func restrictedPodViolations(pod corev1.PodSpec) []string {
	var out []string
	psc := pod.SecurityContext
	if psc == nil {
		psc = &corev1.PodSecurityContext{}
	}
	for _, v := range pod.Volumes {
		if v.HostPath != nil {
			out = append(out, "volume "+v.Name+" is a hostPath")
		}
	}
	all := append(append([]corev1.Container{}, pod.InitContainers...), pod.Containers...)
	for _, c := range all {
		out = append(out, restrictedContainerViolations(psc, c)...)
	}
	return out
}

func restrictedContainerViolations(psc *corev1.PodSecurityContext, c corev1.Container) []string {
	var out []string
	sc := c.SecurityContext
	if sc == nil {
		sc = &corev1.SecurityContext{}
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		out = append(out, c.Name+": allowPrivilegeEscalation is not false")
	}
	dropsAll := false
	if sc.Capabilities != nil {
		for _, d := range sc.Capabilities.Drop {
			dropsAll = dropsAll || d == "ALL"
		}
	}
	if !dropsAll {
		out = append(out, c.Name+": does not drop ALL capabilities")
	}
	nonRoot := psc.RunAsNonRoot
	if sc.RunAsNonRoot != nil {
		nonRoot = sc.RunAsNonRoot
	}
	if nonRoot == nil || !*nonRoot {
		out = append(out, c.Name+": runAsNonRoot is not true")
	}
	seccomp := psc.SeccompProfile
	if sc.SeccompProfile != nil {
		seccomp = sc.SeccompProfile
	}
	if seccomp == nil || seccomp.Type != corev1.SeccompProfileTypeRuntimeDefault {
		out = append(out, c.Name+": seccomp profile is not RuntimeDefault")
	}
	return out
}

// The evaluator above can fail.
func TestRestrictedPodViolations_FindsABarePod(t *testing.T) {
	if got := restrictedPodViolations(corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}); len(got) != 4 {
		t.Fatalf("a bare pod breaks %d rules, want 4: %v", len(got), got)
	}
}

// With no edge CA file, the loop writes no CA ConfigMap and the pod has no CA
// mount.
func TestCatalogPlugins_NoEdgeCAFile(t *testing.T) {
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	r.Config.EnvoyCAFile = ""
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-envoy-ca"}, &corev1.ConfigMap{}) {
		t.Error("a CA ConfigMap exists although the config names no CA file")
	}
	var dep appsv1.Deployment
	cpGet(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &dep)
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "envoy-ca" {
			t.Error("the pod has a CA volume although the config names no CA file")
		}
	}
}

// A plugin that a tenant disabled loses its objects. The namespace stays
// while a second plugin of the tenant is wanted, and goes with the last one.
func TestCatalogPlugins_PruneRemovesWhatIsNotWanted(t *testing.T) {
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{
		cpWish(cpTenant, "github"), cpWish(cpTenant, "gitlab"), cpWish("other", "github"),
	}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant), cpTenantObject("other"))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	gitlab := client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-gitlab"}
	github := client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}
	if !cpExists(t, c, gitlab, &appsv1.Deployment{}) {
		t.Fatal("the gitlab instance was not made, so the prune check would prove nothing")
	}

	d.desired = []provision.DesiredCatalogPlugin{cpWish(cpTenant, "github"), cpWish("other", "github")}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-gitlab-egress"},
		cpEgressPolicy(cpNamespace, "gibson-plugin-gitlab-egress")) {
		t.Error("the egress policy of the disabled plugin still exists")
	}
	if !cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github-egress"},
		cpEgressPolicy(cpNamespace, "gibson-plugin-github-egress")) {
		t.Error("the egress policy of the wanted plugin is gone")
	}
	for _, obj := range []client.Object{&appsv1.Deployment{}, &networkingv1.NetworkPolicy{}, &corev1.ServiceAccount{}} {
		if cpExists(t, c, gitlab, obj) {
			t.Errorf("%T of the disabled plugin still exists", obj)
		}
		if !cpExists(t, c, github, obj) {
			t.Errorf("%T of the wanted plugin is gone", obj)
		}
	}
	if cpExists(t, c, client.ObjectKey{Name: "gibson-plugin-gitlab-acme"}, cpIdentity("gibson-plugin-gitlab-acme")) {
		t.Error("the identity of the disabled plugin still exists")
	}
	if !cpExists(t, c, client.ObjectKey{Name: "gibson-plugin-github-acme"}, cpIdentity("gibson-plugin-github-acme")) {
		t.Error("the identity of the wanted plugin is gone")
	}
	if !cpExists(t, c, client.ObjectKey{Name: "gibson-plugin-github-other"}, cpIdentity("gibson-plugin-github-other")) {
		t.Error("the identity of a different tenant is gone")
	}

	d.desired = []provision.DesiredCatalogPlugin{cpWish("other", "github")}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
		t.Error("the plugin namespace of a tenant with no plugin still exists")
	}
	if !cpExists(t, c, client.ObjectKey{Name: "tenant-other-plugins"}, &corev1.Namespace{}) {
		t.Error("the plugin namespace of a different tenant is gone")
	}
}

// The prune never deletes an object that does not carry the label of the
// loop, and never deletes the namespace of a tenant.
func TestCatalogPlugins_PruneLeavesForeignObjects(t *testing.T) {
	tenantNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "tenant-acme",
		Labels: map[string]string{"gibson.zeroroot.ai/managed-by": "tenant-operator", "gibson.zeroroot.ai/tenant": cpTenant},
	}}
	foreignID := cpIdentity("gibson-daemon")
	d := &fakeCatalogPluginDaemon{}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant), tenantNS, foreignID)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if !cpExists(t, c, client.ObjectKey{Name: "tenant-acme"}, &corev1.Namespace{}) {
		t.Error("the prune deleted the namespace of a tenant")
	}
	if !cpExists(t, c, client.ObjectKey{Name: "gibson-daemon"}, cpIdentity("gibson-daemon")) {
		t.Error("the prune deleted an identity that the loop did not make")
	}
}

// The namespace tenant-<a>-plugins is also the namespace of a tenant with the
// name <a>-plugins. The loop never takes over a namespace that is not its own.
func TestCatalogPlugins_RefusesAForeignNamespace(t *testing.T) {
	foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   cpNamespace,
		Labels: map[string]string{"gibson.zeroroot.ai/managed-by": "tenant-operator", "gibson.zeroroot.ai/tenant": "acme-plugins"},
	}}
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant), foreign)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	got := d.lastReport(t)
	if got.phase != "Failed" || !strings.Contains(got.lastError, errForeignNamespace.Error()) {
		t.Errorf("report = %+v, want Failed with the foreign namespace error", got)
	}
	if cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &appsv1.Deployment{}) {
		t.Error("the loop made a Deployment in a namespace that is not its own")
	}
	if cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-tenant-operator-plugins"}, &rbacv1.RoleBinding{}) {
		t.Error("the loop made a RoleBinding in a namespace that is not its own")
	}
	var ns corev1.Namespace
	cpGet(t, c, client.ObjectKey{Name: cpNamespace}, &ns)
	if ns.Labels["app.kubernetes.io/managed-by"] != "" {
		t.Error("the loop put its label on a namespace that is not its own")
	}
}

// A wish of a tenant that is gone, or in deletion, makes nothing, and the
// instance that exists is removed.
func TestCatalogPlugins_TenantGone(t *testing.T) {
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if !cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
		t.Fatal("the instance was not made")
	}
	if err := c.Delete(context.Background(), cpTenantObject(cpTenant)); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	reportsBefore := len(d.reports)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(d.reports) != reportsBefore {
		t.Error("the loop reported a state for a tenant that is gone")
	}
	if cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
		t.Error("the plugin namespace of a tenant that is gone still exists")
	}
	if cpExists(t, c, client.ObjectKey{Name: "gibson-plugin-github-acme"}, cpIdentity("gibson-plugin-github-acme")) {
		t.Error("the identity of a tenant that is gone still exists")
	}
}

// A name that cannot be an object name is refused before any write.
func TestCatalogPlugins_RefusesBadNames(t *testing.T) {
	cases := map[string]provision.DesiredCatalogPlugin{
		"tenant with a slash":  {TenantID: "a/b", PluginID: cpPlugin, Image: cpImage},
		"tenant with a dot":    {TenantID: "a.b", PluginID: cpPlugin, Image: cpImage},
		"plugin in upper case": {TenantID: cpTenant, PluginID: "GitHub", Image: cpImage},
		"no image":             {TenantID: cpTenant, PluginID: cpPlugin},
		"long tenant":          {TenantID: strings.Repeat("a", 49), PluginID: cpPlugin, Image: cpImage},
	}
	for name, wish := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validInstance(wish); err == nil {
				t.Fatal("validInstance accepted the wish")
			}
		})
	}
	if err := validInstance(cpWish(strings.Repeat("a", 48), cpPlugin)); err != nil {
		t.Errorf("a tenant name of 48 characters was refused: %v", err)
	}
}

// When the pull fails, the pass removes nothing.
func TestCatalogPlugins_ListErrorRemovesNothing(t *testing.T) {
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	d.desired, d.listErr = nil, errors.New("the daemon is not reachable")
	if err := r.converge(context.Background()); err == nil {
		t.Fatal("converge returned no error although the pull failed")
	}
	if !cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-github"}, &appsv1.Deployment{}) {
		t.Error("a failed pull removed an instance")
	}
}

func TestCatalogPluginConfig_Validate(t *testing.T) {
	if err := cpConfig().Validate(); err != nil {
		t.Fatalf("a full config was refused: %v", err)
	}
	noCA := cpConfig()
	noCA.EnvoyCAFile = ""
	if err := noCA.Validate(); err != nil {
		t.Errorf("a config with no CA file was refused: %v", err)
	}
	for _, clear := range []func(*CatalogPluginConfig){
		func(c *CatalogPluginConfig) { c.SpireClassName = "" },
		func(c *CatalogPluginConfig) { c.TrustDomain = "" },
		func(c *CatalogPluginConfig) { c.GibsonURL = "" },
		func(c *CatalogPluginConfig) { c.WaitForSpireImage = "" },
		func(c *CatalogPluginConfig) { c.OperatorServiceAccount = "" },
		func(c *CatalogPluginConfig) { c.OperatorNamespace = "" },
	} {
		cfg := cpConfig()
		clear(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("a config with a required value missing was accepted: %+v", cfg)
		}
	}
}
