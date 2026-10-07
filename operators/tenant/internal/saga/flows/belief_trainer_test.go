// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package flows

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

func testTrainerConfig(t *testing.T) BeliefTrainerConfig {
	t.Helper()
	cfg, err := NewBeliefTrainerConfig("ghcr.io/zeroroot-ai/gibson:v1.2.3",
		"gibson-gibson-workloads.gibson.svc:50051", "spiffe://example.org/platform/daemon", "gibson")
	if err != nil {
		t.Fatalf("NewBeliefTrainerConfig: %v", err)
	}
	return cfg
}

func trainerTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func trainerTenant() *gibsonv1alpha1.Tenant {
	t := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID("uid-acme")}}
	t.Status.Namespace = "tenant-acme"
	return t
}

func TestNewBeliefTrainerConfig_RequiresEachValue(t *testing.T) {
	for name, args := range map[string][4]string{
		"no image":          {"", "d:50051", "spiffe://example.org/platform/daemon", "gibson"},
		"no daemon address": {"img", "", "spiffe://example.org/platform/daemon", "gibson"},
		"no daemon SVID":    {"img", "d:50051", "", "gibson"},
		"no namespace":      {"img", "d:50051", "spiffe://example.org/platform/daemon", ""},
		"no port":           {"img", "daemon", "spiffe://example.org/platform/daemon", "gibson"},
		"bad port":          {"img", "daemon:http", "spiffe://example.org/platform/daemon", "gibson"},
	} {
		if _, err := NewBeliefTrainerConfig(args[0], args[1], args[2], args[3]); !errors.Is(err, errBeliefTrainerConfig) {
			t.Errorf("%s: err = %v, want errBeliefTrainerConfig", name, err)
		}
	}
}

// The schedule is nightly, at a minute that depends on the tenant only.
func TestBeliefTrainerSchedule_IsNightlyAndStable(t *testing.T) {
	a := beliefTrainerSchedule("acme")
	if a != beliefTrainerSchedule("acme") {
		t.Fatal("the schedule of one tenant changed between calls")
	}
	f := strings.Fields(a)
	minute, err := strconv.Atoi(f[0])
	if len(f) != 5 || err != nil || minute < 0 || minute > 59 || f[1] != "3" || f[2] != "*" || f[3] != "*" || f[4] != "*" {
		t.Fatalf("schedule %q is not nightly at 03:MM", a)
	}
}

func TestEnsureBeliefTrainer_CreatesTheCronJobAndItsPolicy(t *testing.T) {
	tenant := trainerTenant()
	c := trainerTestClient(t)
	step := newBeliefTrainerStep(ProvisionDeps{K8sClient: c, BeliefTrainer: testTrainerConfig(t)})
	ctx := context.Background()

	done, err := step.Provision(ctx, tenant, nil)
	if err != nil || !done {
		t.Fatalf("Provision = %v, %v; want done", done, err)
	}

	assertTrainerCronJob(t, c)
	assertTrainerPolicy(t, c)

	// A second run updates in place and stays done.
	if done, err := step.Provision(ctx, tenant, nil); err != nil || !done {
		t.Fatalf("second Provision = %v, %v; want done", done, err)
	}
}

// The step waits for the namespace step.
func TestEnsureBeliefTrainer_WaitsForTheNamespace(t *testing.T) {
	tenant := trainerTenant()
	tenant.Status.Namespace = ""
	step := newBeliefTrainerStep(ProvisionDeps{K8sClient: trainerTestClient(t), BeliefTrainer: testTrainerConfig(t)})
	if done, err := step.Provision(context.Background(), tenant, nil); err != nil || done {
		t.Fatalf("Provision with no namespace = %v, %v; want not done and no error", done, err)
	}
}

func assertTenantOwner(t *testing.T, refs []metav1.OwnerReference) {
	t.Helper()
	if len(refs) != 1 || refs[0].Kind != "Tenant" || refs[0].Name != "acme" || refs[0].UID != "uid-acme" ||
		refs[0].Controller == nil || !*refs[0].Controller {
		t.Errorf("owner references = %+v, want the Tenant acme as controller", refs)
	}
}

// assertSecurePod checks the restricted Pod Security standard and the secure
// pod rule (D8).
func assertSecurePod(t *testing.T, spec corev1.PodSpec, ctr corev1.Container) {
	t.Helper()
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("the pod mounts a service account token")
	}
	psc := spec.SecurityContext
	if psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.SeccompProfile == nil ||
		psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("pod security context = %+v, want non-root and RuntimeDefault seccomp", psc)
	}
	sc := ctr.SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation ||
		sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem ||
		sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Errorf("container security context = %+v, want no escalation, a read-only root and no capability", sc)
	}
	if ctr.Resources.Limits.Cpu().IsZero() || ctr.Resources.Limits.Memory().IsZero() {
		t.Error("the container has no CPU or memory limit")
	}
	for _, v := range spec.Volumes {
		if v.CSI == nil || v.CSI.Driver != "csi.spiffe.io" {
			t.Errorf("volume %s is not the SPIFFE CSI socket", v.Name)
		}
	}
}

// assertTrainerCronJob checks the CronJob that Provision created.
func assertTrainerCronJob(t *testing.T, c client.Client) {
	t.Helper()
	ctx := context.Background()
	var cj batchv1.CronJob
	if err := c.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: BeliefTrainerName}, &cj); err != nil {
		t.Fatalf("get CronJob: %v", err)
	}
	if cj.Spec.ConcurrencyPolicy != batchv1.ForbidConcurrent {
		t.Errorf("concurrencyPolicy = %q, want Forbid", cj.Spec.ConcurrencyPolicy)
	}
	assertTenantOwner(t, cj.OwnerReferences)
	pod := cj.Spec.JobTemplate.Spec.Template
	if pod.Labels[labelComponent] != ComponentBeliefTrainer || pod.Labels[labelTenant] != "acme" {
		t.Errorf("pod labels = %v, want the trainer component and tenant acme", pod.Labels)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("pod has %d containers, want 1", len(pod.Spec.Containers))
	}
	ctr := pod.Spec.Containers[0]
	if ctr.Image != "ghcr.io/zeroroot-ai/gibson:v1.2.3" {
		t.Errorf("image = %q", ctr.Image)
	}
	if !slices.Equal(ctr.Command, []string{"belief-trainer", "-tenant", "acme"}) {
		t.Errorf("command = %v", ctr.Command)
	}
	env := map[string]string{}
	for _, e := range ctr.Env {
		env[e.Name] = e.Value
	}
	if env["GIBSON_DAEMON_GRPC_ADDRESS"] == "" || env["GIBSON_DAEMON_SPIFFE_ID"] == "" || env["SPIFFE_ENDPOINT_SOCKET"] == "" {
		t.Errorf("env = %v, want the daemon address, the daemon SVID and the SPIRE socket", env)
	}
	for _, e := range ctr.Env {
		if e.ValueFrom != nil {
			t.Errorf("env %s reads a Secret or a ConfigMap; the trainer holds no credential", e.Name)
		}
	}
	assertSecurePod(t, pod.Spec, ctr)
}

// assertTrainerPolicy checks the NetworkPolicy that Provision created.
func assertTrainerPolicy(t *testing.T, c client.Client) {
	t.Helper()
	ctx := context.Background()
	var np networkingv1.NetworkPolicy
	if err := c.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: BeliefTrainerName}, &np); err != nil {
		t.Fatalf("get NetworkPolicy: %v", err)
	}
	assertTenantOwner(t, np.OwnerReferences)
	if len(np.Spec.Ingress) != 0 {
		t.Errorf("the trainer policy admits ingress: %+v", np.Spec.Ingress)
	}
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("egress rules = %d, want the daemon and DNS", len(np.Spec.Egress))
	}
	daemon := np.Spec.Egress[0]
	if len(daemon.Ports) != 1 || daemon.Ports[0].Port.IntVal != 50051 {
		t.Errorf("daemon egress ports = %+v, want 50051 from the daemon address", daemon.Ports)
	}
	if peer := daemon.To[0]; peer.NamespaceSelector == nil || peer.PodSelector == nil ||
		peer.PodSelector.MatchLabels[labelComponent] != "daemon" {
		t.Errorf("daemon peer = %+v, want the daemon pods of the platform namespace", peer)
	}
}
