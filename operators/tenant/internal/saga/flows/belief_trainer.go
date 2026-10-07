// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package flows

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// The belief trainer of a tenant (ADR-0106, gibson#616). The tenant operator
// creates one CronJob in the namespace of each tenant. The CronJob runs
// `belief-trainer -tenant <id>` on the gibson image every night. The pod talks
// only to the daemon, over SPIFFE mTLS, with the SVID
// spiffe://<td>/trainer/<tenant>. It holds no database credential.
const (
	// BeliefTrainerName names the CronJob and its NetworkPolicy.
	BeliefTrainerName = "belief-trainer"

	// ComponentBeliefTrainer is the app.kubernetes.io/component value of the
	// trainer pods. The chart ClusterSPIFFEID that issues the trainer SVID
	// selects on it, and so does the NetworkPolicy.
	ComponentBeliefTrainer = "belief-trainer"

	// labelComponent and labelTenant are the labels that the trainer pod
	// carries.
	labelComponent = "app.kubernetes.io/component"
	labelTenant    = "gibson.zeroroot.ai/tenant"
	labelManagedBy = "gibson.zeroroot.ai/managed-by"

	// spireSocketDir is where the CSI driver mounts the SPIRE agent socket.
	spireSocketDir = "/run/spire/sockets"

	// trainerUID is the non-root user of the trainer container.
	trainerUID = 65532
)

// errBeliefTrainerConfig reports a missing value of the trainer config.
var errBeliefTrainerConfig = errors.New("belief trainer config")

// BeliefTrainerConfig is what the trainer CronJob of each tenant needs. Every
// field is required; NewBeliefTrainerConfig refuses an empty one.
type BeliefTrainerConfig struct {
	// Image is the gibson image that holds the belief-trainer binary.
	Image string
	// DaemonAddr is the gRPC address of the daemon (host:port).
	DaemonAddr string
	// DaemonSPIFFEID is the SVID that the daemon must present.
	DaemonSPIFFEID string
	// PlatformNamespace is the namespace of the daemon pods.
	PlatformNamespace string

	// daemonPort is the port of DaemonAddr.
	daemonPort int32
}

// NewBeliefTrainerConfig validates the trainer config. The daemon port comes
// from the address, so the NetworkPolicy opens exactly the port the trainer
// dials.
func NewBeliefTrainerConfig(image, daemonAddr, daemonSPIFFEID, platformNamespace string) (BeliefTrainerConfig, error) {
	c := BeliefTrainerConfig{
		Image:             strings.TrimSpace(image),
		DaemonAddr:        strings.TrimSpace(daemonAddr),
		DaemonSPIFFEID:    strings.TrimSpace(daemonSPIFFEID),
		PlatformNamespace: strings.TrimSpace(platformNamespace),
	}
	for name, v := range map[string]string{
		"image": c.Image, "daemon address": c.DaemonAddr,
		"daemon SPIFFE ID": c.DaemonSPIFFEID, "platform namespace": c.PlatformNamespace,
	} {
		if v == "" {
			return BeliefTrainerConfig{}, fmt.Errorf("%w: the %s is required", errBeliefTrainerConfig, name)
		}
	}
	_, portStr, err := net.SplitHostPort(c.DaemonAddr)
	if err != nil {
		return BeliefTrainerConfig{}, fmt.Errorf("%w: daemon address %q: %w", errBeliefTrainerConfig, c.DaemonAddr, err)
	}
	port, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil || port <= 0 || port > 65535 {
		return BeliefTrainerConfig{}, fmt.Errorf("%w: daemon address %q has no valid port", errBeliefTrainerConfig, c.DaemonAddr)
	}
	c.daemonPort = int32(port)
	return c, nil
}

// beliefTrainerSchedule spreads the tenants over one night hour: the minute
// comes from the tenant name, so the trainers of all tenants do not start at
// the same second. It is nightly at 03:MM UTC.
func beliefTrainerSchedule(tenant string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenant))
	return fmt.Sprintf("%d 3 * * *", h.Sum32()%60)
}

// beliefTrainerLabels are the labels of the trainer pod.
func beliefTrainerLabels(tenant string) map[string]string {
	return map[string]string{
		labelComponent: ComponentBeliefTrainer,
		labelTenant:    tenant,
		labelManagedBy: "tenant-operator",
	}
}

// tenantOwnerRef makes the Tenant the controller of an object in its
// namespace, so a tenant delete removes the object.
func tenantOwnerRef(t *gibsonv1alpha1.Tenant) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         gibsonv1alpha1.GroupVersion.String(),
		Kind:               "Tenant",
		Name:               t.Name,
		UID:                t.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(false),
	}
}

// buildBeliefTrainerCronJob returns the trainer CronJob of the tenant. The
// pod meets the restricted Pod Security standard of the tenant namespace and
// the secure pod rule (D8).
func buildBeliefTrainerCronJob(t *gibsonv1alpha1.Tenant, ns string, cfg BeliefTrainerConfig) *batchv1.CronJob {
	labels := beliefTrainerLabels(t.Name)
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:            BeliefTrainerName,
			Namespace:       ns,
			Labels:          labels,
			OwnerReferences: []metav1.OwnerReference{tenantOwnerRef(t)},
		},
		Spec: batchv1.CronJobSpec{
			Schedule:                   beliefTrainerSchedule(t.Name),
			TimeZone:                   ptr.To("Etc/UTC"),
			ConcurrencyPolicy:          batchv1.ForbidConcurrent,
			SuccessfulJobsHistoryLimit: ptr.To[int32](1),
			FailedJobsHistoryLimit:     ptr.To[int32](3),
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: batchv1.JobSpec{
					BackoffLimit:            ptr.To[int32](2),
					ActiveDeadlineSeconds:   ptr.To[int64](int64((30 * time.Minute).Seconds())),
					TTLSecondsAfterFinished: ptr.To[int32](int32((24 * time.Hour).Seconds())),
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: labels},
						Spec:       beliefTrainerPodSpec(t.Name, cfg),
					},
				},
			},
		},
	}
}

// beliefTrainerPodSpec is the pod of one trainer run.
func beliefTrainerPodSpec(tenant string, cfg BeliefTrainerConfig) corev1.PodSpec {
	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: ptr.To(false),
		EnableServiceLinks:           ptr.To(false),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   ptr.To(true),
			RunAsUser:      ptr.To[int64](trainerUID),
			RunAsGroup:     ptr.To[int64](trainerUID),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:            BeliefTrainerName,
			Image:           cfg.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"belief-trainer", "-tenant", tenant},
			Env: []corev1.EnvVar{
				{Name: "GIBSON_DAEMON_GRPC_ADDRESS", Value: cfg.DaemonAddr},
				{Name: "GIBSON_DAEMON_SPIFFE_ID", Value: cfg.DaemonSPIFFEID},
				{Name: "SPIFFE_ENDPOINT_SOCKET", Value: "unix://" + spireSocketDir + "/api.sock"},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("1"),
					corev1.ResourceMemory: resource.MustParse("512Mi"),
				},
			},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
				ReadOnlyRootFilesystem:   ptr.To(true),
				RunAsNonRoot:             ptr.To(true),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
			VolumeMounts: []corev1.VolumeMount{{
				Name: "spire-agent-socket", MountPath: spireSocketDir, ReadOnly: true,
			}},
		}},
		Volumes: []corev1.Volume{{
			Name: "spire-agent-socket",
			VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{
				Driver: "csi.spiffe.io", ReadOnly: ptr.To(true),
			}},
		}},
	}
}

// buildBeliefTrainerNetworkPolicy lets the trainer pod reach the daemon gRPC
// port and DNS, and nothing else. No pod may connect to it. The namespace-wide
// default-deny policy does not select the trainer (tenant_namespace.go), so
// this is the only policy of the pod.
func buildBeliefTrainerNetworkPolicy(t *gibsonv1alpha1.Tenant, ns string, cfg BeliefTrainerConfig) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	daemonPort := intstr.FromInt32(cfg.daemonPort)
	dns := intstr.FromInt32(53)
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:            BeliefTrainerName,
			Namespace:       ns,
			Labels:          map[string]string{labelManagedBy: "tenant-operator"},
			OwnerReferences: []metav1.OwnerReference{tenantOwnerRef(t)},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{labelComponent: ComponentBeliefTrainer}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// The namespace and the pod selector are ANDed in one peer:
					// the daemon pods of the platform namespace only.
					To: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kubernetes.io/metadata.name": cfg.PlatformNamespace},
						},
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{labelComponent: "daemon"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &daemonPort}},
				},
				{
					To: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &udp, Port: &dns},
						{Protocol: &tcp, Port: &dns},
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// EnsureBeliefTrainer
// ---------------------------------------------------------------------------

type beliefTrainerStep struct {
	saga.StepBase
	k8s client.Client
	cfg BeliefTrainerConfig
}

func newBeliefTrainerStep(deps ProvisionDeps) *beliefTrainerStep {
	return &beliefTrainerStep{
		StepBase: saga.StepBase{
			N:     "EnsureBeliefTrainer",
			C:     gibsonv1alpha1.ConditionBeliefTrainerReady,
			Caps:  []saga.ClientCapability{saga.CapabilityKubernetes},
			Owner: "tenant-operator",
			P99:   2 * time.Second,
		},
		k8s: deps.K8sClient,
		cfg: deps.BeliefTrainer,
	}
}

// Provision creates or updates the trainer CronJob and its NetworkPolicy in
// the tenant namespace. It waits until the namespace step has recorded the
// namespace.
func (s *beliefTrainerStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	ns := t.Status.Namespace
	if ns == "" {
		return false, nil
	}
	np := buildBeliefTrainerNetworkPolicy(t, ns, s.cfg)
	if err := s.apply(ctx, np, func(existing client.Object) {
		e := existing.(*networkingv1.NetworkPolicy) //nolint:forcetypeassert // apply passes the type it was given
		e.Labels, e.OwnerReferences, e.Spec = np.Labels, np.OwnerReferences, np.Spec
	}); err != nil {
		return false, fmt.Errorf("ensure the belief trainer NetworkPolicy of tenant %s: %w", t.Name, err)
	}
	cj := buildBeliefTrainerCronJob(t, ns, s.cfg)
	if err := s.apply(ctx, cj, func(existing client.Object) {
		e := existing.(*batchv1.CronJob) //nolint:forcetypeassert // apply passes the type it was given
		e.Labels, e.OwnerReferences, e.Spec = cj.Labels, cj.OwnerReferences, cj.Spec
	}); err != nil {
		return false, fmt.Errorf("ensure the belief trainer CronJob of tenant %s: %w", t.Name, err)
	}
	return true, nil
}

// apply creates want, or updates the existing object with mutate.
func (s *beliefTrainerStep) apply(ctx context.Context, want client.Object, mutate func(client.Object)) error {
	existing, ok := want.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("%T is not a client.Object", want)
	}
	_, err := controllerutil.CreateOrUpdate(ctx, s.k8s, existing, func() error {
		mutate(existing)
		return nil
	})
	if err != nil {
		return fmt.Errorf("create or update %s/%s: %w", want.GetNamespace(), want.GetName(), err)
	}
	return nil
}
