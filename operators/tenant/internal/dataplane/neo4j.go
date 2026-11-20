// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
	tenantns "github.com/zeroroot-ai/gibson/operators/tenant/internal/tenant"
)

const (
	// neo4jProvisionTimeout is the maximum time to wait for the per-tenant
	// Neo4j pod to reach Ready after resources are applied.
	neo4jProvisionTimeout = 2 * time.Minute

	// neo4jPollInterval is how frequently the provisioner checks pod readiness.
	neo4jPollInterval = 5 * time.Second

	// neo4jSizeConfigMapName is the ConfigMap that the Helm chart renders into
	// the platform namespace. It holds the default size of a tenant Neo4j in
	// three keys: storage, cpu and memory. The chart owns the numbers and
	// this operator owns the shape.
	neo4jSizeConfigMapName = "tenant-neo4j-size"

	// The keys of that ConfigMap.
	neo4jSizeStorageKey = "storage"
	neo4jSizeCPUKey     = "cpu"
	neo4jSizeMemoryKey  = "memory"

	// neo4jTemplateNamespace is the namespace where the size ConfigMap lives.
	neo4jTemplateNamespace = "gibson"

	// neo4jContainerName is the name of the database container in the
	// StatefulSet of a tenant.
	neo4jContainerName = "neo4j"

	// neo4jBoltPort is the Bolt protocol port exposed by Neo4j.
	neo4jBoltPort = 7687
)

// Neo4jConfig holds the wiring needed by the Neo4j provisioner.
// The previous URI/Username/Password/MigrationsDir fields for admin-driver
// access are replaced by a controller-runtime K8s client.
type Neo4jConfig struct {
	// K8sClient is the per-tenant-scoped controller-runtime client used to
	// apply and delete K8s resources. Required. The wrapper (see
	// internal/dataplane/client) rejects any per-tenant-kind write that
	// targets the operator's release namespace, which closes the bug
	// class behind tenant-operator#57. Use K8sClient.Unscoped() ONLY for
	// the legitimate operator-ns / cluster-scope reads documented at
	// each call site.
	K8sClient *dpclient.Client

	// VaultClient is the admin Vault client used to write Neo4j credentials
	// into the per-tenant Vault namespace at "infra/neo4j" after provisioning.
	// Required — the operator is single-code-path (tenant-operator#197).
	// Spec: per-tenant-data-plane-completion Task 19a (D3 amended).
	VaultClient vaultadmin.AdminClient

	// PlatformNamespace is the namespace the gibson daemon runs in. It is
	// the namespaceSelector half of the per-tenant Neo4j NetworkPolicy's
	// single ingress peer (gibson#1255). The chart sets OPERATOR_NAMESPACE
	// from the downward API, so this is the release namespace in every
	// environment. Empty falls back to neo4jTemplateNamespace.
	PlatformNamespace string

	// Image is the per-tenant Neo4j image, a reference with a digest. The
	// chart sets it from the mirror (TENANT_NEO4J_IMAGE), so an air-gapped
	// install pulls it from its own registry (gibson#1051). Required.
	Image string
}

// Neo4jProvisioner provisions per-tenant Neo4j instances as K8s resources
// (StatefulSet + Service + PVC + Secret). It replaces the old CREATE DATABASE
// pattern which required a Neo4j Enterprise shared cluster.
type Neo4jProvisioner struct {
	cfg Neo4jConfig
}

// NewNeo4jProvisioner constructs a Neo4j provisioner.
func NewNeo4jProvisioner(cfg Neo4jConfig) (*Neo4jProvisioner, error) {
	if cfg.K8sClient == nil {
		return nil, fmt.Errorf("dataplane/neo4j: K8sClient required")
	}
	if cfg.VaultClient == nil {
		return nil, fmt.Errorf("dataplane/neo4j: VaultClient required")
	}
	if err := validateNeo4jImage(cfg.Image); err != nil {
		return nil, err
	}
	return &Neo4jProvisioner{cfg: cfg}, nil
}

// validateNeo4jImage refuses a tenant Neo4j image with no digest. A tag alone
// can move, and every other image of the platform is pinned by digest.
func validateNeo4jImage(image string) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return errors.New("dataplane/neo4j: Image required (TENANT_NEO4J_IMAGE)")
	}
	if _, digest, ok := strings.Cut(image, "@sha256:"); !ok || len(digest) != 64 {
		return fmt.Errorf("dataplane/neo4j: Image %q has no sha256 digest", image)
	}
	return nil
}

// Provision creates the per-tenant Neo4j instance (StatefulSet, Service, PVC,
// Secret, NetworkPolicy), waits for the pod to reach Ready, and then writes
// the credentials to the secret store.
//
// The size of the instance is the default size of the chart (the
// tenant-neo4j-size ConfigMap). A field that limits.Neo4j sets replaces the
// same field of the default. No plan sets the size.
//
// Idempotent: resources are applied with CreateOrUpdate semantics; a second
// call on an already-provisioned tenant is safe.
func (n *Neo4jProvisioner) Provision(ctx context.Context, tenantID string, limits Limits) error {
	names, err := tenantNames(tenantID)
	if err != nil {
		return err
	}
	tenantNS, err := tenantns.NamespaceFor(ctx, n.cfg.K8sClient, tenantID)
	if err != nil {
		return fmt.Errorf("dataplane/neo4j: resolve namespace: %w", err)
	}

	// Derive the Neo4j password from the KEK.
	neo4jPassword, err := n.deriveNeo4jPassword(ctx, tenantID, tenantNS)
	if err != nil {
		return fmt.Errorf("dataplane/neo4j: derive password: %w", err)
	}

	// Apply the four K8s resources first so we have a definitive bolt URI
	// to write to Vault.
	if err := n.applyResources(ctx, tenantID, tenantNS, neo4jPassword, limits.Neo4j); err != nil {
		return err
	}

	// Wait for the StatefulSet pod to reach Ready.
	stsName := names.Neo4jStatefulSet()
	if err := n.waitForReady(ctx, tenantID, stsName, tenantNS); err != nil {
		return fmt.Errorf("dataplane/neo4j: wait for ready %q: %w", stsName, err)
	}

	boltURI := fmt.Sprintf("bolt://%s.%s.svc.cluster.local:%d", names.Neo4jService(), tenantNS, neo4jBoltPort)

	// Write credentials to Vault. Spec
	// tenant-provisioning-unification-phase2 Phase 6.3: include bolt_uri
	// so the daemon can resolve everything from a single broker.Get.
	if err := n.cfg.VaultClient.WriteInfraNeo4jCredentials(ctx, tenantID, pdataplane.Neo4jCredentials{
		BoltURI:  boltURI,
		Username: "neo4j",
		Password: neo4jPassword,
	}); err != nil {
		return fmt.Errorf("dataplane/neo4j: write credentials to Vault for tenant %q: %w", tenantID, err)
	}

	return nil
}

// Deprovision deletes the four K8s resources and removes the registry row.
// All deletes use IgnoreNotFound so the method is idempotent.
func (n *Neo4jProvisioner) Deprovision(ctx context.Context, tenantID string) error {
	names, err := tenantNames(tenantID)
	if err != nil {
		return err
	}

	// Resolve the per-tenant namespace via the canonical resolver — same
	// source of truth as Provision (Status.Namespace || derived). The
	// per-tenant Role only grants delete verbs in the tenant namespace,
	// so this is required for correctness, not just consistency.
	tenantNS, nsErr := tenantns.NamespaceFor(ctx, n.cfg.K8sClient, tenantID)
	if nsErr != nil {
		return fmt.Errorf("dataplane/neo4j: resolve namespace: %w", nsErr)
	}

	base := names.Neo4jStatefulSet()
	var errs []error

	// Delete StatefulSet.
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: base, Namespace: tenantNS}}
	if err := client.IgnoreNotFound(n.cfg.K8sClient.Delete(ctx, sts)); err != nil {
		errs = append(errs, fmt.Errorf("delete StatefulSet %q: %w", base, err))
	}

	// Delete Service.
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: base, Namespace: tenantNS}}
	if err := client.IgnoreNotFound(n.cfg.K8sClient.Delete(ctx, svc)); err != nil {
		errs = append(errs, fmt.Errorf("delete Service %q: %w", base, err))
	}

	// Delete PVC.
	pvcName := "data-" + base + "-0"
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: pvcName, Namespace: tenantNS}}
	if err := client.IgnoreNotFound(n.cfg.K8sClient.Delete(ctx, pvc)); err != nil {
		errs = append(errs, fmt.Errorf("delete PVC %q: %w", pvcName, err))
	}

	// Delete NetworkPolicy. Removed with the tenant so a re-provisioned
	// tenant of the same name never inherits a stale policy.
	npName := names.Neo4jNetworkPolicy()
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: npName, Namespace: tenantNS}}
	if err := client.IgnoreNotFound(n.cfg.K8sClient.Delete(ctx, np)); err != nil {
		errs = append(errs, fmt.Errorf("delete NetworkPolicy %q: %w", npName, err))
	}

	// Delete Secret.
	secretName := base + "-auth"
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: tenantNS}}
	if err := client.IgnoreNotFound(n.cfg.K8sClient.Delete(ctx, secret)); err != nil {
		errs = append(errs, fmt.Errorf("delete Secret %q: %w", secretName, err))
	}

	// Delete Neo4j credentials from Vault. This MUST NOT delete the tenant
	// namespace itself — that is the responsibility of the
	// DeprovisionSecretsBackend saga step (ensure_vault_namespace.go).
	// Spec: per-tenant-data-plane-completion Task 19a (D3 amended).
	if delErr := n.cfg.VaultClient.DeleteInfraNeo4j(ctx, tenantID); delErr != nil {
		errs = append(errs, fmt.Errorf("delete neo4j credentials from Vault: %w", delErr))
	}

	return errors.Join(errs...)
}

// sizeFor resolves the size of the instance of one tenant: the default of the
// chart, then the size on the Tenant, then the floor of an instance that runs.
// It returns the StatefulSet that exists, or nil when there is none.
func (n *Neo4jProvisioner) sizeFor(
	ctx context.Context, tenantID, tenantNS string, override *gibsonv1alpha1.TenantNeo4jResources,
) (neo4jSize, *appsv1.StatefulSet, error) {
	names, err := tenantNames(tenantID)
	if err != nil {
		return neo4jSize{}, nil, err
	}
	chartDefault, err := n.defaultSize(ctx)
	if err != nil {
		return neo4jSize{}, nil, fmt.Errorf("dataplane/neo4j: tenant %q: %w", tenantID, err)
	}
	size, err := resolveNeo4jSize(chartDefault, override)
	if err != nil {
		return neo4jSize{}, nil, fmt.Errorf("dataplane/neo4j: tenant %q: %w", tenantID, err)
	}

	// Read the StatefulSet before the build. An instance that runs keeps the
	// CPU and the memory it has when only the default is smaller.
	existingSTS := &appsv1.StatefulSet{}
	stsKey := types.NamespacedName{Name: names.Neo4jStatefulSet(), Namespace: tenantNS}
	if getErr := n.cfg.K8sClient.Get(ctx, stsKey, existingSTS); getErr != nil {
		if apierrors.IsNotFound(getErr) {
			return size, nil, nil
		}
		return neo4jSize{}, nil, fmt.Errorf("dataplane/neo4j: get StatefulSet: %w", getErr)
	}
	return size.notBelowRunning(existingSTS, override), existingSTS, nil
}

// applyResources resolves the size of the instance and applies the five K8s
// resources.
func (n *Neo4jProvisioner) applyResources(
	ctx context.Context, tenantID, tenantNS, neo4jPassword string, override *gibsonv1alpha1.TenantNeo4jResources,
) error {
	size, existingSTS, err := n.sizeFor(ctx, tenantID, tenantNS, override)
	if err != nil {
		return err
	}
	sts, svc, pvc, secret, np := n.buildResources(tenantID, tenantNS, neo4jPassword, size)

	// Apply NetworkPolicy FIRST — before the StatefulSet that creates the
	// pod — so there is no window in which a tenant's Neo4j is running
	// with no policy in front of it. Unlike the Secret and PVC below this
	// is a create-or-update: the policy is the security boundary, so any
	// hand-edit to its spec must be reconciled away rather than preserved.
	existingNP := &networkingv1.NetworkPolicy{}
	err = n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: np.Name, Namespace: np.Namespace}, existingNP)
	switch {
	case apierrors.IsNotFound(err):
		if err := n.cfg.K8sClient.Create(ctx, np); err != nil {
			return fmt.Errorf("dataplane/neo4j: create NetworkPolicy: %w", err)
		}
	case err != nil:
		return fmt.Errorf("dataplane/neo4j: get NetworkPolicy: %w", err)
	default:
		existingNP.Spec = np.Spec
		existingNP.Labels = np.Labels
		if err := n.cfg.K8sClient.Update(ctx, existingNP); err != nil {
			return fmt.Errorf("dataplane/neo4j: update NetworkPolicy: %w", err)
		}
	}

	// Apply Secret (idempotent create).
	existingSecret := &corev1.Secret{}
	err = n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, existingSecret)
	if apierrors.IsNotFound(err) {
		if err := n.cfg.K8sClient.Create(ctx, secret); err != nil {
			return fmt.Errorf("dataplane/neo4j: create Secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("dataplane/neo4j: get Secret: %w", err)
	}

	// Apply PVC (idempotent create). An existing PVC keeps its size:
	// Kubernetes refuses a smaller request, and this operator does not grow
	// a volume. The storage size applies only when the PVC is created.
	existingPVC := &corev1.PersistentVolumeClaim{}
	err = n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: pvc.Name, Namespace: pvc.Namespace}, existingPVC)
	if apierrors.IsNotFound(err) {
		if err := n.cfg.K8sClient.Create(ctx, pvc); err != nil {
			return fmt.Errorf("dataplane/neo4j: create PVC: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("dataplane/neo4j: get PVC: %w", err)
	}

	// Apply Service.
	existingSvc := &corev1.Service{}
	err = n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}, existingSvc)
	if apierrors.IsNotFound(err) {
		if err := n.cfg.K8sClient.Create(ctx, svc); err != nil {
			return fmt.Errorf("dataplane/neo4j: create Service: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("dataplane/neo4j: get Service: %w", err)
	}

	return n.applyStatefulSet(ctx, sts, existingSTS)
}

// applyStatefulSet creates the StatefulSet, or reconciles the pod template of
// the StatefulSet that exists.
func (n *Neo4jProvisioner) applyStatefulSet(ctx context.Context, sts, existingSTS *appsv1.StatefulSet) error {
	if existingSTS == nil {
		if err := n.cfg.K8sClient.Create(ctx, sts); err != nil {
			return fmt.Errorf("dataplane/neo4j: create StatefulSet: %w", err)
		}
	} else {
		// The StatefulSet already exists. Reconcile its pod template so a
		// tenant provisioned before APOC Core was required picks the plugin
		// and the procedure allowlist up on the next reconcile — otherwise
		// every Host projection into that tenant fails forever, because
		// apoc.merge.node is not registered there (ADR-0112, gibson#1257).
		// This is the "per-tenant StatefulSet change plus a restart" the ADR
		// records: rewriting spec.template rolls the pod.
		//
		// Only spec.template is reconciled. spec.volumeClaimTemplates,
		// spec.selector and spec.serviceName are immutable on a StatefulSet
		// and an update that touched them would be rejected outright. So a
		// storage size that differs from the claim template of a running
		// instance changes nothing, and Kubernetes refuses nothing.
		//
		// DeepDerivative treats fields we do not set as "don't care", so
		// server-side defaults (terminationMessagePath, dnsPolicy, …) do not
		// read as drift and the operator does not rewrite an unchanged
		// template on every reconcile.
		if !equality.Semantic.DeepDerivative(sts.Spec.Template, existingSTS.Spec.Template) {
			existingSTS.Spec.Template = sts.Spec.Template
			if err := n.cfg.K8sClient.Update(ctx, existingSTS); err != nil {
				return fmt.Errorf("dataplane/neo4j: update StatefulSet pod template: %w", err)
			}
		}
	}

	return nil
}

// buildResources constructs the K8s objects for a tenant Neo4j instance of the
// given size. The memory of the size is the request and the limit of the
// container, and neo4jMemoryEnv pins the JVM heap and the page cache from it.
func (n *Neo4jProvisioner) buildResources(tenantID, tenantNS, neo4jPassword string, size neo4jSize) (
	sts *appsv1.StatefulSet,
	svc *corev1.Service,
	pvc *corev1.PersistentVolumeClaim,
	secret *corev1.Secret,
	np *networkingv1.NetworkPolicy,
) {
	// tenantID is already validated upstream (Provision called sanitize); the
	// only failure mode here is a programmer-bug call from a test that bypassed
	// the validation. Panic-or-empty either way; pick empty for safety.
	names, _ := tenantNames(tenantID)
	name := names.Neo4jStatefulSet()
	authSecretName := names.Neo4jSecret()

	// Shared with buildNeo4jNetworkPolicy's podSelector — see
	// neo4j_networkpolicy.go. Keeping one constructor is what stops the
	// policy from silently selecting nothing.
	labels := neo4jLabels(tenantID, tenantNS)

	// Secret: username + password for the Neo4j instance.
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      authSecretName,
			Namespace: tenantNS,
			Labels:    labels,
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"NEO4J_AUTH": "neo4j/" + neo4jPassword,
			"username":   "neo4j",
			"password":   neo4jPassword,
		},
	}

	// PVC: standalone persistent storage for Neo4j data. Separate from the
	// VolumeClaimTemplate in the StatefulSet so it can be deleted independently
	// during deprovisioning without deleting the STS first.
	//
	// StorageClassName is left nil so the cluster's default StorageClass is
	// used. Passing &"" here would explicitly disable dynamic provisioning and
	// strand the PVC in Pending forever (no PV would ever bind to it).
	pvc = &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "data-" + name + "-0",
			Namespace: tenantNS,
			Labels:    labels,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: size.Storage,
				},
			},
		},
	}

	// Service: ClusterIP exposing Bolt port only. The daemon reads the registry
	// to discover this DNS name: bolt://tenant-<safe>-neo4j.<ns>.svc.cluster.local:7687
	svc = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tenantNS,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "bolt",
					Port:       int32(neo4jBoltPort),
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(neo4jBoltPort),
				},
			},
		},
	}

	// StatefulSet: single-replica Neo4j Community container.
	replicas := int32(1)
	sts = &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tenantNS,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			ServiceName: name,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					// APOC Core is installed by copying the jar out of the
					// image, never with NEO4J_PLUGINS — see neo4j_apoc.go and
					// pkg/platform/dataplane/apoc.go for why that distinction
					// is load-bearing (ADR-0112, gibson#1257).
					SecurityContext: neo4jPodSecurityContext(),
					InitContainers:  []corev1.Container{apocInitContainer(n.cfg.Image)},
					Volumes:         []corev1.Volume{apocPluginVolume()},
					Containers: []corev1.Container{
						{
							Name:            neo4jContainerName,
							Image:           n.cfg.Image,
							SecurityContext: neo4jContainerSecurityContext(),
							Env:             append(neo4jSecurityEnv(), neo4jMemoryEnv(size.Memory)...),
							Ports: []corev1.ContainerPort{
								{
									Name:          "bolt",
									ContainerPort: int32(neo4jBoltPort),
									Protocol:      corev1.ProtocolTCP,
								},
							},
							EnvFrom: []corev1.EnvFromSource{
								{
									SecretRef: &corev1.SecretEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: authSecretName,
										},
									},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    size.CPU,
									corev1.ResourceMemory: size.Memory,
								},
								// Memory limit prevents OOM/eviction; the CPU
								// limit is intentionally omitted so the Neo4j
								// JVM can burst against the cluster's spare
								// CPU during its ~30-60s startup window. A
								// CPU limit on the pod would only slow the
								// start.
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: size.Memory,
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(neo4jBoltPort),
									},
								},
								InitialDelaySeconds: 30,
								PeriodSeconds:       10,
								FailureThreshold:    6,
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "data", MountPath: "/data"},
								apocPluginMount(),
							},
						},
					},
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "data",
						Labels: labels,
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: size.Storage,
							},
						},
					},
				},
			},
		},
	}

	// NetworkPolicy: bolt ingress from the daemon only, egress DNS-only.
	// Defence in depth behind the single-writer projector (ADR-0112,
	// gibson#1255); INERT until the CNI enforces NetworkPolicy.
	np = buildNeo4jNetworkPolicy(names, tenantID, tenantNS, n.cfg.PlatformNamespace)

	return sts, svc, pvc, secret, np
}

// waitForReady polls the StatefulSet's ReadyReplicas until it reaches 1 or
// the context deadline (neo4jProvisionTimeout) is exceeded. Each iteration
// also re-Gets the parent Tenant CR and aborts if DeletionTimestamp is set —
// without that early-out, a `kubectl delete tenant` issued mid-provision
// gets queued behind the full timeout, blocking the controller's Reconcile
// dispatch (and therefore reconcileDelete) from running for minutes. See
// tenant-operator#60.
func (n *Neo4jProvisioner) waitForReady(ctx context.Context, tenantID, stsName, namespace string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, neo4jProvisionTimeout)
	defer cancel()

	return wait.PollUntilContextTimeout(timeoutCtx, neo4jPollInterval, neo4jProvisionTimeout, true,
		func(ctx context.Context) (bool, error) {
			// Cancel mid-wait if the Tenant CR is being deleted — otherwise
			// the saga blocks here for the full provision timeout while the
			// controller waits to run Deprovision.
			var t gibsonv1alpha1.Tenant
			if err := n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: tenantID}, &t); err == nil && !t.DeletionTimestamp.IsZero() {
				return false, fmt.Errorf("aborted: tenant %q is being deleted", tenantID)
			}

			var sts appsv1.StatefulSet
			if err := n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: stsName, Namespace: namespace}, &sts); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil // still creating, keep polling
				}
				return false, err
			}
			return sts.Status.ReadyReplicas >= 1, nil
		},
	)
}

// deriveNeo4jPassword returns the per-tenant Neo4j password. Phase 3.2
// of spec tenant-provisioning-unification-phase2: random password
// (crypto/rand 32-byte base64), generated only on first provision —
// subsequent reconciles read the existing password from the per-tenant
// K8s Secret so the Neo4j pod's data dir (which persists the original
// password) stays in sync with the env var.
func (n *Neo4jProvisioner) deriveNeo4jPassword(ctx context.Context, tenantID, tenantNS string) (string, error) {
	// 1) Reuse existing password if the K8s Secret already exists.
	names, err := tenantNames(tenantID)
	if err != nil {
		return "", err
	}
	secretName := names.Neo4jSecret()
	existing := &corev1.Secret{}
	getErr := n.cfg.K8sClient.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: secretName}, existing)
	if getErr == nil {
		if v, ok := existing.Data["NEO4J_AUTH"]; ok && len(v) > len("neo4j/") {
			return strings.TrimPrefix(string(v), "neo4j/"), nil
		}
	}

	// 2) The store. A restore (hosted, ADR-0083) brings the OpenBao volume
	// and the Neo4j data volume back and NO Secret, so the password the
	// data directory was initialised with lives at infra/neo4j in the
	// tenant namespace and nowhere else. Generating a fresh one here wrote
	// a Secret the restored store did not accept: every client failed,
	// Neo4j rate-limited the user, and the exit test read "The client has
	// provided incorrect authentication details too many times in a row"
	// (blocker 3, hosted run 34377075123, 2026-09-09).
	if creds, found, err := n.cfg.VaultClient.ReadInfraNeo4jCredentials(ctx, tenantID); err != nil {
		return "", fmt.Errorf("dataplane/neo4j: read credentials from Vault for tenant %q: %w", tenantID, err)
	} else if found && creds.Password != "" {
		return creds.Password, nil
	}

	// 3) Fresh provision — generate cryptographically-random password.
	// 32 raw bytes → 43-char base64-url (no padding); well within Neo4j's
	// password length limits and high entropy.
	//
	// The leading "P" prefix is load-bearing: the Neo4j docker image's
	// entrypoint passes the password to `neo4j-admin dbms set-initial-
	// password "$password"`, and base64-url's alphabet includes `-`. A
	// password that starts with `-` is parsed by neo4j-admin's CLI as an
	// unknown flag and the container crashloops with
	// "Missing required parameter: '<password>'". Prefixing with a known
	// alphanumeric char ensures the password is always treated as a
	// positional argument. See tenant-operator#67.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("dataplane/neo4j: rand.Read failed: %w", err)
	}
	return "P" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// neo4jSize is the size of one tenant Neo4j, in the shape this operator
// applies it: one storage request, one CPU request, and one memory number used
// for BOTH the request and the limit (neo4jMemoryEnv pins the JVM heap and page
// cache from it, so request and limit must agree or the JVM is sized against a
// number the container may not get).
type neo4jSize struct {
	Storage resource.Quantity
	CPU     resource.Quantity
	Memory  resource.Quantity
}

// builtInNeo4jSize is the size for a cluster with no chart, where the
// tenant-neo4j-size ConfigMap does not exist. It equals the default of the
// chart: the smallest size at which a tenant Neo4j with a pinned heap is
// measured to run, and a size that schedules on a single-node kind cluster.
func builtInNeo4jSize() neo4jSize {
	return neo4jSize{
		Storage: resource.MustParse("10Gi"),
		CPU:     resource.MustParse("100m"),
		Memory:  resource.MustParse("1Gi"),
	}
}

// defaultSize returns the default size of a tenant Neo4j. The chart renders it
// into the tenant-neo4j-size ConfigMap. When the ConfigMap does not exist, the
// built-in size applies.
//
// A ConfigMap that is present and wrong is an ERROR, not a reason to use the
// built-in size. A fall-through would let an install run the built-in size
// while its values say a different size and everything reports healthy.
func (n *Neo4jProvisioner) defaultSize(ctx context.Context) (neo4jSize, error) {
	// Unscoped(): this ConfigMap lives in the release namespace of the
	// operator, not in a tenant namespace. The per-tenant-kind guard would
	// refuse the read, and Unscoped() with this comment is the documented
	// exception.
	var cm corev1.ConfigMap
	err := n.cfg.K8sClient.Unscoped().Get(ctx, types.NamespacedName{
		Name:      neo4jSizeConfigMapName,
		Namespace: neo4jTemplateNamespace,
	}, &cm)
	if apierrors.IsNotFound(err) {
		return builtInNeo4jSize(), nil
	}
	if err != nil {
		return neo4jSize{}, fmt.Errorf(
			"get the %s ConfigMap in %s: %w", neo4jSizeConfigMapName, neo4jTemplateNamespace, err)
	}
	size, err := parseNeo4jSize(cm.Data)
	if err != nil {
		return neo4jSize{}, fmt.Errorf(
			"the %s ConfigMap in %s is present but unusable (%w). The chart renders it, so this is a chart defect",
			neo4jSizeConfigMapName, neo4jTemplateNamespace, err)
	}
	return size, nil
}

// parseNeo4jSize reads the three keys of the tenant-neo4j-size ConfigMap.
//
// Each quantity is parsed here and not where it is used, so a typo in a values
// file is a reported error and never a panic in the apply path.
func parseNeo4jSize(data map[string]string) (neo4jSize, error) {
	var size neo4jSize
	for _, field := range []struct {
		key string
		dst *resource.Quantity
	}{
		{neo4jSizeStorageKey, &size.Storage},
		{neo4jSizeCPUKey, &size.CPU},
		{neo4jSizeMemoryKey, &size.Memory},
	} {
		value := strings.TrimSpace(data[field.key])
		if value == "" {
			return neo4jSize{}, fmt.Errorf("the %s key is missing or empty", field.key)
		}
		q, err := resource.ParseQuantity(value)
		if err != nil {
			return neo4jSize{}, fmt.Errorf("the %s key has an unparseable quantity %q: %w", field.key, value, err)
		}
		*field.dst = q
	}
	if err := size.validate(); err != nil {
		return neo4jSize{}, err
	}
	return size, nil
}

// resolveNeo4jSize applies the size a Tenant sets (spec.resources.neo4j) to
// the default of the chart. A field the Tenant does not set keeps the default.
func resolveNeo4jSize(chartDefault neo4jSize, override *gibsonv1alpha1.TenantNeo4jResources) (neo4jSize, error) {
	size := chartDefault
	if override == nil {
		return size, nil
	}
	if err := override.Validate(); err != nil {
		return neo4jSize{}, fmt.Errorf("spec.resources.neo4j: %w", err)
	}
	if override.Storage != nil {
		size.Storage = override.Storage.DeepCopy()
	}
	if override.CPU != nil {
		size.CPU = override.CPU.DeepCopy()
	}
	if override.Memory != nil {
		size.Memory = override.Memory.DeepCopy()
	}
	return size, nil
}

// validate applies to a size the same rules that a Tenant size obeys.
func (s neo4jSize) validate() error {
	res := &gibsonv1alpha1.TenantNeo4jResources{Storage: &s.Storage, CPU: &s.CPU, Memory: &s.Memory}
	if err := res.Validate(); err != nil {
		return fmt.Errorf("the size is not usable: %w", err)
	}
	return nil
}

// notBelowRunning keeps the CPU and the memory of an instance that runs when
// the size is smaller and the Tenant did not set that field.
//
// The default of the chart is the size of a NEW instance. A default that is
// smaller than a running instance must not take resources away from it: the
// heap and the page cache follow the memory, so a smaller default would
// restart the database with a fraction of its memory. This is what keeps a
// tenant that was sized by a plan (4Gi or 8Gi) at its size after the plan
// stopped being the input. A default that is larger still raises the
// instance, and a field the Tenant sets always applies as written, so a
// deliberate reduction stays possible.
//
// Storage is not handled here. The PVC of a running instance is never
// rewritten, so its storage cannot shrink.
func (s neo4jSize) notBelowRunning(
	running *appsv1.StatefulSet, override *gibsonv1alpha1.TenantNeo4jResources,
) neo4jSize {
	for i := range running.Spec.Template.Spec.Containers {
		c := &running.Spec.Template.Spec.Containers[i]
		if c.Name != neo4jContainerName {
			continue
		}
		if cpu, ok := c.Resources.Requests[corev1.ResourceCPU]; ok &&
			(override == nil || override.CPU == nil) && cpu.Cmp(s.CPU) > 0 {
			s.CPU = cpu
		}
		if mem, ok := c.Resources.Requests[corev1.ResourceMemory]; ok &&
			(override == nil || override.Memory == nil) && mem.Cmp(s.Memory) > 0 {
			s.Memory = mem
		}
	}
	return s
}

// neo4jMemoryEnv pins Neo4j's heap and page cache to sizes derived from the
// memory limit of the instance, instead of letting Neo4j size itself from detected
// memory. Left unset, Neo4j computes both from what it detects, and inside a
// kind node on a GitHub-hosted runner that detection lies: the computed sizes
// exceeded the container limit and every start failed with "Invalid memory
// configuration - exceeds physical memory", so the per-tenant Neo4j never
// became ready, the data plane stayed Failed, and the Tenant CR never reached
// Ready (deploy#1766, exit-test-vanilla-install run 33600876035; the platform
// chart pins its own Neo4j for the same reason).
//
// Heap gets a quarter of the limit and the page cache an eighth, leaving well
// over half for JVM native overhead and APOC: 1Gi -> 256m heap + 128m cache,
// 8Gi -> 2g heap + 1g cache. Initial heap equals max heap so the JVM never
// grows into a limit-crossing resize.
func neo4jMemoryEnv(memLimit resource.Quantity) []corev1.EnvVar {
	mib := memLimit.Value() / (1024 * 1024)
	heap := fmt.Sprintf("%dm", mib/4)
	cache := fmt.Sprintf("%dm", mib/8)
	return []corev1.EnvVar{
		{Name: pdataplane.Neo4jSettingEnvVar("server.memory.heap.initial_size"), Value: heap},
		{Name: pdataplane.Neo4jSettingEnvVar("server.memory.heap.max_size"), Value: heap},
		{Name: pdataplane.Neo4jSettingEnvVar("server.memory.pagecache.size"), Value: cache},
	}
}
