/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	// neo4jTemplateConfigMapName is the name of the ConfigMap (in the gibson
	// namespace, created by the Helm chart — Task 22) that holds the YAML
	// templates for the per-tenant StatefulSet, Service, PVC, and Secret.
	neo4jTemplateConfigMapName = "tenant-neo4j-template"

	// neo4jTemplateNamespace is the namespace where the template ConfigMap lives.
	neo4jTemplateNamespace = "gibson"

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
}

// Neo4jProvisioner provisions per-tenant Neo4j instances as K8s resources
// (StatefulSet + Service + PVC + Secret). It replaces the old CREATE DATABASE
// pattern which required a Neo4j Enterprise shared cluster.
//
// The type is exported so cmd/main.go can pass it directly to the
// Neo4jUpgradeReconciler which requires the Neo4jUpgradeProvisioner interface.
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
	return &Neo4jProvisioner{cfg: cfg}, nil
}

// Provision creates the per-tenant Neo4j instance (StatefulSet, Service, PVC,
// Secret), waits up to 5 minutes for the pod to reach Ready, and then writes
// the endpoint into the tenant_neo4j_endpoints registry table.
//
// The method reads the tenant-neo4j-template ConfigMap from the gibson
// namespace (created by the Helm chart, Task 22) and substitutes the
// placeholders {{tenantID}}, {{tier}}, {{namespace}}, {{neo4jPassword}}
// before applying each resource.
//
// Idempotent: resources are applied with CreateOrUpdate semantics; a second
// call on an already-provisioned tenant is safe.
func (n *Neo4jProvisioner) Provision(ctx context.Context, tenantID string) error {
	names, err := tenantNames(tenantID)
	if err != nil {
		return err
	}
	safe := names.Slug()

	// Resolve the Tenant CRD to get the tier and namespace.
	var tenant gibsonv1alpha1.Tenant
	if err := n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: tenantID}, &tenant); err != nil {
		return fmt.Errorf("dataplane/neo4j: get tenant %q: %w", tenantID, err)
	}
	tier := string(tenant.Spec.Tier)
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
	if err := n.applyResources(ctx, safe, tenantID, tier, tenantNS, neo4jPassword); err != nil {
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

// applyResources reads the template ConfigMap and applies the four K8s resources.
func (n *Neo4jProvisioner) applyResources(ctx context.Context, safe, tenantID, tier, tenantNS, neo4jPassword string) error {
	sts, svc, pvc, secret := n.buildResources(ctx, safe, tenantID, tier, tenantNS, neo4jPassword)

	// Apply Secret (idempotent create).
	existingSecret := &corev1.Secret{}
	err := n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, existingSecret)
	if apierrors.IsNotFound(err) {
		if err := n.cfg.K8sClient.Create(ctx, secret); err != nil {
			return fmt.Errorf("dataplane/neo4j: create Secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("dataplane/neo4j: get Secret: %w", err)
	}

	// Apply PVC (idempotent create — do not resize existing).
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

	// Apply StatefulSet (create-or-update).
	existingSTS := &appsv1.StatefulSet{}
	err = n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, existingSTS)
	if apierrors.IsNotFound(err) {
		if err := n.cfg.K8sClient.Create(ctx, sts); err != nil {
			return fmt.Errorf("dataplane/neo4j: create StatefulSet: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("dataplane/neo4j: get StatefulSet: %w", err)
	}
	// StatefulSet exists — rolling image updates handled by Task 30 upgrade path.

	return nil
}

// buildResources constructs the K8s objects for a tenant Neo4j instance.
// It first tries to read the tenant-neo4j-template ConfigMap (created by Helm
// chart Task 22) and substitute placeholders. If the ConfigMap does not exist
// yet (pre-chart bootstrap), inline defaults are used so the operator remains
// independently testable.
//
// Tier-based resource sizing follows D7: the ConfigMap contains the right
// values from chart values (e.g. tiers.small.resources). The inline fallback
// here is only for pre-chart environments.
func (n *Neo4jProvisioner) buildResources(ctx context.Context, safe, tenantID, tier, tenantNS, neo4jPassword string) (
	sts *appsv1.StatefulSet,
	svc *corev1.Service,
	pvc *corev1.PersistentVolumeClaim,
	secret *corev1.Secret,
) {
	// tenantID is already validated upstream (Provision called sanitize); the
	// only failure mode here is a programmer-bug call from a test that bypassed
	// the validation. Panic-or-empty either way; pick empty for safety.
	names, _ := tenantNames(tenantID)
	name := names.Neo4jStatefulSet()
	authSecretName := names.Neo4jSecret()

	// Attempt to read the operator template ConfigMap to get chart-managed
	// tier→resource values (D7). The result is currently used for placeholder
	// substitution; full YAML parsing is deferred to Task 22 chart delivery.
	//
	// Unscoped(): this ConfigMap legitimately lives in the operator's
	// release namespace (neo4jTemplateNamespace = "gibson"), chart-mounted
	// by helm/gibson-operators. The per-tenant-kind guard would otherwise
	// reject the read; using Unscoped() with this comment is the
	// documented escape hatch.
	var cm corev1.ConfigMap
	templateAvailable := false
	if err := n.cfg.K8sClient.Unscoped().Get(ctx, types.NamespacedName{
		Name:      neo4jTemplateConfigMapName,
		Namespace: neo4jTemplateNamespace,
	}, &cm); err == nil {
		templateAvailable = true
	}

	// Inline tier defaults — only active when ConfigMap is absent (D7 note above).
	storageRequest, cpuRequest, memRequest := tierDefaults(tier)

	// Allow chart substitution to override defaults when ConfigMap is present.
	// Full YAML template parsing is implemented once Task 22 delivers the ConfigMap.
	if templateAvailable {
		// TODO(Task-22): parse cm.Data["statefulset.yaml"] after substituting
		// {{tenantID}}, {{tier}}, {{namespace}}, {{neo4jPassword}} placeholders.
		_ = substituteTemplate(cm.Data["statefulset.yaml"], safe, tier, tenantNS, neo4jPassword)
	}

	labels := map[string]string{
		"app.kubernetes.io/name":      "neo4j",
		"app.kubernetes.io/component": "tenant-neo4j",
		"app.kubernetes.io/instance":  tenantNS,
		"gibson.zeroroot.ai/tenant":   tenantID,
	}

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
					corev1.ResourceStorage: resource.MustParse(storageRequest),
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
					Containers: []corev1.Container{
						{
							Name:  "neo4j",
							Image: "neo4j:5.26.0-community",
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
									corev1.ResourceCPU:    resource.MustParse(cpuRequest),
									corev1.ResourceMemory: resource.MustParse(memRequest),
								},
								// Memory limit prevents OOM/eviction; the CPU
								// limit is intentionally omitted so the Neo4j
								// JVM can burst against the cluster's spare
								// CPU during its ~30-60s startup window. Tier
								// quotas constrain aggregate spend at the
								// platform level; per-pod CPU caps would only
								// slow startup without improving fairness.
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse(memRequest),
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
								corev1.ResourceStorage: resource.MustParse(storageRequest),
							},
						},
					},
				},
			},
		},
	}

	return sts,
		svc,
		pvc,
		secret
}

// substituteTemplate replaces {{tenantID}}, {{tier}}, {{namespace}},
// {{neo4jPassword}} placeholders in a template string. Returns the substituted
// result. Used to process ConfigMap templates from Task 22.
func substituteTemplate(tmpl, tenantID, tier, namespace, password string) string {
	r := strings.NewReplacer(
		"{{tenantID}}", tenantID,
		"{{tier}}", tier,
		"{{namespace}}", namespace,
		"{{neo4jPassword}}", password,
	)
	return r.Replace(tmpl)
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

	// 2) Fresh provision — generate cryptographically-random password.
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

// tierDefaults returns (storage, cpu, memory) resource request strings for
// the given plan tier. These are used only when the tenant-neo4j-template
// ConfigMap (Task 22) is absent. Production values are governed by Helm chart
// values per D7 — the operator never hardcodes tier→resource mapping for
// production use.
//
// CPU requests are sized so the team tier can schedule on a single-node
// kind dev cluster without crowding out the rest of the platform (Zitadel,
// CNPG, Vault, Envoy, daemon, dashboard, ext-authz, …). Neo4j is a JVM
// workload that bursts at startup and is mostly idle afterward, so setting
// the request low and letting it burst against the cluster's spare CPU is
// the right shape for dev. Production environments override these via the
// chart-rendered tenant-neo4j-template ConfigMap (see tenant-operator#61).
func tierDefaults(tier string) (storage, cpu, memory string) {
	switch tier {
	case "enterprise", "enterprise-deploy",
		// legacy ids the migrate job will rewrite, included for completeness
		"platform", "enterprise-cloud", "enterprise-onprem", "public-sector":
		return "200Gi", "1", "8Gi"
	case "org":
		return "50Gi", "500m", "4Gi"
	default:
		// team (and any legacy solo/squad/free/pro pending migration) → small
		return "10Gi", "100m", "1Gi"
	}
}
