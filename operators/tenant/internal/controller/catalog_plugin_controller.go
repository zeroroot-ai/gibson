// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// Catalog plugins for each tenant (gibson#815).
//
// A tenant enables a catalog plugin through the daemon. The daemon records
// the wish and starts nothing (ADR-0023). This loop pulls the wishes and runs
// one instance of the plugin for each (tenant, plugin) pair, in the namespace
// tenant-<tenant>-plugins, with the identity
// spiffe://<trust domain>/plugin/<plugin>/<tenant>.
//
// The names and the fields of each object are a contract with the admission
// policies of the chart. Change them only together with the chart.

const (
	defaultCatalogPluginInterval = 30 * time.Second

	// catalogPluginManagedBy is the label value every object of this loop
	// carries. The loop deletes only objects with this label.
	catalogPluginManagedBy = "gibson-tenant-operator"

	labelManagedBy         = "app.kubernetes.io/managed-by"
	labelPluginTenant      = "gibson.zeroroot.ai/tenant"
	labelPlugin            = "gibson.zeroroot.ai/plugin"
	labelPluginNamespaceOf = "gibson.zeroroot.ai/plugin-namespace-of"
	labelAppName           = "app.kubernetes.io/name"
	labelAppComponent      = "app.kubernetes.io/component"
	pluginComponent        = "plugin"

	envoyCAConfigMap = "gibson-envoy-ca"
	envoyCAKey       = "ca.crt"

	// pluginNamespaceClusterRole is the ClusterRole of the chart that holds
	// the rules the operator needs inside a plugin namespace. The operator
	// binds it into each plugin namespace with a RoleBinding. It can bind this
	// one name and cannot change its rules.
	pluginNamespaceClusterRole = "gibson-tenant-operator-plugin-namespace"
	// pluginNamespaceRoleBinding is the name of that RoleBinding.
	pluginNamespaceRoleBinding = "gibson-tenant-operator-plugins"

	// The SPIRE agent socket, as the CSI driver mounts it. The init container
	// waits for the socket, and the plugin reads it at a second mount path.
	spireSocketVolume     = "spire-agent-socket"
	spireWaitMountPath    = "/run/spire/agent"
	spireWaitSocket       = spireWaitMountPath + "/spire-agent.sock"
	spirePluginMountPath  = "/run/spire/sockets"
	spirePluginSocketAddr = "unix://" + spirePluginMountPath + "/api.sock"

	// Phases the loop reports to the daemon.
	catalogPluginPhaseProvisioning = "Provisioning"
	catalogPluginPhaseReady        = "Ready"
	catalogPluginPhaseFailed       = "Failed"
)

// clusterSPIFFEIDGVK is the SPIRE controller manager resource that registers a
// workload identity.
var clusterSPIFFEIDGVK = schema.GroupVersionKind{Group: "spire.spiffe.io", Version: "v1alpha1", Kind: "ClusterSPIFFEID"}

// catalogPluginNameRe is the rule for a tenant name and a plugin id in this
// loop. Both go into a namespace name, object names and a SPIFFE ID path, so
// the rule is the DNS label rule: no dot, no underscore, no upper case.
var catalogPluginNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// CatalogPluginDaemon is the slice of the daemon client this loop needs.
type CatalogPluginDaemon interface {
	ListDesiredCatalogPlugins(ctx context.Context) ([]provision.DesiredCatalogPlugin, error)
	ReportCatalogPluginStatus(ctx context.Context, tenantID, pluginID, phase, lastError string) error
}

// CatalogPluginConfig holds the facts about the install that the chart gives
// the operator. Each one is an env value on the operator Deployment.
type CatalogPluginConfig struct {
	// SpireClassName is the class of the SPIRE controller manager the chart
	// installs (PLUGIN_SPIRE_CLASS_NAME). Required.
	SpireClassName string
	// TrustDomain is the SPIFFE trust domain of the install
	// (PLUGIN_TRUST_DOMAIN). Required. No code holds it as a literal (ADR-0164).
	TrustDomain string
	// GibsonURL is the value of GIBSON_URL in a plugin pod
	// (PLUGIN_GIBSON_URL). Required.
	GibsonURL string
	// EnvoyCAFile is the file that holds the public certificate of the edge CA
	// (PLUGIN_ENVOY_CA_FILE). Empty means the edge uses public roots: the loop
	// then writes no CA ConfigMap and the pod has no CA mount.
	EnvoyCAFile string
	// WaitForSpireImage is the image of the init container that waits for the
	// SPIRE agent socket (PLUGIN_WAIT_FOR_SPIRE_IMAGE). Required.
	WaitForSpireImage string
	// OperatorServiceAccount and OperatorNamespace name the ServiceAccount of
	// this operator (OPERATOR_SERVICE_ACCOUNT_NAME and
	// OPERATOR_SERVICE_ACCOUNT_NAMESPACE). The loop binds the plugin namespace
	// rules to it. Required.
	OperatorServiceAccount string
	OperatorNamespace      string
}

// CatalogPluginConfigFromEnv reads the config from the environment of the
// operator.
func CatalogPluginConfigFromEnv(getenv func(string) string) CatalogPluginConfig {
	return CatalogPluginConfig{
		SpireClassName:         getenv("PLUGIN_SPIRE_CLASS_NAME"),
		TrustDomain:            getenv("PLUGIN_TRUST_DOMAIN"),
		GibsonURL:              getenv("PLUGIN_GIBSON_URL"),
		EnvoyCAFile:            getenv("PLUGIN_ENVOY_CA_FILE"),
		WaitForSpireImage:      getenv("PLUGIN_WAIT_FOR_SPIRE_IMAGE"),
		OperatorServiceAccount: getenv(envOperatorSAName),
		OperatorNamespace:      getenv(envOperatorSANamespace),
	}
}

// Validate refuses a config with a required value missing.
func (c CatalogPluginConfig) Validate() error {
	for name, v := range map[string]string{
		"PLUGIN_SPIRE_CLASS_NAME":     c.SpireClassName,
		"PLUGIN_TRUST_DOMAIN":         c.TrustDomain,
		"PLUGIN_GIBSON_URL":           c.GibsonURL,
		"PLUGIN_WAIT_FOR_SPIRE_IMAGE": c.WaitForSpireImage,
		envOperatorSAName:             c.OperatorServiceAccount,
		envOperatorSANamespace:        c.OperatorNamespace,
	} {
		if v == "" {
			return fmt.Errorf("catalog plugins: %s is required", name)
		}
	}
	return nil
}

// The cluster-wide rules of this loop. A ClusterSPIFFEID has no namespace, so
// the rule is in the ClusterRole of the operator, and an admission policy of
// the chart limits the objects that the operator can write. The rules for the
// objects inside a plugin namespace are not here: the chart holds them in the
// ClusterRole gibson-tenant-operator-plugin-namespace, and ensureNamespaceRBAC
// binds it into each plugin namespace.
// +kubebuilder:rbac:groups=spire.spiffe.io,resources=clusterspiffeids,verbs=get;list;create;update;delete

// CatalogPluginRunnable converges the cluster to the catalog plugins the
// tenants enabled.
type CatalogPluginRunnable struct {
	Client   client.Client
	Daemon   CatalogPluginDaemon
	Config   CatalogPluginConfig
	Interval time.Duration

	// readFile reads the edge CA file. Tests replace it.
	readFile func(string) ([]byte, error)
}

// NeedLeaderElection makes one replica run the loop.
func (r *CatalogPluginRunnable) NeedLeaderElection() bool { return true }

// SetupWithManager checks the inputs and adds the loop to the manager.
func (r *CatalogPluginRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Daemon == nil {
		return errors.New("catalog plugins: Daemon client is nil")
	}
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("catalog plugins: add the loop to the manager: %w", err)
	}
	return nil
}

// Start runs the loop until ctx ends.
func (r *CatalogPluginRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultCatalogPluginInterval
	}
	logger := log.FromContext(ctx).WithName("catalog-plugins")
	logger.Info("starting the catalog plugin loop", "interval", interval.String())

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.converge(ctx); err != nil {
				logger.Error(err, "catalog plugin pass failed; retrying next tick")
			}
		}
	}
}

// pluginNamespace is the namespace of the plugin instances of one tenant.
func pluginNamespace(tenant string) string { return "tenant-" + tenant + "-plugins" }

// pluginObjectName is the name of the ServiceAccount, the Deployment and the
// NetworkPolicy of one plugin instance.
func pluginObjectName(plugin string) string { return "gibson-plugin-" + plugin }

// clusterSPIFFEIDName is the name of the identity registration of one instance.
func clusterSPIFFEIDName(plugin, tenant string) string {
	return "gibson-plugin-" + plugin + "-" + tenant
}

// validInstance refuses a pair whose names cannot be object names.
func validInstance(p provision.DesiredCatalogPlugin) error {
	if !catalogPluginNameRe.MatchString(p.TenantID) {
		return fmt.Errorf("tenant %q is not a valid name for a plugin instance", p.TenantID)
	}
	if !catalogPluginNameRe.MatchString(p.PluginID) {
		return fmt.Errorf("plugin %q is not a valid name for a plugin instance", p.PluginID)
	}
	if len(pluginNamespace(p.TenantID)) > 63 {
		return fmt.Errorf("namespace %q is over 63 characters", pluginNamespace(p.TenantID))
	}
	if p.Image == "" {
		return fmt.Errorf("plugin %q has no image", p.PluginID)
	}
	return nil
}

// converge runs one pass: make what is wanted, report its state, remove what
// is no longer wanted.
func (r *CatalogPluginRunnable) converge(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("catalog-plugins")
	desired, err := r.Daemon.ListDesiredCatalogPlugins(ctx)
	if err != nil {
		return fmt.Errorf("list desired catalog plugins: %w", err)
	}

	wanted := make(map[string]map[string]struct{}) // tenant -> plugin set
	for _, p := range desired {
		phase, lastErr := catalogPluginPhaseProvisioning, ""
		ready, ensureErr := r.ensureInstance(ctx, p)
		if errors.Is(ensureErr, errTenantGone) {
			// The tenant does not exist any more, or it is in deletion. Its
			// instances are not wanted, so the prune below removes them.
			continue
		}
		switch {
		case ensureErr != nil:
			phase, lastErr = catalogPluginPhaseFailed, ensureErr.Error()
			logger.Error(ensureErr, "catalog plugin instance failed", "tenant", p.TenantID, "plugin", p.PluginID)
		case ready:
			phase = catalogPluginPhaseReady
		}
		// A pair that could not be made still counts as wanted, so the pass
		// below does not delete the objects of an instance that had one bad
		// pass.
		if wanted[p.TenantID] == nil {
			wanted[p.TenantID] = make(map[string]struct{})
		}
		wanted[p.TenantID][p.PluginID] = struct{}{}
		if reportErr := r.Daemon.ReportCatalogPluginStatus(ctx, p.TenantID, p.PluginID, phase, lastErr); reportErr != nil {
			logger.Error(reportErr, "report catalog plugin status failed", "tenant", p.TenantID, "plugin", p.PluginID)
		}
	}
	return r.prune(ctx, wanted)
}

// errTenantGone reports a wish of a tenant that has no Tenant object, or whose
// Tenant object is in deletion.
var errTenantGone = errors.New("the tenant does not exist or is in deletion")

// ensureInstance makes every object of one plugin instance and returns
// whether its Deployment is available.
func (r *CatalogPluginRunnable) ensureInstance(ctx context.Context, p provision.DesiredCatalogPlugin) (bool, error) {
	if err := validInstance(p); err != nil {
		return false, err
	}
	var tenant gibsonv1alpha1.Tenant
	switch err := r.Client.Get(ctx, client.ObjectKey{Name: p.TenantID}, &tenant); {
	case apierrors.IsNotFound(err):
		return false, errTenantGone
	case err != nil:
		return false, fmt.Errorf("get Tenant %q: %w", p.TenantID, err)
	}
	if !tenant.DeletionTimestamp.IsZero() {
		return false, errTenantGone
	}
	steps := []func(context.Context, provision.DesiredCatalogPlugin) error{
		r.ensureNamespace, r.ensureNamespaceRBAC, r.ensureDefaultDeny, r.ensureEnvoyCA, r.ensureServiceAccount,
		r.ensureClusterSPIFFEID, r.ensurePluginNetworkPolicy, r.ensureDeployment,
	}
	for _, step := range steps {
		if err := step(ctx, p); err != nil {
			return false, err
		}
	}
	var dep appsv1.Deployment
	key := client.ObjectKey{Namespace: pluginNamespace(p.TenantID), Name: pluginObjectName(p.PluginID)}
	if err := r.Client.Get(ctx, key, &dep); err != nil {
		return false, fmt.Errorf("get Deployment %s: %w", key, err)
	}
	return dep.Status.AvailableReplicas >= 1, nil
}

func instanceLabels(p provision.DesiredCatalogPlugin) map[string]string {
	return map[string]string{
		labelManagedBy:    catalogPluginManagedBy,
		labelPluginTenant: p.TenantID,
		labelPlugin:       p.PluginID,
	}
}

func podLabels(p provision.DesiredCatalogPlugin) map[string]string {
	return map[string]string{
		labelAppName:      pluginObjectName(p.PluginID),
		labelAppComponent: pluginComponent,
		labelPlugin:       p.PluginID,
		labelPluginTenant: p.TenantID,
	}
}

// errForeignNamespace reports a namespace with the name of a plugin namespace
// that this loop did not make. The namespace tenant-<a>-plugins is also the
// namespace of a tenant with the name <a>-plugins, so the loop never takes
// over a namespace that does not carry its own labels.
var errForeignNamespace = errors.New("the namespace exists and is not a plugin namespace of this tenant")

func (r *CatalogPluginRunnable) ensureNamespace(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pluginNamespace(p.TenantID)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, ns, func() error {
		if !ns.CreationTimestamp.IsZero() || ns.ResourceVersion != "" {
			if ns.Labels[labelManagedBy] != catalogPluginManagedBy || ns.Labels[labelPluginNamespaceOf] != p.TenantID {
				return errForeignNamespace
			}
		}
		if ns.Labels == nil {
			ns.Labels = map[string]string{}
		}
		ns.Labels[labelManagedBy] = catalogPluginManagedBy
		ns.Labels[labelPluginTenant] = p.TenantID
		// For NetworkPolicy selectors only. No admission rule reads it.
		ns.Labels[labelPluginNamespaceOf] = p.TenantID
		ns.Labels[podSecurityEnforceLabel] = podSecurityRestricted // a plugin pod must meet "restricted"
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure Namespace %s: %w", ns.Name, err)
	}
	return nil
}

// ensureNamespaceRBAC gives the operator its rules inside the plugin
// namespace. The cluster-wide role of the operator holds no rule for a
// Deployment, a ServiceAccount, a ConfigMap or a NetworkPolicy. The chart
// holds those rules in one ClusterRole, and this RoleBinding applies them to
// this namespace only. It is the first object in a new namespace, because
// each later step needs it.
func (r *CatalogPluginRunnable) ensureNamespaceRBAC(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name: pluginNamespaceRoleBinding, Namespace: pluginNamespace(p.TenantID),
	}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
		rb.Labels = map[string]string{labelManagedBy: catalogPluginManagedBy, labelPluginTenant: p.TenantID}
		rb.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      r.Config.OperatorServiceAccount,
			Namespace: r.Config.OperatorNamespace,
		}}
		rb.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: pluginNamespaceClusterRole}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure RoleBinding %s/%s: %w", rb.Namespace, rb.Name, err)
	}
	return nil
}

// ensureDefaultDeny closes the namespace in both directions. Each plugin pod
// then gets its own allow policy.
func (r *CatalogPluginRunnable) ensureDefaultDeny(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: pluginNamespace(p.TenantID)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, np, func() error {
		np.Labels = map[string]string{labelManagedBy: catalogPluginManagedBy, labelPluginTenant: p.TenantID}
		np.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure default-deny NetworkPolicy in %s: %w", np.Namespace, err)
	}
	return nil
}

// ensureEnvoyCA copies the public certificate of the edge CA into the plugin
// namespace. The operator reads it from its own mount, which holds the
// certificate only. It never reads the Secret of the edge, which also holds
// the private key.
func (r *CatalogPluginRunnable) ensureEnvoyCA(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	if r.Config.EnvoyCAFile == "" {
		return nil
	}
	read := r.readFile
	if read == nil {
		read = os.ReadFile
	}
	pem, err := read(r.Config.EnvoyCAFile)
	if err != nil {
		return fmt.Errorf("read the edge CA file: %w", err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: envoyCAConfigMap, Namespace: pluginNamespace(p.TenantID)}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Labels = map[string]string{labelManagedBy: catalogPluginManagedBy, labelPluginTenant: p.TenantID}
		cm.Data = map[string]string{envoyCAKey: string(pem)}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure ConfigMap %s/%s: %w", cm.Namespace, cm.Name, err)
	}
	return nil
}

func (r *CatalogPluginRunnable) ensureServiceAccount(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: pluginObjectName(p.PluginID), Namespace: pluginNamespace(p.TenantID)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sa, func() error {
		sa.Labels = instanceLabels(p)
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)
	}
	return nil
}

// clusterSPIFFEIDSpec is the exact spec the admission policy of the chart
// admits. It sets no other field: admin, downstream, fallback,
// autoPopulateDNSNames, dnsNameTemplates, federatesWith, ttl and jwtTTL stay
// absent.
func (r *CatalogPluginRunnable) clusterSPIFFEIDSpec(p provision.DesiredCatalogPlugin) map[string]any {
	ns := pluginNamespace(p.TenantID)
	return map[string]any{
		"className":        r.Config.SpireClassName,
		"spiffeIDTemplate": "spiffe://" + r.Config.TrustDomain + "/plugin/" + p.PluginID + "/" + p.TenantID,
		"namespaceSelector": map[string]any{
			"matchLabels": map[string]any{"kubernetes.io/metadata.name": ns},
		},
		"podSelector": map[string]any{
			"matchLabels": map[string]any{labelAppComponent: pluginComponent, labelPlugin: p.PluginID},
		},
		"workloadSelectorTemplates": []any{"k8s:ns:" + ns, "k8s:sa:" + pluginObjectName(p.PluginID)},
	}
}

func (r *CatalogPluginRunnable) ensureClusterSPIFFEID(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(clusterSPIFFEIDGVK)
	obj.SetName(clusterSPIFFEIDName(p.PluginID, p.TenantID))
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, obj, func() error {
		obj.SetLabels(instanceLabels(p))
		obj.Object["spec"] = r.clusterSPIFFEIDSpec(p)
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure ClusterSPIFFEID %s: %w", obj.GetName(), err)
	}
	return nil
}

// ensurePluginNetworkPolicy admits the health probes of the kubelet and lets
// the plugin reach its vendor. The SDK of the plugin enforces the egress list
// of the catalog in process, because a NetworkPolicy cannot match a DNS name.
func (r *CatalogPluginRunnable) ensurePluginNetworkPolicy(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: pluginObjectName(p.PluginID), Namespace: pluginNamespace(p.TenantID)}}
	tcp := corev1.ProtocolTCP
	health := intstr.FromInt32(8080)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, np, func() error {
		np.Labels = instanceLabels(p)
		np.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{
				labelAppName: pluginObjectName(p.PluginID), labelAppComponent: pluginComponent,
			}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &health}},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{}},
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure NetworkPolicy %s/%s: %w", np.Namespace, np.Name, err)
	}
	return nil
}

func (r *CatalogPluginRunnable) ensureDeployment(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: pluginObjectName(p.PluginID), Namespace: pluginNamespace(p.TenantID)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, dep, func() error {
		dep.Labels = instanceLabels(p)
		replicas := int32(1)
		dep.Spec.Replicas = &replicas
		dep.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{
			labelAppName: pluginObjectName(p.PluginID), labelAppComponent: pluginComponent,
		}}
		dep.Spec.Template.Labels = podLabels(p)
		dep.Spec.Template.Spec = r.podSpec(p)
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure Deployment %s/%s: %w", dep.Namespace, dep.Name, err)
	}
	return nil
}

// podSpec is the plugin pod. It is the pod the chart rendered for a plugin
// before this loop existed, built from the inputs of CatalogPluginConfig.
func (r *CatalogPluginRunnable) podSpec(p provision.DesiredCatalogPlugin) corev1.PodSpec {
	nonRoot, readOnly, noEscalation := true, true, false
	uid := int64(65532)
	grace := int64(30)
	certDirs := "/etc/ssl/certs"

	mounts := []corev1.VolumeMount{
		{Name: "state", MountPath: "/home/nonroot/.gibson"},
		{Name: spireSocketVolume, MountPath: spirePluginMountPath, ReadOnly: true},
	}
	volumes := []corev1.Volume{
		{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: spireSocketVolume, VolumeSource: corev1.VolumeSource{
			CSI: &corev1.CSIVolumeSource{Driver: "csi.spiffe.io", ReadOnly: &readOnly},
		}},
	}
	if r.Config.EnvoyCAFile != "" {
		certDirs += ":/etc/ssl/envoy-ca"
		mounts = append(mounts, corev1.VolumeMount{Name: "envoy-ca", MountPath: "/etc/ssl/envoy-ca", ReadOnly: true})
		volumes = append(volumes, corev1.Volume{Name: "envoy-ca", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: envoyCAConfigMap},
				Items:                []corev1.KeyToPath{{Key: envoyCAKey, Path: envoyCAKey}},
			},
		}})
	}
	containerSecurity := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &noEscalation,
		ReadOnlyRootFilesystem:   &readOnly,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	probe := func(path string) corev1.ProbeHandler {
		return corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstr.FromString("health")}}
	}
	return corev1.PodSpec{
		ServiceAccountName:            pluginObjectName(p.PluginID),
		TerminationGracePeriodSeconds: &grace,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &nonRoot, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		InitContainers: []corev1.Container{r.waitForSpireSocket(containerSecurity)},
		Containers: []corev1.Container{{
			Name:            "plugin",
			Image:           p.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Env: []corev1.EnvVar{
				{Name: "HOME", Value: "/home/nonroot"},
				{Name: "GIBSON_URL", Value: r.Config.GibsonURL},
				{Name: "GIBSON_DAEMON_TLS", Value: "1"},
				{Name: "GIBSON_PLUGIN_RUNTIME", Value: "pod"},
				{Name: "GIBSON_PLUGIN_MANIFEST", Value: "/etc/gibson/plugin.yaml"},
				{Name: "SSL_CERT_DIR", Value: certDirs},
				{Name: "SPIFFE_ENDPOINT_SOCKET", Value: spirePluginSocketAddr},
			},
			Ports:           []corev1.ContainerPort{{Name: "health", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
			StartupProbe:    &corev1.Probe{ProbeHandler: probe("/healthz"), PeriodSeconds: 5, FailureThreshold: 12, TimeoutSeconds: 5},
			ReadinessProbe:  &corev1.Probe{ProbeHandler: probe("/healthz"), InitialDelaySeconds: 5, PeriodSeconds: 10, TimeoutSeconds: 3},
			LivenessProbe:   &corev1.Probe{ProbeHandler: probe("/livez"), InitialDelaySeconds: 15, PeriodSeconds: 20, TimeoutSeconds: 3},
			SecurityContext: containerSecurity,
			VolumeMounts:    mounts,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
			},
		}},
		Volumes: volumes,
	}
}

// waitForSpireSocketScript waits up to 60 seconds for the SPIRE agent socket,
// then fails, so the plugin never starts with no identity. It is the script
// that the chart helper gibson.waitForSpireSocket renders for each platform
// pod.
const waitForSpireSocketScript = `SOCK="` + spireWaitSocket + `"
DEADLINE=$(( $(date +%s) + 60 ))
echo "[wait-for-spire-socket] waiting for ${SOCK} (timeout: 60s)..."
until [ -S "${SOCK}" ]; do
  if [ $(date +%s) -ge ${DEADLINE} ]; then
    echo "[wait-for-spire-socket] ERROR: ${SOCK} not present after 60s" >&2
    exit 1
  fi
  sleep 1
done
echo "[wait-for-spire-socket] ok"
`

func (r *CatalogPluginRunnable) waitForSpireSocket(security *corev1.SecurityContext) corev1.Container {
	return corev1.Container{
		Name:            "wait-for-spire-socket",
		Image:           r.Config.WaitForSpireImage,
		Command:         []string{"sh", "-c"},
		Args:            []string{waitForSpireSocketScript},
		SecurityContext: security,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: spireSocketVolume, MountPath: spireWaitMountPath, ReadOnly: true}},
	}
}

// prune removes what no tenant wants any more. It deletes only objects that
// carry the managed-by label of this loop.
func (r *CatalogPluginRunnable) prune(ctx context.Context, wanted map[string]map[string]struct{}) error {
	managed := client.MatchingLabels{labelManagedBy: catalogPluginManagedBy}
	isWanted := func(labels map[string]string) bool {
		_, ok := wanted[labels[labelPluginTenant]][labels[labelPlugin]]
		return ok
	}

	ids := &unstructured.UnstructuredList{}
	ids.SetGroupVersionKind(schema.GroupVersionKind{Group: clusterSPIFFEIDGVK.Group, Version: clusterSPIFFEIDGVK.Version, Kind: "ClusterSPIFFEIDList"})
	if err := r.Client.List(ctx, ids, managed); err != nil {
		return fmt.Errorf("list ClusterSPIFFEIDs: %w", err)
	}
	for i := range ids.Items {
		if isWanted(ids.Items[i].GetLabels()) {
			continue
		}
		if err := r.Client.Delete(ctx, &ids.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete ClusterSPIFFEID %s: %w", ids.Items[i].GetName(), err)
		}
	}

	// The operator has rules for a Deployment only inside a plugin namespace,
	// so the pass reads each plugin namespace and never lists Deployments for
	// the whole cluster.
	var namespaces corev1.NamespaceList
	if err := r.Client.List(ctx, &namespaces, managed); err != nil {
		return fmt.Errorf("list plugin namespaces: %w", err)
	}
	for i := range namespaces.Items {
		ns := &namespaces.Items[i]
		tenant := ns.Labels[labelPluginNamespaceOf]
		if tenant == "" || !ns.DeletionTimestamp.IsZero() {
			continue
		}
		if len(wanted[tenant]) == 0 {
			if err := r.Client.Delete(ctx, ns); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete Namespace %s: %w", ns.Name, err)
			}
			continue
		}
		var deps appsv1.DeploymentList
		if err := r.Client.List(ctx, &deps, client.InNamespace(ns.Name), managed); err != nil {
			return fmt.Errorf("list plugin Deployments in %s: %w", ns.Name, err)
		}
		for d := range deps.Items {
			if isWanted(deps.Items[d].Labels) {
				continue
			}
			if err := r.deleteInstanceObjects(ctx, deps.Items[d].Namespace, deps.Items[d].Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteInstanceObjects removes the Deployment, the NetworkPolicy and the
// ServiceAccount of one plugin instance.
func (r *CatalogPluginRunnable) deleteInstanceObjects(ctx context.Context, namespace, name string) error {
	meta := metav1.ObjectMeta{Namespace: namespace, Name: name}
	for _, obj := range []client.Object{
		&appsv1.Deployment{ObjectMeta: meta},
		&networkingv1.NetworkPolicy{ObjectMeta: meta},
		&corev1.ServiceAccount{ObjectMeta: meta},
	} {
		if err := r.Client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %T %s/%s: %w", obj, namespace, name, err)
		}
	}
	return nil
}
