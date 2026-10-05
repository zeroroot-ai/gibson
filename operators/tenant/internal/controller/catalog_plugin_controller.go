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
}

// Validate refuses a config with a required value missing.
func (c CatalogPluginConfig) Validate() error {
	for name, v := range map[string]string{
		"PLUGIN_SPIRE_CLASS_NAME":     c.SpireClassName,
		"PLUGIN_TRUST_DOMAIN":         c.TrustDomain,
		"PLUGIN_GIBSON_URL":           c.GibsonURL,
		"PLUGIN_WAIT_FOR_SPIRE_IMAGE": c.WaitForSpireImage,
	} {
		if v == "" {
			return fmt.Errorf("catalog plugins: %s is required", name)
		}
	}
	return nil
}

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
	return mgr.Add(r)
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

// ensureInstance makes every object of one plugin instance and returns
// whether its Deployment is available.
func (r *CatalogPluginRunnable) ensureInstance(ctx context.Context, p provision.DesiredCatalogPlugin) (bool, error) {
	if err := validInstance(p); err != nil {
		return false, err
	}
	var tenant gibsonv1alpha1.Tenant
	if err := r.Client.Get(ctx, client.ObjectKey{Name: p.TenantID}, &tenant); err != nil {
		return false, fmt.Errorf("get Tenant %q: %w", p.TenantID, err)
	}
	steps := []func(context.Context, provision.DesiredCatalogPlugin) error{
		r.ensureNamespace, r.ensureDefaultDeny, r.ensureEnvoyCA, r.ensureServiceAccount,
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

func (r *CatalogPluginRunnable) ensureNamespace(ctx context.Context, p provision.DesiredCatalogPlugin) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pluginNamespace(p.TenantID)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, ns, func() error {
		if ns.Labels == nil {
			ns.Labels = map[string]string{}
		}
		ns.Labels[labelManagedBy] = catalogPluginManagedBy
		ns.Labels[labelPluginTenant] = p.TenantID
		// For NetworkPolicy selectors only. No admission rule reads it.
		ns.Labels[labelPluginNamespaceOf] = p.TenantID
		return nil
	})
	if err != nil {
		return fmt.Errorf("ensure Namespace %s: %w", ns.Name, err)
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
		dep.Spec.Template.ObjectMeta.Labels = podLabels(p)
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
		{Name: "spire-agent-socket", MountPath: "/run/spire/sockets", ReadOnly: true},
	}
	volumes := []corev1.Volume{
		{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "spire-agent-socket", VolumeSource: corev1.VolumeSource{
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
		InitContainers: []corev1.Container{{
			Name:  "wait-for-spire-socket",
			Image: r.Config.WaitForSpireImage,
			// Wait up to 60 seconds for the SPIRE agent socket, then fail, so
			// the plugin never starts with no identity.
			Command: []string{"sh", "-c",
				"i=0; while [ $i -lt 60 ]; do [ -S /run/spire/sockets/api.sock ] && exit 0; i=$((i+1)); sleep 1; done; exit 1"},
			SecurityContext: containerSecurity,
			VolumeMounts:    []corev1.VolumeMount{{Name: "spire-agent-socket", MountPath: "/run/spire/sockets", ReadOnly: true}},
		}},
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
				{Name: "SPIFFE_ENDPOINT_SOCKET", Value: "unix:///run/spire/sockets/api.sock"},
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

	var deps appsv1.DeploymentList
	if err := r.Client.List(ctx, &deps, managed); err != nil {
		return fmt.Errorf("list plugin Deployments: %w", err)
	}
	for i := range deps.Items {
		if isWanted(deps.Items[i].Labels) {
			continue
		}
		if err := r.deleteInstanceObjects(ctx, deps.Items[i].Namespace, deps.Items[i].Name); err != nil {
			return err
		}
	}

	var namespaces corev1.NamespaceList
	if err := r.Client.List(ctx, &namespaces, managed); err != nil {
		return fmt.Errorf("list plugin namespaces: %w", err)
	}
	for i := range namespaces.Items {
		tenant := namespaces.Items[i].Labels[labelPluginNamespaceOf]
		if tenant == "" || len(wanted[tenant]) > 0 {
			continue
		}
		if err := r.Client.Delete(ctx, &namespaces.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete Namespace %s: %w", namespaces.Items[i].Name, err)
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
