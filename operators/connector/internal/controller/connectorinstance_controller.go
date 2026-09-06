// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package controller reconciles a ConnectorInstance into ToolHive resources
// (ADR-0014). The operator wraps ToolHive: it owns an MCPServer (a hosted
// container connector) or an MCPRemoteProxy (a vendor-hosted one), the
// NetworkPolicy that confines it, and the egress-profile ConfigMap. The
// connector's credential Secret is written by the daemon from the tenant
// secret store (ADR-0015); the operator only references it. ToolHive is
// never a product surface.
package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

const (
	// finalizer holds the ConnectorInstance until the connector's grant is
	// revoked (ADR-0015 §5). The ToolHive resource and the daemon-written
	// credential Secret carry owner references, so Kubernetes garbage-collects
	// them; the vendor grant and the Grant/access secrets in the tenant store
	// need an explicit revoke, which only the daemon can run.
	finalizer = "gibson.zeroroot.ai/connector-cleanup"

	// revokeDeadline bounds the finalizer's retry on a failing revoke. Past it
	// the finalizer releases with a logged warning rather than wedging the
	// delete forever behind a daemon that is down: the credential Secret is
	// already gone with the CR, and the grant is reported for manual revoke.
	revokeDeadline = 10 * time.Minute

	// tenantNamespacePrefix is the fixed prefix of a per-tenant namespace
	// (tenant-<id>), the same convention the daemon writes CRs into.
	tenantNamespacePrefix = "tenant-"

	condRevoked = "GrantRevoked"

	// toolhiveAPIVersion is the ToolHive CRD version this operator pins. The
	// chart serves v1alpha1 as of ToolHive 0.12.1 (ADR-0014, Spike 1). The
	// ConnectorInstance wrapper absorbs a future bump.
	toolhiveAPIVersion = "toolhive.stacklok.dev/v1alpha1"

	kindMCPServer      = "MCPServer"
	kindMCPRemoteProxy = "MCPRemoteProxy"

	// proxyPort is the port the ToolHive proxy Service exposes.
	proxyPort = 8080

	condProvisioned = "Provisioned"
	condReady       = "Ready"
)

// GrantRevoker revokes a tenant's connector grant through the daemon. The
// production implementation is daemonclient.Client over SPIFFE mTLS
// (ADR-0002); it is required, never nil.
type GrantRevoker interface {
	Revoke(ctx context.Context, tenantID, connector string) error
}

// ConnectorInstanceReconciler reconciles a ConnectorInstance.
type ConnectorInstanceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Revoker runs the finalizer's grant revoke on delete (ADR-0015 §5).
	Revoker GrantRevoker
	// Now is the clock the revoke deadline is measured on. Nil means time.Now.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=connectorinstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=connectorinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=connectorinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups=toolhive.stacklok.dev,resources=mcpservers;mcpremoteproxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps;secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives a ConnectorInstance toward its desired state.
func (r *ConnectorInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(ctx, req.NamespacedName, &ci); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get connectorinstance: %w", err)
	}

	// Deletion: run the finalizer, then let Kubernetes remove the object. The
	// owner references garbage-collect the ToolHive resource and the
	// credential Secret on their own.
	if !ci.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &ci)
	}

	if controllerutil.AddFinalizer(&ci, finalizer) {
		if err := r.Update(ctx, &ci); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	// The tenant default-deny NetworkPolicy severs the connector; open exactly
	// the paths it needs (ADR-0014, Slice 3).
	if err := r.reconcileNetworkPolicy(ctx, &ci); err != nil {
		return r.fail(ctx, &ci, "NetworkPolicy", err)
	}

	// The connector's credential is NOT reconciled here. For auth secret and
	// auth oauth alike, the daemon reads the credential from the tenant's
	// configured secret store and writes the <connector>-connector-cred Secret
	// beside this CR, with an ownerReference to it (ADR-0015). The operator
	// has no secret-store client by design; it only references the Secret.

	// Confine egress to the vendor hosts, when declared (ADR-0014).
	if err := r.reconcileEgressProfile(ctx, &ci); err != nil {
		return r.fail(ctx, &ci, "EgressProfile", err)
	}

	// Reconcile the ToolHive resource the ConnectorInstance owns.
	th, err := r.desiredToolHive(&ci)
	if err != nil {
		return r.fail(ctx, &ci, "InvalidSpec", err)
	}
	if err := controllerutil.SetControllerReference(&ci, th, r.Scheme); err != nil {
		return r.fail(ctx, &ci, "OwnerRef", err)
	}
	if err := r.applyToolHive(ctx, th); err != nil {
		return r.fail(ctx, &ci, "ApplyToolHive", err)
	}

	// Read the live ToolHive resource to reflect its phase.
	live := newToolHive(th.GetKind())
	if err := r.Get(ctx, client.ObjectKeyFromObject(th), live); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return r.fail(ctx, &ci, "ReadToolHive", err)
	}

	phase, _, _ := unstructured.NestedString(live.Object, "status", "phase")
	ci.Status.ToolHiveKind = th.GetKind()
	ci.Status.ToolHiveName = th.GetName()
	ci.Status.ProxyURL = fmt.Sprintf(
		"http://mcp-%s-proxy.%s.svc.cluster.local:%d/mcp", ci.Name, ci.Namespace, proxyPort)
	ci.Status.ObservedGeneration = ci.Generation
	ci.Status.LastError = ""
	setCondition(&ci, condProvisioned, metav1.ConditionTrue, "Applied",
		fmt.Sprintf("ToolHive %s %s applied", th.GetKind(), th.GetName()))

	if phase == toolHiveServingPhase(th.GetKind()) {
		ci.Status.Phase = connectorv1alpha1.ConnectorInstancePhaseReady
		setCondition(&ci, condReady, metav1.ConditionTrue, "Serving", "the MCP server is serving")
		if err := r.Status().Update(ctx, &ci); err != nil {
			return ctrl.Result{}, fmt.Errorf("status update: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// Not yet serving: stay in Provisioning and requeue.
	ci.Status.Phase = connectorv1alpha1.ConnectorInstancePhaseProvisioning
	setCondition(&ci, condReady, metav1.ConditionFalse, "Provisioning",
		fmt.Sprintf("ToolHive phase is %q", phase))
	if err := r.Status().Update(ctx, &ci); err != nil {
		return ctrl.Result{}, fmt.Errorf("status update: %w", err)
	}
	logger.Info("waiting for ToolHive to run", "phase", phase)
	return ctrl.Result{Requeue: true}, nil
}

// finalize revokes the connector's grant through the daemon and releases the
// finalizer (ADR-0015 §5). A failing revoke is retried with backoff until
// revokeDeadline has passed since the delete, then the finalizer releases
// with a logged warning so the delete never wedges. A connector with no
// vendor credential (auth none) has no grant and skips the revoke.
func (r *ConnectorInstanceReconciler) finalize(ctx context.Context, ci *connectorv1alpha1.ConnectorInstance) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(ci, finalizer) {
		return ctrl.Result{}, nil
	}
	logger := log.FromContext(ctx)

	if ci.Spec.Auth != connectorv1alpha1.ConnectorAuthNone {
		if err := r.revokeGrant(ctx, ci); err != nil {
			if r.now().Sub(ci.DeletionTimestamp.Time) < revokeDeadline {
				ci.Status.Phase = connectorv1alpha1.ConnectorInstancePhaseDeprovisioning
				ci.Status.LastError = fmt.Sprintf("GrantRevoke: %v", err)
				setCondition(ci, condRevoked, metav1.ConditionFalse, "RevokeFailed", err.Error())
				_ = r.Status().Update(ctx, ci)
				// Returning the error requeues with the controller's backoff.
				return ctrl.Result{}, fmt.Errorf("revoke connector grant: %w", err)
			}
			logger.Error(err, "releasing the finalizer without a confirmed grant revoke; revoke the grant by hand",
				"connector", ci.Spec.Connector, "deadline", revokeDeadline.String())
		} else {
			setCondition(ci, condRevoked, metav1.ConditionTrue, "Revoked", "the connector grant is revoked")
		}
	}

	ci.Status.Phase = connectorv1alpha1.ConnectorInstancePhaseDeprovisioning
	_ = r.Status().Update(ctx, ci)
	controllerutil.RemoveFinalizer(ci, finalizer)
	if err := r.Update(ctx, ci); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// revokeGrant asks the daemon to revoke the connector's grant. The tenant is
// recovered from the CR's namespace (tenant-<id>); a ConnectorInstance outside
// a tenant namespace has no tenant store to revoke in and is an error.
func (r *ConnectorInstanceReconciler) revokeGrant(ctx context.Context, ci *connectorv1alpha1.ConnectorInstance) error {
	if r.Revoker == nil {
		return errors.New("no grant revoker is wired")
	}
	if !strings.HasPrefix(ci.Namespace, tenantNamespacePrefix) {
		return fmt.Errorf("namespace %q is not a tenant namespace", ci.Namespace)
	}
	connector := ci.Spec.Connector
	if connector == "" {
		connector = ci.Name
	}
	tenantID := strings.TrimPrefix(ci.Namespace, tenantNamespacePrefix)
	if err := r.Revoker.Revoke(ctx, tenantID, connector); err != nil {
		return fmt.Errorf("daemon revoke for %s/%s: %w", tenantID, connector, err)
	}
	return nil
}

func (r *ConnectorInstanceReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// toolHiveServingPhase is the ToolHive status.phase that means the proxy is
// serving traffic, which differs by kind. An MCPServer (a Hosted connector)
// reports "Running"; an MCPRemoteProxy (a Remote connector) reports "Ready".
// The two ToolHive CRDs use different terminal phase strings, so a Remote
// connector never left Provisioning while the operator only matched "Running".
func toolHiveServingPhase(kind string) string {
	if kind == kindMCPRemoteProxy {
		return "Ready"
	}
	return "Running"
}

// desiredToolHive builds the ToolHive resource for a ConnectorInstance. A
// Hosted connector maps to an MCPServer; a Remote connector maps to an
// MCPRemoteProxy.
func (r *ConnectorInstanceReconciler) desiredToolHive(
	ci *connectorv1alpha1.ConnectorInstance,
) (*unstructured.Unstructured, error) {
	transport := string(ci.Spec.Transport)
	if transport == "" {
		transport = string(connectorv1alpha1.ConnectorTransportStreamableHTTP)
	}

	switch ci.Spec.Shape {
	case connectorv1alpha1.ConnectorShapeHosted:
		if ci.Spec.Image == "" {
			return nil, errors.New("shape Hosted needs spec.image")
		}
		th := newToolHive(kindMCPServer)
		th.SetName(ci.Name)
		th.SetNamespace(ci.Namespace)
		// The MCPServer keeps ToolHive's builtin "network" profile. Egress is
		// enforced by the owned NetworkPolicy (reconcileNetworkPolicy), which
		// confines the connector to 443 on public IPs (private ranges blocked
		// for SSRF containment). Host-level egress from spec.egressAllow is NOT
		// applied to the MCPServer: ToolHive v0.12.1 reads a "configmap" profile
		// from an operator-local path (/etc/toolhive/profiles/<key>), not from
		// the referenced tenant ConfigMap, so a per-connector custom profile
		// breaks the run-config validation. reconcileEgressProfile still records
		// the intent in an owned ConfigMap; wire it into permissionProfile once
		// ToolHive resolves a per-MCPServer ConfigMap profile.
		permProfile := map[string]interface{}{"type": "builtin", "name": "network"}
		spec := map[string]interface{}{
			"image":             ci.Spec.Image,
			"transport":         transport,
			"mcpPort":           int64(proxyPort),
			"proxyPort":         int64(proxyPort),
			"permissionProfile": permProfile,
		}
		_ = unstructured.SetNestedMap(th.Object, spec, "spec")
		return th, nil

	case connectorv1alpha1.ConnectorShapeRemote:
		if ci.Spec.Endpoint == "" {
			return nil, errors.New("shape Remote needs spec.endpoint")
		}
		th := newToolHive(kindMCPRemoteProxy)
		th.SetName(ci.Name)
		th.SetNamespace(ci.Namespace)
		spec := map[string]interface{}{
			"remoteURL": ci.Spec.Endpoint,
			"transport": transport,
			"proxyPort": int64(proxyPort),
			// oidcConfig is REQUIRED by the MCPRemoteProxy CRD. type kubernetes
			// makes only the daemon's Kubernetes ServiceAccount token able to
			// call the proxy — this IS the ADR-0014 decision "ToolHive OIDC
			// gates daemon access".
			"oidcConfig": map[string]interface{}{
				"type": "kubernetes",
			},
		}
		// A vendor connector presents a bearer token as the Authorization
		// header. ToolHive forwards it from a Kubernetes Secret the daemon
		// writes from the tenant secret store for both auth modes (ADR-0015):
		// an oauth access token it rotates, or the static credential the
		// tenant admin stored. The Secret VALUE is the full header
		// "Bearer <token>". The Secret name follows the connector convention.
		if ci.Spec.Auth != connectorv1alpha1.ConnectorAuthNone {
			spec["headerForward"] = map[string]interface{}{
				"addHeadersFromSecret": []interface{}{
					map[string]interface{}{
						"headerName": "Authorization",
						"valueSecretRef": map[string]interface{}{
							"name": credentialSecretName(ci.Name),
							"key":  "authorization",
						},
					},
				},
			}
		}
		_ = unstructured.SetNestedMap(th.Object, spec, "spec")
		return th, nil

	default:
		return nil, fmt.Errorf("unknown shape %q", ci.Spec.Shape)
	}
}

// applyToolHive creates or updates the ToolHive resource, preserving the spec
// the operator owns while leaving any operator-added defaults in place.
func (r *ConnectorInstanceReconciler) applyToolHive(ctx context.Context, desired *unstructured.Unstructured) error {
	live := newToolHive(desired.GetKind())
	live.SetName(desired.GetName())
	live.SetNamespace(desired.GetNamespace())

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, live, func() error {
		spec, _, _ := unstructured.NestedMap(desired.Object, "spec")
		if err := unstructured.SetNestedMap(live.Object, spec, "spec"); err != nil {
			return fmt.Errorf("set toolhive spec: %w", err)
		}
		live.SetOwnerReferences(desired.GetOwnerReferences())
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply toolhive %s/%s: %w", desired.GetKind(), desired.GetName(), err)
	}
	return nil
}

// fail records a reconcile error on the status and returns it for a retry.
func (r *ConnectorInstanceReconciler) fail(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance, reason string, cause error,
) (ctrl.Result, error) {
	ci.Status.Phase = connectorv1alpha1.ConnectorInstancePhaseFailed
	ci.Status.LastError = fmt.Sprintf("%s: %v", reason, cause)
	setCondition(ci, condReady, metav1.ConditionFalse, reason, cause.Error())
	_ = r.Status().Update(ctx, ci)
	return ctrl.Result{}, cause
}

func setCondition(ci *connectorv1alpha1.ConnectorInstance, condType string, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type: condType, Status: status, Reason: reason, Message: msg,
		ObservedGeneration: ci.Generation,
	}
	for i := range ci.Status.Conditions {
		if ci.Status.Conditions[i].Type == condType {
			if ci.Status.Conditions[i].Status != status {
				cond.LastTransitionTime = metav1.Now()
			} else {
				cond.LastTransitionTime = ci.Status.Conditions[i].LastTransitionTime
			}
			ci.Status.Conditions[i] = cond
			return
		}
	}
	cond.LastTransitionTime = metav1.Now()
	ci.Status.Conditions = append(ci.Status.Conditions, cond)
}

// credentialSecretName is the Kubernetes Secret the connector's credential
// lands in. The daemon writes it from the tenant secret store for auth secret
// and auth oauth alike (ADR-0015); it MUST match the daemon's
// connectorCredSecretName (internal/server/daemon/connector_token_materializer.go).
// The Secret value is the full "Bearer <token>" header for a Remote connector.
func credentialSecretName(connector string) string {
	return connector + "-connector-cred"
}

func newToolHive(kind string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.FromAPIVersionAndKind(toolhiveAPIVersion, kind))
	return u
}

// SetupWithManager wires the controller and watches the owned ToolHive kinds.
func (r *ConnectorInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mcpServer := newToolHive(kindMCPServer)
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&connectorv1alpha1.ConnectorInstance{}).
		Owns(mcpServer).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r); err != nil {
		return fmt.Errorf("build connectorinstance controller: %w", err)
	}
	return nil
}
