// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/modelprovider"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/outsideagent"
)

// modelProviderCredentialRetry is how long the controller waits before it looks
// again for the credential Secret of a provider.
const modelProviderCredentialRetry = 30 * time.Second

// modelProviderResync re-renders a Ready provider, so a gateway object that
// someone changed or deleted comes back.
const modelProviderResync = 10 * time.Minute

// The kinds that the controller writes in the namespace of the gateway.
var (
	agentgatewayBackendGVK = schema.GroupVersionKind{Group: "agentgateway.dev", Version: "v1alpha1", Kind: "AgentgatewayBackend"}
	httpRouteGVK           = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
)

// ModelProviderReconciler renders each ModelProvider into the objects of the
// model gateway (gibson#1387, ADR-0172). The objects live in the namespace of
// the gateway, and the ModelProvider lives in the namespace of the tenant. An
// owner reference cannot cross a namespace, so a finalizer removes the objects.
//
// The controller writes the credential Secret that the backend names, in the
// namespace of the gateway. It gets the content from the daemon, which holds the
// tenant secret store (the mechanism of the connector-cred Secret, gibson#663).
// The controller keeps no copy of the value. It reports the phase
// WaitingForCredential until the tenant secret exists. A finalizer deletes the
// Secret with the provider.
type ModelProviderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Render is the install-side configuration: the namespace of the gateway,
	// its name and the ext-authz service.
	Render modelprovider.Config

	// Credentials reads the content of the credential Secret from the daemon.
	Credentials ModelCredentialSource
}

// ModelCredentialSource returns the content of the credential Secret of a model
// provider, by the key names that the gateway reads. The daemon implements it.
// It returns clients.ErrNotFound when the tenant secret does not exist.
type ModelCredentialSource interface {
	ModelProviderCredential(
		ctx context.Context, tenantID, credentialSecret, providerType, caBundleSecret string,
	) (map[string][]byte, error)
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=modelproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=modelproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=modelproviders/finalizers,verbs=update
// The operator also writes the AgentgatewayBackend, the HTTPRoute and the
// credential Secret in the dedicated namespace of the gateway. A cluster-wide
// grant on these kinds is forbidden, so the chart gives that access with a Role
// in the gateway namespace, and no marker is here. The manager client reads the
// backends and the routes as unstructured objects, which the cache does not
// hold, and it reads Secrets without the cache (cache_disable_for.go). So no
// cluster-wide list or watch is needed.

// Reconcile drives a ModelProvider toward its desired state.
func (r *ModelProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("modelprovider", req.NamespacedName)

	var mp gibsonv1alpha1.ModelProvider
	if err := r.Get(ctx, req.NamespacedName, &mp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !mp.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &mp)
	}
	if !controllerutil.ContainsFinalizer(&mp, gibsonv1alpha1.ModelProviderFinalizer) {
		controllerutil.AddFinalizer(&mp, gibsonv1alpha1.ModelProviderFinalizer)
		if err := r.Update(ctx, &mp); err != nil {
			return ctrl.Result{}, fmt.Errorf("add the finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if mp.Status.ObservedGeneration != mp.Generation {
		log.Info("rendering a new generation", "generation", mp.Generation, "observed", mp.Status.ObservedGeneration)
	}
	desired, err := modelprovider.Render(&mp, r.Render)
	if err != nil {
		log.Error(err, "the provider cannot be rendered")
		return r.fail(ctx, &mp, err)
	}
	for _, obj := range desired {
		if err := r.apply(ctx, obj); err != nil {
			return r.fail(ctx, &mp, err)
		}
	}
	if err := r.deleteStale(ctx, &mp, desired); err != nil {
		return r.fail(ctx, &mp, err)
	}

	secretName := modelprovider.CredentialSecretName(mp.Spec.TenantID, mp.Name)
	waiting, err := r.syncCredential(ctx, &mp, secretName)
	switch {
	case waiting != "":
		r.setStatus(ctx, &mp, gibsonv1alpha1.ModelProviderPhaseWaitingForCredential, secretName, metav1.ConditionFalse,
			"WaitingForCredential", waiting, "")
		return ctrl.Result{RequeueAfter: modelProviderCredentialRetry}, nil
	case err != nil:
		return r.fail(ctx, &mp, err)
	}
	r.setStatus(ctx, &mp, gibsonv1alpha1.ModelProviderPhaseReady, secretName, metav1.ConditionTrue,
		"Rendered", "the gateway objects exist and the credential Secret is written", "")
	return ctrl.Result{RequeueAfter: modelProviderResync}, nil
}

// syncCredential writes the credential Secret of the provider from the content
// that the daemon returns. The content replaces the data of the Secret, so a
// rotated tenant secret reaches the gateway on the next resync. When the tenant
// secret does not exist, it returns a waiting message and no error. The error
// text never holds a value.
func (r *ModelProviderReconciler) syncCredential(
	ctx context.Context, mp *gibsonv1alpha1.ModelProvider, secretName string,
) (waiting string, err error) {
	data, err := r.Credentials.ModelProviderCredential(
		ctx, mp.Spec.TenantID, mp.Spec.CredentialSecret, string(mp.Spec.Type), mp.Spec.CABundleSecret)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return "the tenant secret " + mp.Spec.CredentialSecret + " does not exist", nil
		}
		return "", fmt.Errorf("read the credential of the provider from the daemon: %w", err)
	}
	if len(data) == 0 {
		return "", errors.New("the daemon returned an empty credential")
	}
	key := types.NamespacedName{Namespace: r.Render.Namespace, Name: secretName}
	annotations := map[string]string{modelprovider.AnnotationCredentialSecret: mp.Spec.CredentialSecret}
	if err := upsertSecret(ctx, r.Client, key, r.credentialLabels(mp), annotations, data); err != nil {
		return "", err
	}
	return "", nil
}

// credentialLabels are the labels of the credential Secret. They are the labels
// of the gateway objects of the provider, so one selector finds them all.
func (r *ModelProviderReconciler) credentialLabels(mp *gibsonv1alpha1.ModelProvider) map[string]string {
	return map[string]string(r.ownedSelector(mp))
}

func secretDataEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// apply creates the object, or updates it when its spec or labels differ.
func (r *ModelProviderReconciler) apply(ctx context.Context, desired *unstructured.Unstructured) error {
	return applyObject(ctx, r.Client, desired)
}

// ownerLabelKeys are the labels that name the owner of a gateway object.
var ownerLabelKeys = []string{
	modelprovider.LabelTenant, modelprovider.LabelModelProvider, outsideagent.LabelOutsideAgent,
}

// applyObject creates the object, or updates it when its spec or labels differ.
// It is the write of each controller and loop that renders gateway objects.
func applyObject(ctx context.Context, c client.Client, desired *unstructured.Unstructured) error {
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(desired.GroupVersionKind())
	err := c.Get(ctx, client.ObjectKeyFromObject(desired), current)
	if apierrors.IsNotFound(err) {
		if cerr := c.Create(ctx, desired.DeepCopy()); cerr != nil {
			return fmt.Errorf("create %s %s: %w", desired.GetKind(), desired.GetName(), cerr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s %s: %w", desired.GetKind(), desired.GetName(), err)
	}
	// Two names can render to one object name (tenant a-b with agent c, and
	// tenant a with agent b-c). The object of another owner is never replaced.
	for _, k := range ownerLabelKeys {
		if have, want := current.GetLabels()[k], desired.GetLabels()[k]; have != "" && want != "" && have != want {
			return fmt.Errorf("%s %s belongs to another owner (label %s is %q, not %q)",
				desired.GetKind(), desired.GetName(), k, have, want)
		}
	}
	wantSpec, _, _ := unstructured.NestedFieldNoCopy(desired.Object, "spec")
	haveSpec, _, _ := unstructured.NestedFieldNoCopy(current.Object, "spec")
	if equality.Semantic.DeepEqual(wantSpec, haveSpec) && labelsContain(current.GetLabels(), desired.GetLabels()) {
		return nil
	}
	updated := current.DeepCopy()
	updated.Object["spec"] = desired.DeepCopy().Object["spec"]
	merged := updated.GetLabels()
	if merged == nil {
		merged = map[string]string{}
	}
	for k, v := range desired.GetLabels() {
		merged[k] = v
	}
	updated.SetLabels(merged)
	if uerr := c.Update(ctx, updated); uerr != nil {
		return fmt.Errorf("update %s %s: %w", desired.GetKind(), desired.GetName(), uerr)
	}
	return nil
}

// upsertSecret writes a Secret in the namespace of the gateway. It creates the
// Secret, or it replaces the data and merges the labels when they differ. The
// error text never holds a value.
func upsertSecret(
	ctx context.Context, c client.Client, key types.NamespacedName,
	labels, annotations map[string]string, data map[string][]byte,
) error {
	var live corev1.Secret
	getErr := c.Get(ctx, key, &live)
	if apierrors.IsNotFound(getErr) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: key.Namespace, Name: key.Name, Labels: labels, Annotations: annotations,
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}
		if cerr := c.Create(ctx, secret); cerr != nil {
			return fmt.Errorf("create the credential Secret %s: %w", key.Name, cerr)
		}
		return nil
	}
	if getErr != nil {
		return fmt.Errorf("read the credential Secret %s: %w", key.Name, getErr)
	}
	if secretDataEqual(live.Data, data) && labelsContain(live.Labels, labels) {
		return nil
	}
	live.Data = data
	if live.Labels == nil {
		live.Labels = map[string]string{}
	}
	for k, v := range labels {
		live.Labels[k] = v
	}
	if uerr := c.Update(ctx, &live); uerr != nil {
		return fmt.Errorf("update the credential Secret %s: %w", key.Name, uerr)
	}
	return nil
}

func labelsContain(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// ownedSelector selects the gateway objects that belong to one provider.
func (r *ModelProviderReconciler) ownedSelector(mp *gibsonv1alpha1.ModelProvider) client.MatchingLabels {
	return client.MatchingLabels{
		modelprovider.LabelManagedBy:     "gibson-tenant-operator",
		modelprovider.LabelTenant:        mp.Spec.TenantID,
		modelprovider.LabelModelProvider: mp.Name,
		modelprovider.LabelSourceNS:      mp.Namespace,
	}
}

// listOwned returns the gateway objects of the provider, of both kinds.
func (r *ModelProviderReconciler) listOwned(ctx context.Context, mp *gibsonv1alpha1.ModelProvider) ([]unstructured.Unstructured, error) {
	var out []unstructured.Unstructured
	for _, gvk := range []schema.GroupVersionKind{agentgatewayBackendGVK, httpRouteGVK} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
		if err := r.List(ctx, list, client.InNamespace(r.Render.Namespace), r.ownedSelector(mp)); err != nil {
			return nil, fmt.Errorf("list %s: %w", gvk.Kind, err)
		}
		out = append(out, list.Items...)
	}
	return out, nil
}

// deleteStale removes a gateway object of the provider that the render no
// longer holds.
func (r *ModelProviderReconciler) deleteStale(
	ctx context.Context, mp *gibsonv1alpha1.ModelProvider, desired []*unstructured.Unstructured,
) error {
	want := map[string]bool{}
	for _, d := range desired {
		want[d.GetKind()+"/"+d.GetName()] = true
	}
	owned, err := r.listOwned(ctx, mp)
	if err != nil {
		return err
	}
	for i := range owned {
		o := &owned[i]
		if want[o.GetKind()+"/"+o.GetName()] {
			continue
		}
		if err := r.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete the stale %s %s: %w", o.GetKind(), o.GetName(), err)
		}
	}
	return nil
}

func (r *ModelProviderReconciler) reconcileDelete(ctx context.Context, mp *gibsonv1alpha1.ModelProvider) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(mp, gibsonv1alpha1.ModelProviderFinalizer) {
		return ctrl.Result{}, nil
	}
	owned, err := r.listOwned(ctx, mp)
	if err != nil {
		return ctrl.Result{}, err
	}
	for i := range owned {
		if err := r.Delete(ctx, &owned[i]); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete %s %s: %w", owned[i].GetKind(), owned[i].GetName(), err)
		}
	}
	// The credential Secret goes first. The finalizer stays until it is gone, so
	// a provider that is deleted never leaves a credential in the gateway
	// namespace.
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: r.Render.Namespace,
		Name:      modelprovider.CredentialSecretName(mp.Spec.TenantID, mp.Name),
	}}
	if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("delete the credential Secret %s: %w", secret.Name, err)
	}
	patch := client.MergeFrom(mp.DeepCopy())
	controllerutil.RemoveFinalizer(mp, gibsonv1alpha1.ModelProviderFinalizer)
	if err := r.Patch(ctx, mp, patch); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, nil
}

func (r *ModelProviderReconciler) fail(ctx context.Context, mp *gibsonv1alpha1.ModelProvider, cause error) (ctrl.Result, error) {
	r.setStatus(ctx, mp, gibsonv1alpha1.ModelProviderPhaseFailed, "", metav1.ConditionFalse, "Failed", cause.Error(), cause.Error())
	return ctrl.Result{}, cause
}

func (r *ModelProviderReconciler) setStatus(
	ctx context.Context, mp *gibsonv1alpha1.ModelProvider,
	phase gibsonv1alpha1.ModelProviderPhase, secretName string,
	cond metav1.ConditionStatus, reason, message, lastError string,
) {
	base := mp.DeepCopy()
	mp.Status.Phase = phase
	mp.Status.Ready = phase == gibsonv1alpha1.ModelProviderPhaseReady
	if secretName != "" {
		mp.Status.CredentialSecretName = secretName
	}
	mp.Status.LastError = lastError
	mp.Status.ObservedGeneration = mp.Generation
	meta := metav1.Condition{
		Type: gibsonv1alpha1.ConditionModelProviderReady, Status: cond, Reason: reason, Message: message,
		ObservedGeneration: mp.Generation, LastTransitionTime: metav1.Now(),
	}
	replaced := false
	for i := range mp.Status.Conditions {
		if mp.Status.Conditions[i].Type == meta.Type {
			if mp.Status.Conditions[i].Status == cond {
				meta.LastTransitionTime = mp.Status.Conditions[i].LastTransitionTime
			}
			mp.Status.Conditions[i] = meta
			replaced = true
		}
	}
	if !replaced {
		mp.Status.Conditions = append(mp.Status.Conditions, meta)
	}
	if equality.Semantic.DeepEqual(base.Status, mp.Status) {
		return
	}
	if err := r.Status().Patch(ctx, mp, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "patch the status of the model provider")
	}
}

// SetupWithManager registers the controller with the manager. A status write does
// not bump the generation, so it does not trigger a second reconcile.
func (r *ModelProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := r.Render.Validate(); err != nil {
		return fmt.Errorf("model provider reconciler: %w", err)
	}
	if r.Credentials == nil {
		return errors.New("model provider reconciler: the credential source is required")
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("modelprovider-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.ModelProvider{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("modelprovider").
		Complete(r)
}
