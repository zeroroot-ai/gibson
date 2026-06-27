// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	fga "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/fga"
	vault "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/vault"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

const (
	platformBootstrapFinalizer = "platform-operator.gibson.zeroroot.ai/platformbootstrap"
	// defaultChildNamespace is where child OIDCClient CRs land when the
	// parent's spec doesn't specify one. The platform-workloads chart
	// installs into `gibson`.
	defaultChildNamespace = "gibson"
)

// FGAClientFactory builds an OpenFGA client. Wired for test substitution.
type FGAClientFactory func(apiEndpoint string) (fga.Client, error)

// VaultClientFactory builds a Vault client from an endpoint and a token
// function. The tokenFn is called on every HTTP request so that a
// lease-renewing source (vaulttoken.Renewer) can supply a current token
// without requiring a new client per reconcile.
type VaultClientFactory func(apiEndpoint string, tokenFn vault.TokenFunc) (vault.Client, error)

// PostgresClientFactory is defined in platformbootstrap_postgres.go; the
// reconciler holds a field of that type for test substitution.

// VaultTokenSource supplies the current Vault admin token. Implementations
// must be safe for concurrent use from multiple goroutines.
//
// The primary production implementation is vaulttoken.Renewer, which wraps
// platform-clients vault.Provider and calls RenewSelf before the token TTL
// expires. Tests may substitute a static implementation.
//
// A non-nil error from Token signals that the token is stale or the renewal
// goroutine has lost contact with Vault; reconcileVaultTransit treats this as
// a transient error and requeues.
type VaultTokenSource interface {
	Token() (string, error)
}

// PlatformBootstrapReconciler reconciles PlatformBootstrap CRs.
//
// State machine per design.md (`### Component 4`):
//  1. Ensure Zitadel project exists + service users provisioned →
//     ZitadelProjectReady
//  2. Ensure one OIDCClient child CR per spec.oidcClients[], watch
//     children, aggregate → OIDCClientsReady
//     2b. Populate gibson-sa-identity-map ConfigMap with the numeric Zitadel
//     subject of each platform service account → SAIdentityMapReady
//  3. Load OpenFGA model → FGAModelLoaded
//  4. Ensure Vault transit engine + key (or skip if !enabled) →
//     VaultTransitReady
//  5. Plan sync (hash-based) → PlanSyncComplete
//  6. Register cluster-internal Zitadel Service hostname as trusted domain →
//     TrustedDomainReady (ADR-0006)
//  7. Top-level Ready = AND(above)
//
// Children (OIDCClient CRs) are owned via ownerReferences so K8s GC
// handles cascade on delete.
//
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps/finalizers,verbs=update
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create
type PlatformBootstrapReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	ZitadelFactory      ZitadelClientFactory
	FGAFactory          FGAClientFactory
	VaultFactory        VaultClientFactory
	VaultToken          VaultTokenSource
	PostgresFactory     PostgresClientFactory
	SystemClientFactory SystemClientFactory
}

// SetupWithManager wires the reconciler to the manager.
func (r *PlatformBootstrapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ZitadelFactory == nil {
		r.ZitadelFactory = DefaultZitadelClientFactory
	}
	if r.FGAFactory == nil {
		r.FGAFactory = fga.New
	}
	if r.VaultFactory == nil {
		r.VaultFactory = func(apiEndpoint string, tokenFn vault.TokenFunc) (vault.Client, error) {
			return vault.New(apiEndpoint, tokenFn)
		}
	}
	if r.PostgresFactory == nil {
		r.PostgresFactory = DefaultPostgresClientFactory
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.PlatformBootstrap{}).
		Watches(
			&gibsonv1alpha1.OIDCClient{},
			handler.EnqueueRequestsFromMapFunc(r.mapChildToParent),
		).
		Complete(r)
}

// mapChildToParent maps a child OIDCClient back to its PlatformBootstrap
// parent via ownerReferences so a child's Ready flip wakes up the parent
// to re-aggregate.
func (r *PlatformBootstrapReconciler) mapChildToParent(ctx context.Context, obj client.Object) []reconcile.Request {
	oc, ok := obj.(*gibsonv1alpha1.OIDCClient)
	if !ok {
		return nil
	}
	for _, owner := range oc.OwnerReferences {
		if owner.Kind == "PlatformBootstrap" && owner.APIVersion == gibsonv1alpha1.SchemeGroupVersion.String() {
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: owner.Name}}}
		}
	}
	return nil
}

// Reconcile is the top-level state-machine entry.
func (r *PlatformBootstrapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("platformbootstrap", req.Name)

	var pb gibsonv1alpha1.PlatformBootstrap
	if err := r.Get(ctx, req.NamespacedName, &pb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !pb.DeletionTimestamp.IsZero() {
		return r.reconcileDeletion(ctx, &pb)
	}

	if !controllerutil.ContainsFinalizer(&pb, platformBootstrapFinalizer) {
		controllerutil.AddFinalizer(&pb, platformBootstrapFinalizer)
		if err := r.Update(ctx, &pb); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Step 1: Zitadel project + service users.
	if result, err := r.reconcileZitadelProject(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 2: OIDCClient children.
	if result, err := r.reconcileOIDCChildren(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 2b: SA identity map. Runs after the OIDCClient children are Ready
	// because it reflects each MACHINE_USER child's numeric status.clientID
	// into the gibson-sa-identity-map ConfigMap. Replaces the gitops
	// sa-identity-map-populator Sync Job (gitops#170).
	if result, err := r.reconcileSAIdentityMap(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 3: Register cluster-internal Zitadel Service hostname as a trusted
	// domain so in-cluster consumers can dial it directly (ADR-0008).
	//
	// Ordering rationale: trusted-domain registration depends only on
	// reconcileZitadelProject (Step 1) + reconcileOIDCChildren (Step 2)
	// being complete (it needs the Zitadel instance + the system-bot
	// MACHINE_USER to exist). It is orthogonal to FGA, vault, plans,
	// master-key, and postgres-bundle — promoting it ahead of those
	// avoids gating slice 0 behind an unrelated reconciler short-circuit
	// (gitops#122 tracks the postgres-side investigation).
	if result, err := r.reconcileTrustedDomain(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 4: FGA model.
	if result, err := r.reconcileFGAModel(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 5: Vault transit.
	if result, err := r.reconcileVaultTransit(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 6: Plan sync.
	if result, err := r.reconcilePlanSync(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 7: Master-key Secret.
	if result, err := r.reconcileMasterKey(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Step 8: Postgres database ownership + grants.
	if result, err := r.reconcilePostgresBundle(ctx, &pb, logger); err != nil || !result.IsZero() {
		_ = r.statusUpdate(ctx, &pb)
		return result, err
	}

	// Top-level Ready rollup.
	r.aggregateReady(&pb)
	pb.Status.ObservedGeneration = pb.Generation
	if err := r.statusUpdate(ctx, &pb); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// reconcileZitadelProject ensures the Zitadel project exists and
// (optionally) provisions service users with their PATs.
func (r *PlatformBootstrapReconciler) reconcileZitadelProject(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	pat, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.Zitadel.AdminTokenRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
			"WaitingForAdminToken", "Zitadel admin token Secret not yet materialised")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	zc := r.ZitadelFactory(pb.Spec.Zitadel.Issuer, pat)
	if pb.Spec.Zitadel.Project.EnsureExists {
		if _, err := zc.EnsureProject(ctx, pb.Spec.Zitadel.Project.Name); err != nil {
			if zitadel.IsPermanent(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
					"ZitadelPermanentError", fmt.Sprintf("EnsureProject: %v", err))
				return ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionUnknown,
				"ZitadelTransientError", fmt.Sprintf("EnsureProject: %v", err))
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
	} else {
		if _, err := zc.GetProjectIDByName(ctx, pb.Spec.Zitadel.Project.Name); err != nil {
			if zitadel.IsNotFound(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
					"ProjectNotFound", fmt.Sprintf("project %q does not exist (ensureExists=false)", pb.Spec.Zitadel.Project.Name))
				return ctrl.Result{}, nil
			}
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
	}
	// Enforce allowRegister=false on the instance login policy so Zitadel's
	// hosted self-registration page is not served. DefaultInstance config in
	// the chart only applies at first-instance creation, so already-running
	// instances are closed here, idempotently, on every reconcile (deploy#886).
	if changed, err := zc.EnsureRegistrationDisabled(ctx); err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("EnsureRegistrationDisabled: %v", err))
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("EnsureRegistrationDisabled: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	} else if changed {
		logger.Info("disabled Zitadel self-service registration on the instance login policy (deploy#886)")
	}

	// Service-user provisioning is deferred — handled by tenant-operator's
	// existing zitadel-mint-user-pat tooling. Marked Ready here.
	setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionTrue,
		"ProjectExists", "Zitadel project reachable")
	return ctrl.Result{}, nil
}

// reconcileOIDCChildren creates one OIDCClient CR per spec.oidcClients[]
// entry and watches their Ready conditions, aggregating into the parent.
func (r *PlatformBootstrapReconciler) reconcileOIDCChildren(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	allReady := true
	pb.Status.OIDCClients = nil
	for _, ref := range pb.Spec.OIDCClients {
		child := &gibsonv1alpha1.OIDCClient{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ref.Name,
				Namespace: defaultChildNamespace,
			},
		}
		op, err := controllerutil.CreateOrUpdate(ctx, r.Client, child, func() error {
			if err := controllerutil.SetControllerReference(pb, child, r.Scheme); err != nil {
				return err
			}
			child.Spec = gibsonv1alpha1.OIDCClientSpec{
				ZitadelIssuer:              pb.Spec.Zitadel.Issuer,
				AdminTokenRef:              pb.Spec.Zitadel.AdminTokenRef,
				ProjectRef:                 gibsonv1alpha1.ProjectReference{Name: pb.Spec.Zitadel.Project.Name},
				ClientName:                 ref.Name,
				ApplicationType:            defaultAppType(ref),
				Roles:                      ref.Roles,
				RedirectURIs:               ref.RedirectURIs,
				PostLogoutRedirectURIs:     ref.PostLogoutRedirectURIs,
				GrantTypes:                 grantTypesForRef(ref),
				ResponseTypes:              defaultResponseTypes(ref),
				AccessTokenLifetimeSeconds: ref.AccessTokenLifetimeSeconds,
				SecretRef:                  ref.SecretRef,
			}
			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("CreateOrUpdate OIDCClient %s: %w", ref.Name, err)
		}
		_ = op

		var current gibsonv1alpha1.OIDCClient
		if err := r.Get(ctx, types.NamespacedName{Namespace: defaultChildNamespace, Name: ref.Name}, &current); err != nil {
			return ctrl.Result{}, err
		}
		entry := gibsonv1alpha1.OIDCClientStatusEntry{
			Name:     ref.Name,
			ClientID: current.Status.ClientID,
			Ready:    isConditionTrue(current.Status.Conditions, gibsonv1alpha1.ConditionReady),
		}
		pb.Status.OIDCClients = append(pb.Status.OIDCClients, entry)
		if !entry.Ready {
			allReady = false
		}
	}
	if allReady {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionOIDCClientsReady, metav1.ConditionTrue,
			"AllChildrenReady", fmt.Sprintf("%d/%d OIDCClient CRs Ready", len(pb.Spec.OIDCClients), len(pb.Spec.OIDCClients)))
		return ctrl.Result{}, nil
	}
	ready := 0
	for _, e := range pb.Status.OIDCClients {
		if e.Ready {
			ready++
		}
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionOIDCClientsReady, metav1.ConditionFalse,
		"ChildrenPending",
		fmt.Sprintf("%d/%d OIDCClient CRs Ready", ready, len(pb.Spec.OIDCClients)))
	return ctrl.Result{RequeueAfter: requeueMedium}, nil
}

// reconcileFGAModel ensures the OpenFGA store + authorization model.
// reconcileFGAModel loads the OpenFGA authorization model. OpenFGA is
// structural infrastructure (ADR-0003 one-code-path) and the spec is
// CRD-required; no `FGADisabled` skip path exists.
func (r *PlatformBootstrapReconciler) reconcileFGAModel(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	// Read the model ConfigMap.
	cm, err := r.readConfigMap(ctx, defaultChildNamespace, pb.Spec.FGAModel.ModelConfigMapRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionFGAModelLoaded, metav1.ConditionFalse,
				"WaitingForModelConfigMap", err.Error())
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		return ctrl.Result{}, err
	}
	model := []byte(cm.Data[pb.Spec.FGAModel.ModelConfigMapRef.Key])
	if len(model) == 0 {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionFGAModelLoaded, metav1.ConditionFalse,
			"EmptyModel", "ConfigMap key is empty")
		return ctrl.Result{}, nil
	}

	fgaCli, err := r.FGAFactory(pb.Spec.FGAModel.APIEndpoint)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionFGAModelLoaded, metav1.ConditionFalse,
			"FGAClientInit", err.Error())
		return ctrl.Result{}, nil
	}
	storeID, err := fgaCli.EnsureStore(ctx, "gibson")
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionFGAModelLoaded, metav1.ConditionFalse,
			"FGATransientError", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	// Hash-based "did the model content change?" check. Stored on the
	// condition's reason field so re-reconciles short-circuit when
	// nothing has changed.
	hash := sha256.Sum256(model)
	hashHex := hex.EncodeToString(hash[:])
	if c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionFGAModelLoaded); c != nil && c.Reason == "ModelMatchesHash:"+hashHex {
		return ctrl.Result{}, nil
	}
	modelID, err := fgaCli.WriteAuthorizationModel(ctx, storeID, model)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionFGAModelLoaded, metav1.ConditionFalse,
			"FGAModelWriteFailed", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	// Persist the store ID into the spec.fgaModel.storeNameRef Secret.
	if err := r.writeFGAStoreID(ctx, pb.Spec.FGAModel.StoreNameRef, storeID, modelID); err != nil {
		return ctrl.Result{}, err
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionFGAModelLoaded, metav1.ConditionTrue,
		"ModelMatchesHash:"+hashHex,
		fmt.Sprintf("model loaded; storeID=%s modelID=%s", storeID, modelID))
	return ctrl.Result{}, nil
}

// reconcileVaultTransit ensures the Vault transit engine + named key.
// reconcileVaultTransit mounts the Vault transit secrets engine and creates
// the per-cluster master-kek key. Vault transit is structural infrastructure
// per ADR-0003 one-code-path / [[feedback-no-service-is-optional]] — there is
// NO `.enabled` toggle; if Vault is unreachable the reconcile requeues
// rather than skipping. CRD validation enforces non-empty Address + TokenRef.
//
// Token resolution order (first that succeeds):
//  1. r.VaultToken (a vaulttoken.Renewer with background lease renewal) — the
//     production path wired in main.go. Token() returns an error when the
//     renewal goroutine has lost contact with Vault, surfacing the problem as
//     a transient condition rather than silently using a stale credential.
//  2. spec.vaultTransit.tokenRef K8s Secret — fallback for test environments
//     and upgrade paths where the renewer is not yet wired.
func (r *PlatformBootstrapReconciler) reconcileVaultTransit(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	var tokenFn vault.TokenFunc

	if r.VaultToken != nil {
		// Production path: use the lease-renewing token source.
		tokenFn = func() (string, error) {
			tok, err := r.VaultToken.Token()
			if err != nil {
				return "", err
			}
			return tok, nil
		}
	} else {
		// Fallback: read from K8s Secret on each reconcile (preserves
		// pre-existing behaviour for tests and environments without the renewer).
		token, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.VaultTransit.TokenRef)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !ok {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionVaultTransitReady, metav1.ConditionFalse,
				"WaitingForVaultToken", "vault admin token Secret not yet materialised")
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		tokenFn = func() (string, error) { return token, nil }
	}

	vc, err := r.VaultFactory(pb.Spec.VaultTransit.Address, tokenFn)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionVaultTransitReady, metav1.ConditionFalse,
			"VaultClientInit", err.Error())
		return ctrl.Result{}, nil
	}
	if err := vc.EnsureTransitMounted(ctx); err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionVaultTransitReady, metav1.ConditionFalse,
			"VaultMountFailed", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	keyName := pb.Spec.VaultTransit.KeyName
	if keyName == "" {
		keyName = "master-kek"
	}
	if err := vc.EnsureTransitKey(ctx, keyName); err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionVaultTransitReady, metav1.ConditionFalse,
			"VaultKeyFailed", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionVaultTransitReady, metav1.ConditionTrue,
		"TransitReady", fmt.Sprintf("key %q ready", keyName))
	return ctrl.Result{}, nil
}

// reconcilePlanSync hashes the plans ConfigMap and writes a status-side
// hash anchor; the daemon reads plans directly from the source ConfigMap.
func (r *PlatformBootstrapReconciler) reconcilePlanSync(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	if pb.Spec.PlanSync == nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlanSyncComplete, metav1.ConditionTrue,
			"PlanSyncDisabled", "spec.planSync not configured")
		return ctrl.Result{}, nil
	}
	cm, err := r.readConfigMap(ctx, defaultChildNamespace, pb.Spec.PlanSync.PlansConfigMapRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPlanSyncComplete, metav1.ConditionFalse,
				"WaitingForPlansConfigMap", err.Error())
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		return ctrl.Result{}, err
	}
	body := []byte(cm.Data[pb.Spec.PlanSync.PlansConfigMapRef.Key])
	hash := sha256.Sum256(body)
	hashHex := hex.EncodeToString(hash[:])
	setBootstrapCond(pb, gibsonv1alpha1.ConditionPlanSyncComplete, metav1.ConditionTrue,
		"PlanHash:"+hashHex,
		fmt.Sprintf("plans ConfigMap %s/%s key %s hashed",
			cm.Namespace, cm.Name, pb.Spec.PlanSync.PlansConfigMapRef.Key))
	return ctrl.Result{}, nil
}

// reconcileDeletion runs the finalizer logic.
func (r *PlatformBootstrapReconciler) reconcileDeletion(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(pb, platformBootstrapFinalizer) {
		return ctrl.Result{}, nil
	}
	// Children (OIDCClient CRs) cascade-GC via ownerReferences and run
	// their own finalizers to revoke Zitadel-side state. We do NOT
	// delete the FGA model or Zitadel project — destructive ops require
	// explicit operator action.
	controllerutil.RemoveFinalizer(pb, platformBootstrapFinalizer)
	if err := r.Update(ctx, pb); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// aggregateReady computes the top-level Ready condition as the AND of
// every sub-step condition.
func (r *PlatformBootstrapReconciler) aggregateReady(pb *gibsonv1alpha1.PlatformBootstrap) {
	all := []string{
		gibsonv1alpha1.ConditionZitadelProjectReady,
		gibsonv1alpha1.ConditionOIDCClientsReady,
		gibsonv1alpha1.ConditionSAIdentityMapReady,
		gibsonv1alpha1.ConditionFGAModelLoaded,
		gibsonv1alpha1.ConditionVaultTransitReady,
		gibsonv1alpha1.ConditionPlanSyncComplete,
		gibsonv1alpha1.ConditionMasterKeyReady,
		gibsonv1alpha1.ConditionPostgresBundleReady,
		gibsonv1alpha1.ConditionTrustedDomainReady,
	}
	for _, cType := range all {
		c := findCondition(pb.Status.Conditions, cType)
		if c == nil || c.Status != metav1.ConditionTrue {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionReady, metav1.ConditionFalse,
				"SubstepsPending", "one or more sub-step conditions are not Ready")
			return
		}
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionReady, metav1.ConditionTrue,
		"AllStepsComplete", "every bootstrap step is complete")
}

// readSecretKey reads a SecretKeyRef. Returns (value, true, nil) on
// success; (_, false, nil) if Secret or key missing; (_, _, err) on
// real errors.
func (r *PlatformBootstrapReconciler) readSecretKey(ctx context.Context, fallbackNs string, ref gibsonv1alpha1.SecretKeyRef) (string, bool, error) {
	ns := secretNamespace(ref, fallbackNs)
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}
	v, ok := sec.Data[ref.Key]
	if !ok || len(v) == 0 {
		return "", false, nil
	}
	// Defensive trim: the Zitadel chart's setup Job has historically
	// written its iam-admin-pat with a trailing newline, which produces
	// a malformed `Authorization: Bearer <pat>\n` header. Strip any
	// surrounding whitespace at the boundary — every consumer of this
	// helper passes the value into HTTP headers or DSN fields where
	// whitespace is never wanted.
	return strings.TrimSpace(string(v)), true, nil
}

// readConfigMap reads a ConfigMapKeyRef.
func (r *PlatformBootstrapReconciler) readConfigMap(ctx context.Context, fallbackNs string, ref gibsonv1alpha1.ConfigMapKeyRef) (*corev1.ConfigMap, error) {
	ns := ref.Namespace
	if ns == "" {
		ns = fallbackNs
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &cm); err != nil {
		return nil, err
	}
	return &cm, nil
}

// writeFGAStoreID persists the store + model IDs into the Secret named
// in spec.fgaModel.storeNameRef.
func (r *PlatformBootstrapReconciler) writeFGAStoreID(ctx context.Context, ref gibsonv1alpha1.SecretKeyRef, storeID, modelID string) error {
	ns := secretNamespace(ref, defaultChildNamespace)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ns},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sec, func() error {
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[ref.Key] = []byte(storeID)
		sec.Data["model_id"] = []byte(modelID)
		sec.Type = corev1.SecretTypeOpaque
		return nil
	})
	if err != nil {
		return fmt.Errorf("write FGA store ID secret: %w", err)
	}
	return nil
}

// statusUpdate writes status via the subresource.
func (r *PlatformBootstrapReconciler) statusUpdate(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap) error {
	if err := r.Status().Update(ctx, pb); err != nil {
		return fmt.Errorf("PlatformBootstrap status update: %w", err)
	}
	return nil
}

// setBootstrapCond patches one condition on a PlatformBootstrap.
func setBootstrapCond(pb *gibsonv1alpha1.PlatformBootstrap, t string, s metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i := range pb.Status.Conditions {
		c := &pb.Status.Conditions[i]
		if c.Type != t {
			continue
		}
		if c.Status == s && c.Reason == reason {
			c.Message = message
			c.ObservedGeneration = pb.Generation
			return
		}
		c.Status = s
		c.Reason = reason
		c.Message = message
		c.LastTransitionTime = now
		c.ObservedGeneration = pb.Generation
		return
	}
	pb.Status.Conditions = append(pb.Status.Conditions, metav1.Condition{
		Type:               t,
		Status:             s,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
		ObservedGeneration: pb.Generation,
	})
}

func findCondition(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

func isConditionTrue(conds []metav1.Condition, t string) bool {
	c := findCondition(conds, t)
	return c != nil && c.Status == metav1.ConditionTrue
}

// Default OIDC client config when the parent spec doesn't override.
// Honors an explicit ref.ApplicationType when set; otherwise picks WEB
// for redirect-URI clients and SERVICE for the rest. SERVICE is the
// safe historic default — overlays that need the daemon/operator
// client_credentials path must opt in to MACHINE_USER explicitly.
func defaultAppType(ref gibsonv1alpha1.OIDCClientReference) gibsonv1alpha1.OIDCApplicationType {
	if ref.ApplicationType != "" {
		return ref.ApplicationType
	}
	if len(ref.RedirectURIs) > 0 {
		return gibsonv1alpha1.OIDCAppTypeWeb
	}
	return gibsonv1alpha1.OIDCAppTypeService
}

// grantTypesForRef honors an explicit ref.GrantTypes (e.g. the CLI
// device-grant app sets DEVICE_CODE + AUTHORIZATION_CODE + REFRESH_TOKEN),
// falling back to the RedirectURIs-derived default when unset.
func grantTypesForRef(ref gibsonv1alpha1.OIDCClientReference) []gibsonv1alpha1.OIDCGrantType {
	if len(ref.GrantTypes) > 0 {
		return ref.GrantTypes
	}
	return defaultGrantTypes(ref)
}

func defaultGrantTypes(ref gibsonv1alpha1.OIDCClientReference) []gibsonv1alpha1.OIDCGrantType {
	if len(ref.RedirectURIs) > 0 {
		return []gibsonv1alpha1.OIDCGrantType{
			gibsonv1alpha1.OIDCGrantType("AUTHORIZATION_CODE"),
			gibsonv1alpha1.OIDCGrantType("REFRESH_TOKEN"),
		}
	}
	return []gibsonv1alpha1.OIDCGrantType{
		gibsonv1alpha1.OIDCGrantType("CLIENT_CREDENTIALS"),
	}
}

func defaultResponseTypes(ref gibsonv1alpha1.OIDCClientReference) []gibsonv1alpha1.OIDCResponseType {
	if len(ref.RedirectURIs) > 0 {
		return []gibsonv1alpha1.OIDCResponseType{
			gibsonv1alpha1.OIDCResponseType("CODE"),
		}
	}
	return nil
}
