// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"k8s.io/client-go/util/retry"
	"os"
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

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
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
// internal/infra/secrets/vault Provider and calls RenewSelf before the token TTL
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
//  6. Top-level Ready = AND(above)
//
// Children (OIDCClient CRs) are owned via ownerReferences so K8s GC
// handles cascade on delete.
type PlatformBootstrapReconciler struct {
	client.Client
	// APIReader reads the PlatformBootstrap straight from the API server.
	// The manager's default client reads through the informer cache, which
	// lags the reconciler's own status write by up to a second, so the very
	// next pass could read stale status and repeat a side effect it had
	// already recorded: identity run 36680224658 mailed the Platform owner's
	// setup link twice one second apart that way. Nil in tests, where the
	// fake client has no cache and Client serves both reads.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	// ZitadelURL is the in-cluster address the operator connects to: the
	// connect base of ZITADEL_URL (ADR-0092, gibson#665). Empty means
	// SetupWithManager reads it from the environment, and a start with no
	// valid ZITADEL_URL fails.
	ZitadelURL     string
	ZitadelFactory ZitadelClientFactory
	FGAFactory     FGAClientFactory
	VaultFactory   VaultClientFactory
	VaultToken     VaultTokenSource
	// Now is the clock of the admin token expiry. Nil means time.Now.
	Now                 func() time.Time
	PostgresFactory     PostgresClientFactory
	SystemClientFactory SystemClientFactory
}

// SetupWithManager wires the reconciler to the manager.
func (r *PlatformBootstrapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ZitadelURL == "" {
		url, err := ZitadelConnectURLFromEnv(os.Getenv)
		if err != nil {
			return fmt.Errorf("platformbootstrap: ZitadelURL is required: %w", err)
		}
		r.ZitadelURL = url
	}
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
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.mapBrandingConfigMap),
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

// The RBAC markers stand here, above a function and apart from its doc
// comment, because controller-gen reads a marker only from a comment that
// belongs to no type. In the doc comment of the reconciler type, where they
// stood before, it ignored all of them and generated no role.
//
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps/finalizers,verbs=update
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create

// Reconcile is the top-level state-machine entry.
func (r *PlatformBootstrapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx).WithValues("platformbootstrap", req.Name)

	var pb gibsonv1alpha1.PlatformBootstrap
	if err := r.reader().Get(ctx, req.NamespacedName, &pb); err != nil {
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
	// Every step below records what it did on pb.Status. One deferred write
	// persists that on every return path, and a failed write is a reconcile
	// error, never a silent loss: the next pass would otherwise read the old
	// status and repeat a step, and a step that mailed a setup link or
	// deleted an account cannot be repeated (identity run 36680224658).
	defer func() { result, err = r.finish(ctx, &pb, result, err) }()
	// The steps, in order. Each records what it did on pb.Status and returns
	// a non-zero Result or an error to stop the pass there; the comments
	// above each step say why it sits where it does.
	steps := []reconcileStep{
		// Step 0: escrow the OpenBao unseal key.
		//
		// FIRST, deliberately. Escrow depends on nothing but the minted key, and
		// every later step depends on services that can be down. Running it after
		// them means a cluster that is partially broken — a failed Zitadel call
		// is enough — never escrows its key at all, which is precisely the
		// cluster whose key you will wish had been copied out. Ordering this last
		// made escrow least likely to happen exactly when it mattered most.
		//
		// It never blocks the rest: an unescrowed key holds the Ready condition,
		// not the reconcile.
		r.reconcileUnsealEscrow,
		// Step 0b: the Zitadel admin token in OpenBao (gibson#794). The
		// operator mints it with its System API key, so it needs no token
		// to exist before. Step 1 reads it through the ExternalSecret.
		r.reconcileAdminToken,
		// Step 1: Zitadel project + service users.
		r.reconcileZitadelProject,
		// Step 2: OIDCClient children.
		r.reconcileOIDCChildren,
		// Step 2b: SA identity map. Runs after the OIDCClient children are Ready
		// because it reflects each MACHINE_USER child's numeric status.clientID
		// into the gibson-sa-identity-map ConfigMap. Replaces the gitops
		// sa-identity-map-populator Sync Job (gitops#170).
		r.reconcileSAIdentityMap,
		// Step 4: FGA model.
		r.reconcileFGAModel,
		// Step 5: Vault transit.
		r.reconcileVaultTransit,
		// Step 6: Plan sync.
		r.reconcilePlanSync,
		// Step 7: Master-key Secret.
		r.reconcileMasterKey,
		// Step 8: Postgres database ownership + grants.
		r.reconcilePostgresBundle,
		// Step 9: the login pages' brand. It never stops the reconcile; see
		// reconcileLoginBranding.
		func(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
			r.reconcileLoginBranding(ctx, pb, logger)
			return ctrl.Result{}, nil
		},
		// Step 9b: the instance's one SMTP email provider (hosted#189). Placed
		// before Step 10 deliberately: reconcilePlatformOwner's mailed setup
		// link is only trustworthy once this step has confirmed (or repaired)
		// an active SMTP provider in the same pass, so a fresh Platform owner is
		// never told "emailed" while nothing can actually deliver the mail.
		r.reconcileZitadelSMTP,
		// Step 10: Platform owner (ADR-0093 decision 6/8, hosted#201). Ordering
		// rationale: depends on the Zitadel project (Step 1, for the org id and
		// admin token) and the FGA model (Step 4, for the store/model ids the
		// platform_owner tuple write needs) both being available. Placed last so
		// a Platform owner is never provisioned against a half-bootstrapped
		// instance.
		r.reconcilePlatformOwner,
		// Step 11: keep the Platform owner the only human Zitadel administrator
		// (ADR-0093 decision 6, hosted#189). Must run after reconcilePlatformOwner
		// (Step 10): it needs status.PlatformOwnerUserID to know which human
		// member to keep, and reconcilePlatformOwner only returns a zero Result
		// once that id is persisted.
		r.reconcileHumanAdminsScoped,
		// Step 12: keep the declared service accounts and the login client the
		// only machine Zitadel administrators (ADR-0093 decision 6, hosted#207).
		// Reads the same service-account list as Step 2b, so it only removes a
		// machine member once every declared one is known.
		r.reconcileMachineAdminsScoped,
		// Top-level Ready rollup.
	}
	for _, step := range steps {
		if result, err = step(ctx, &pb, logger); err != nil || !result.IsZero() {
			return result, err
		}
	}
	r.aggregateReady(&pb)
	pb.Status.ObservedGeneration = pb.Generation
	// The deferred finish writes the status this pass left on pb.
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
	zc := r.ZitadelFactory(r.ZitadelURL, pat)
	var projectID string
	if pb.Spec.Zitadel.Project.EnsureExists {
		id, err := zc.EnsureProject(ctx, pb.Spec.Zitadel.Project.Name)
		if err != nil {
			if zitadel.IsPermanent(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
					"ZitadelPermanentError", fmt.Sprintf("EnsureProject: %v", err))
				return ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionUnknown,
				"ZitadelTransientError", fmt.Sprintf("EnsureProject: %v", err))
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		projectID = id
	} else {
		id, err := zc.GetProjectIDByName(ctx, pb.Spec.Zitadel.Project.Name)
		if err != nil {
			if zitadel.IsNotFound(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
					"ProjectNotFound", fmt.Sprintf("project %q does not exist (ensureExists=false)", pb.Spec.Zitadel.Project.Name))
				return ctrl.Result{}, nil
			}
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		projectID = id
	}

	// Reconcile the four tenant roles on the project (ADR-0093 decision 2).
	// Every tenant org's project grant and every user's role grant name one
	// of these keys, so the project must carry exactly this set before any
	// tenant can be granted access to it.
	if changed, err := zc.EnsureProjectRoles(ctx, projectID, tenantrole.All); err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("EnsureProjectRoles: %v", err))
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("EnsureProjectRoles: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	} else if changed {
		logger.Info("reconciled tenant roles on the gibson project")
	}

	// Enforce the sign-in policy of every install (ADR-0093 section 9): MFA
	// for everyone, passkey or authenticator app only, no external IdPs, no
	// self-service registration (deploy#886 folds in here). Also keep
	// usernames unique install-wide (decision 1), which is what makes our
	// email-derived usernames unique too. DefaultInstance config in the
	// chart only applies at first-instance creation, so already-running
	// instances are corrected here, idempotently, on every reconcile.
	if changed, err := zc.EnsureDomainPolicy(ctx, usernamePolicy); err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("EnsureDomainPolicy: %v", err))
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("EnsureDomainPolicy: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	} else if changed {
		logger.Info("corrected the Zitadel instance domain policy (ADR-0093 decision 1)")
		if r.Recorder != nil {
			r.Recorder.Event(pb, corev1.EventTypeNormal, "SignInPolicyCorrected",
				"corrected: userLoginMustBeDomain")
		}
	}

	corrected, err := zc.EnsureLoginPolicy(ctx, signInPolicy)
	if err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("EnsureLoginPolicy: %v", err))
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("EnsureLoginPolicy: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	if len(corrected) > 0 {
		logger.Info("corrected the Zitadel instance login policy (ADR-0093 section 9)", "corrected", corrected)
		if r.Recorder != nil {
			r.Recorder.Eventf(pb, corev1.EventTypeNormal, "SignInPolicyCorrected",
				"corrected: %s", strings.Join(corrected, ", "))
		}
	}

	// Service-user provisioning is deferred — handled by tenant-operator's
	// existing zitadel-mint-user-pat tooling. Marked Ready here.
	setBootstrapCond(pb, gibsonv1alpha1.ConditionZitadelProjectReady, metav1.ConditionTrue,
		"ProjectExists", "Zitadel project reachable; tenant roles present")
	return ctrl.Result{}, nil
}

// oidcClientDisplayName returns the Zitadel display name for a reference:
// displayName when set, else name.
func oidcClientDisplayName(ref gibsonv1alpha1.OIDCClientReference) string {
	if ref.DisplayName != "" {
		return ref.DisplayName
	}
	return ref.Name
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
				ZitadelURL:                 r.ZitadelURL,
				AdminTokenRef:              pb.Spec.Zitadel.AdminTokenRef,
				ProjectRef:                 gibsonv1alpha1.ProjectReference{Name: pb.Spec.Zitadel.Project.Name},
				ClientName:                 oidcClientDisplayName(ref),
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
//
// Every failure branch below sets VaultTransitReady=False AND requeues with
// backoff (requeueMedium) — none of them return a zero Result. gibson#1173:
// a from-zero bringup raced OpenBao writing the real admin token against
// this reconciler (and the vaulttoken.Renewer inside it, see that package's
// doc comment for the deeper fix) reading a stale placeholder; the specific
// bug that made it un-recoverable without a pod restart lived in
// vaulttoken.Renewer, not here — but every step in this function must still
// requeue on its own so a condition that resolves out-of-band (Vault comes
// back reachable, the token Secret is corrected, etc.) is re-evaluated
// without operator intervention.
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
		// Requeue rather than returning a zero Result: nothing else watches
		// this object to re-trigger a reconcile on a spec.vaultTransit.address
		// fix, so a zero Result here would wedge VaultTransitReady=False
		// forever (gibson#1173 — every "step failed" branch in this function
		// must requeue with backoff so a transient or externally-corrected
		// condition is re-evaluated on its own, without operator intervention).
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
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
		gibsonv1alpha1.ConditionAdminTokenReady,
		gibsonv1alpha1.ConditionZitadelProjectReady,
		gibsonv1alpha1.ConditionOIDCClientsReady,
		gibsonv1alpha1.ConditionSAIdentityMapReady,
		gibsonv1alpha1.ConditionFGAModelLoaded,
		gibsonv1alpha1.ConditionVaultTransitReady,
		gibsonv1alpha1.ConditionPlanSyncComplete,
		gibsonv1alpha1.ConditionMasterKeyReady,
		gibsonv1alpha1.ConditionUnsealKeyEscrowed,
		gibsonv1alpha1.ConditionPostgresBundleReady,
		gibsonv1alpha1.ConditionLoginBrandingReady,
		gibsonv1alpha1.ConditionSMTPProviderReady,
		gibsonv1alpha1.ConditionPlatformOwnerReady,
		gibsonv1alpha1.ConditionHumanAdminsScoped,
		gibsonv1alpha1.ConditionMachineAdminsScoped,
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
//
// A conflict is retried onto a fresh read of the object with the status THIS
// reconcile computed. One reconcile creates the Platform owner in Zitadel,
// records the new user id in pb.Status and writes it here; when the write
// lost a conflict to a concurrent status writer, the id was dropped, the
// next reconcile created the user again (409) and looked it up by email,
// and the platform never became ready (hosted#309). Zitadel side effects
// are not repeatable, so the status that records them must land.
func (r *PlatformBootstrapReconciler) statusUpdate(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap) error {
	desired := pb.Status.DeepCopy()
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		uerr := r.Status().Update(ctx, pb)
		if uerr == nil {
			return nil
		}
		if !apierrors.IsConflict(uerr) {
			return fmt.Errorf("status update: %w", uerr)
		}
		fresh := &gibsonv1alpha1.PlatformBootstrap{}
		if gerr := r.Get(ctx, client.ObjectKeyFromObject(pb), fresh); gerr != nil {
			return fmt.Errorf("re-read PlatformBootstrap after a conflict: %w", gerr)
		}
		fresh.Status = *desired
		*pb = *fresh
		// Wrapped, and still a conflict for RetryOnConflict (errors.As).
		return fmt.Errorf("status update conflict, retrying: %w", uerr)
	})
	if err != nil {
		return fmt.Errorf("PlatformBootstrap status update: %w", err)
	}
	return nil
}

// reconcileStep is one ordered step of Reconcile. A non-zero Result or an
// error stops the pass at that step; the deferred finish still writes the
// status the step left on pb.
type reconcileStep func(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error)

// reader is the client that fetches the PlatformBootstrap at the start of a
// pass: the uncached API reader when the manager gave us one, else Client.
func (r *PlatformBootstrapReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// finish writes the status a step left on pb and returns the step's result.
// A status write that fails is a reconcile error, never a silent loss: the
// next pass would otherwise read the old status and repeat the step, and a
// step that mailed a setup link or deleted an account cannot be repeated.
// The error surfaces in the controller's "Reconciler error" log line and
// requeues the object with backoff.
func (r *PlatformBootstrapReconciler) finish(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, result ctrl.Result, err error) (ctrl.Result, error) {
	if serr := r.statusUpdate(ctx, pb); serr != nil {
		if err != nil {
			return result, fmt.Errorf("%w (and the status write failed: %w)", err, serr)
		}
		return result, serr
	}
	return result, err
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
