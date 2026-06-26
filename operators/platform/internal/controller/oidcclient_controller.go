// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"
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
	"sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// oidcClientFinalizer is the finalizer string the controller owns on
// every OIDCClient CR. Revokes the Zitadel client on delete (best-effort,
// bounded retries — see Reconcile's deletion branch).
const oidcClientFinalizer = "platform-operator.gibson.zeroroot.ai/oidcclient"

// requeue helpers — match the design's retry policy.
var (
	requeueShort  = 10 * time.Second
	requeueMedium = 30 * time.Second
)

// ZitadelClientFactory builds a Zitadel client from an admin-token PAT
// string. Wired so tests can substitute a fake.
type ZitadelClientFactory func(issuer, pat string) zitadel.Client

// DefaultZitadelClientFactory uses the real HTTP client. ZITADEL_EXTERNAL_DOMAIN
// env var (when set) is forged onto the Host header on every request so the
// operator can dial Zitadel's in-cluster Service name while still satisfying
// Zitadel's instance router. Tenant-operator uses the same pattern.
func DefaultZitadelClientFactory(issuer, pat string) zitadel.Client {
	return zitadel.New(issuer, pat, os.Getenv("ZITADEL_EXTERNAL_DOMAIN"))
}

// OIDCClientReconciler reconciles OIDCClient CRs.
//
// State machine per design (Error Handling #1-#4):
//  1. lookup admin-token Secret           → WaitingForAdminToken / requeue 30s
//  2. resolve project name → ID           → WaitingForProject / requeue 30s
//  3. ensure Zitadel client exists        → persist status.clientID FIRST
//  4. write K8s Secret with ownerRef      → SecretMaterialised
//  5. set Ready=True
//
// Transient 5xx / timeout → exponential backoff requeue (10s → 5min cap).
// Permanent 4xx           → conditions[ClientExists]=False, reason+message, no requeue.
// On delete (finalizer)    → revoke Zitadel client, cap 3 retries on transient errors,
//
//	then proceed and emit Warning event.
//
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=oidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=oidcclients/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
type OIDCClientReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Recorder       record.EventRecorder
	ZitadelFactory ZitadelClientFactory
}

// SetupWithManager wires the reconciler to the manager.
func (r *OIDCClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ZitadelFactory == nil {
		r.ZitadelFactory = DefaultZitadelClientFactory
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.OIDCClient{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// Reconcile runs the OIDCClient state machine.
func (r *OIDCClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("oidcclient", req.NamespacedName)

	var oc gibsonv1alpha1.OIDCClient
	if err := r.Get(ctx, req.NamespacedName, &oc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion path: finalizer revokes the Zitadel client before allowing
	// K8s garbage collection.
	if !oc.DeletionTimestamp.IsZero() {
		return r.reconcileDeletion(ctx, &oc)
	}

	// Ensure finalizer is present on first reconcile.
	if !controllerutil.ContainsFinalizer(&oc, oidcClientFinalizer) {
		controllerutil.AddFinalizer(&oc, oidcClientFinalizer)
		if err := r.Update(ctx, &oc); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Step 1: admin token Secret must exist.
	pat, ok, err := r.readSecretKey(ctx, oc.Namespace, oc.Spec.AdminTokenRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		r.setCondition(&oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionFalse,
			"WaitingForAdminToken",
			fmt.Sprintf("Secret %s/%s key %s does not exist yet",
				secretNamespace(oc.Spec.AdminTokenRef, oc.Namespace),
				oc.Spec.AdminTokenRef.Name, oc.Spec.AdminTokenRef.Key))
		r.setCondition(&oc, gibsonv1alpha1.ConditionReady, metav1.ConditionFalse,
			"WaitingForAdminToken", "Admin token Secret not yet materialised")
		if err := r.statusUpdate(ctx, &oc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	zc := r.ZitadelFactory(oc.Spec.ZitadelIssuer, pat)

	// MACHINE_USER branch: skip the OIDC-app path entirely. The resource
	// minted in Zitadel is a Service User (not an app); the K8s Secret
	// shape matches the OIDC-app path so consumers don't have to
	// distinguish — same clientID + clientSecret keys.
	if oc.Spec.ApplicationType == gibsonv1alpha1.OIDCAppTypeMachineUser {
		return r.reconcileMachineUser(ctx, &oc, zc, logger)
	}

	// Step 2: resolve project name → ID.
	projectID, err := zc.GetProjectIDByName(ctx, oc.Spec.ProjectRef.Name)
	if err != nil {
		if zitadel.IsNotFound(err) {
			r.setCondition(&oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionFalse,
				"WaitingForProject",
				fmt.Sprintf("Zitadel project %q not found", oc.Spec.ProjectRef.Name))
			r.setCondition(&oc, gibsonv1alpha1.ConditionReady, metav1.ConditionFalse,
				"WaitingForProject", "Parent project does not exist yet")
			if uerr := r.statusUpdate(ctx, &oc); uerr != nil {
				return ctrl.Result{}, uerr
			}
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		return r.handleTransientOrPermanent(ctx, &oc, "GetProjectIDByName", err, logger)
	}

	// Step 3: ensure the Zitadel client exists. Idempotency anchor is
	// status.ClientID — if set, skip creation and proceed to secret
	// materialisation.
	if oc.Status.ClientID == "" {
		appID, clientID, clientSecret, err := zc.CreateOIDCClient(ctx, zitadel.CreateOIDCClientRequest{
			ProjectID:              projectID,
			Name:                   oc.Spec.ClientName,
			ApplicationType:        string(oc.Spec.ApplicationType),
			RedirectURIs:           oc.Spec.RedirectURIs,
			PostLogoutRedirectURIs: oc.Spec.PostLogoutRedirectURIs,
			GrantTypes:             toStringSlice(oc.Spec.GrantTypes),
			ResponseTypes:          toStringSliceResp(oc.Spec.ResponseTypes),
			AccessTokenLifetime:    accessTokenLifetimeString(oc.Spec.AccessTokenLifetimeSeconds),
		})
		if err != nil {
			return r.handleTransientOrPermanent(ctx, &oc, "CreateOIDCClient", err, logger)
		}
		// Persist BOTH ids to status BEFORE writing the K8s Secret.
		// AppID drives management-API URL paths (RotateClientSecret,
		// DeleteOIDCClient). ClientID is the OAuth client_id every
		// downstream consumer needs. They are NOT the same Zitadel
		// value — losing the distinction caused the
		// invalid_request/Errors.App.NotFound regression on browser
		// login that motivated this refactor.
		oc.Status.ClientID = clientID
		oc.Status.AppID = appID
		r.setCondition(&oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionTrue,
			"Created", "Zitadel client minted")
		if err := r.statusUpdate(ctx, &oc); err != nil {
			return ctrl.Result{}, fmt.Errorf("persist clientID to status: %w", err)
		}
		// Continue with the secret we just received. If clientSecret is
		// empty (idempotent 409 path returned existing app), we'll
		// rotate below to mint a fresh secret. Note: rotate takes appID.
		if clientSecret == "" {
			rotated, rerr := zc.RotateClientSecret(ctx, projectID, appID)
			if rerr != nil {
				return r.handleTransientOrPermanent(ctx, &oc, "RotateClientSecret", rerr, logger)
			}
			clientSecret = rotated
		}
		if err := r.writeSecret(ctx, &oc, clientID, clientSecret); err != nil {
			return ctrl.Result{}, err
		}
		r.setCondition(&oc, gibsonv1alpha1.ConditionOIDCSecretMaterialised, metav1.ConditionTrue,
			"SecretWritten",
			fmt.Sprintf("K8s Secret %s populated", oc.Spec.SecretRef.Name))
		r.setCondition(&oc, gibsonv1alpha1.ConditionReady, metav1.ConditionTrue,
			"AllStepsComplete", "OIDCClient is reconciled")
		oc.Status.ObservedGeneration = oc.Generation
		if err := r.statusUpdate(ctx, &oc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Crash-recovery: status.ClientID is set. Verify Zitadel still has
	// the client; ensure the K8s Secret exists. AppID is what hits the
	// management URL — older CRs from before the AppID/ClientID split
	// persisted only ClientID, so fall back to a NAME-based lookup
	// (clientName is in the spec) which returns both fields.
	appID := oc.Status.AppID
	if appID == "" {
		found, lerr := zc.GetOIDCClientByName(ctx, projectID, oc.Spec.ClientName)
		if lerr == nil && found != nil {
			appID = found.AppID
			oc.Status.AppID = appID
			// Also resync ClientID — if the old status held the WRONG value
			// (the App ID instead of the OAuth client_id, a regression
			// possible before the fix), correct it now.
			if found.ClientID != "" {
				oc.Status.ClientID = found.ClientID
			}
			_ = r.statusUpdate(ctx, &oc)
		}
	}
	existing, err := zc.GetOIDCClient(ctx, projectID, appID)
	if err != nil {
		if zitadel.IsNotFound(err) {
			// Drift: someone deleted the Zitadel app out-of-band. Clear
			// status and re-create on the next reconcile.
			logger.Info("Zitadel client missing; clearing status to recreate",
				"clientID", oc.Status.ClientID, "appID", appID)
			oc.Status.ClientID = ""
			oc.Status.AppID = ""
			r.setCondition(&oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionFalse,
				"RecreatingAfterDrift", "Zitadel client missing; will recreate")
			if uerr := r.statusUpdate(ctx, &oc); uerr != nil {
				return ctrl.Result{}, uerr
			}
			return ctrl.Result{Requeue: true}, nil
		}
		return r.handleTransientOrPermanent(ctx, &oc, "GetOIDCClient", err, logger)
	}
	_ = existing

	return r.reconcileSteadyState(ctx, &oc, zc, projectID, appID, logger)
}

// reconcileSteadyState handles the path where the Zitadel client already
// exists. It guarantees the K8s Secret is present AND that the stored
// client_secret still authenticates against Zitadel. On any mismatch
// (Secret missing, or introspection returns invalid_client) the path
// rotates the secret server-side and rewrites the K8s Secret so Zitadel
// and K8s stay in lockstep.
//
// Without the introspection step, an out-of-band secret rotation (manual
// admin action, a prior reconcile's RotateClientSecret followed by a
// partial Secret write, an alias-key staleness bug, …) silently leaves
// the K8s Secret distrusted by Zitadel and every consumer that mounts
// the Secret receives "invalid_client / invalid secret" on token
// exchange. See zeroroot-ai/platform-operator#22.
func (r *OIDCClientReconciler) reconcileSteadyState(
	ctx context.Context,
	oc *gibsonv1alpha1.OIDCClient,
	zc zitadel.Client,
	projectID, appID string,
	logger logr.Logger,
) (ctrl.Result, error) {
	// Ensure the Zitadel app issues JWT access tokens (not opaque
	// bearer). Envoy's jwt_authn filter rejects opaque tokens with
	// "Jwt is not in the form of Header.Payload.Signature" and every
	// authenticated daemon call routed through Envoy breaks silently.
	// Idempotent: a no-op when the app is already JWT.
	// See zeroroot-ai/platform-operator#23.
	if changed, terr := zc.EnsureJWTAccessToken(ctx, projectID, appID); terr != nil {
		// Transient/permanent surfaced like any other Zitadel error.
		return r.handleTransientOrPermanent(ctx, oc, "EnsureJWTAccessToken", terr, logger)
	} else if changed {
		logger.Info("patched Zitadel OIDC app to ACCESS_TOKEN_TYPE_JWT", "appID", appID)
	}

	exists, err := r.secretExists(ctx, oc)
	if err != nil {
		return ctrl.Result{}, err
	}

	if exists {
		// Verify the K8s Secret's client_secret still authenticates
		// against Zitadel. If it does, we're done (Ready=True). If it's
		// been rotated out from under us, fall through to mint + rewrite.
		liveSecret, rerr := r.readClientSecretFromK8s(ctx, oc)
		if rerr != nil {
			return ctrl.Result{}, rerr
		}
		ok, verr := zc.VerifyClientSecret(ctx, oc.Spec.ZitadelIssuer, oc.Status.ClientID, liveSecret)
		if verr != nil {
			// Verification error is unknown (transport/TLS). Don't rotate
			// blindly — leave the Secret alone and surface the issue so a
			// genuinely-good credential isn't churned away on a flaky
			// network. Next reconcile will retry.
			logger.Info("VerifyClientSecret unknown; leaving Secret unchanged",
				"err", verr.Error())
			return r.markReady(ctx, oc, "SecretExists",
				fmt.Sprintf("K8s Secret %s present (verification skipped: %v)",
					oc.Spec.SecretRef.Name, verr))
		}
		if ok {
			return r.markReady(ctx, oc, "SecretExists",
				fmt.Sprintf("K8s Secret %s present and validated against Zitadel",
					oc.Spec.SecretRef.Name))
		}
		logger.Info("K8s Secret client_secret rejected by Zitadel; rotating",
			"clientID", oc.Status.ClientID, "appID", appID)
		// fall through to rotate
	}

	// Either Secret was missing OR Zitadel rejected the stored secret.
	// Rotate server-side and rewrite the K8s Secret. RotateClientSecret
	// hits the management URL keyed on appID (NOT clientID).
	newSecret, err := zc.RotateClientSecret(ctx, projectID, appID)
	if err != nil {
		return r.handleTransientOrPermanent(ctx, oc, "RotateClientSecret", err, logger)
	}
	if err := r.writeSecret(ctx, oc, oc.Status.ClientID, newSecret); err != nil {
		return ctrl.Result{}, err
	}
	reason := "SecretRotated"
	message := fmt.Sprintf("K8s Secret %s repopulated via secret rotation", oc.Spec.SecretRef.Name)
	if exists {
		message = fmt.Sprintf("K8s Secret %s rotated after Zitadel rejected the stored secret",
			oc.Spec.SecretRef.Name)
	}
	r.setCondition(oc, gibsonv1alpha1.ConditionOIDCSecretMaterialised, metav1.ConditionTrue,
		reason, message)
	return r.markReady(ctx, oc, "AllStepsComplete", "OIDCClient is reconciled")
}

// markReady sets the Ready and ObservedGeneration fields and persists.
func (r *OIDCClientReconciler) markReady(
	ctx context.Context,
	oc *gibsonv1alpha1.OIDCClient,
	reason, message string,
) (ctrl.Result, error) {
	r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionTrue, reason, message)
	if reason == "SecretExists" {
		r.setCondition(oc, gibsonv1alpha1.ConditionOIDCSecretMaterialised,
			metav1.ConditionTrue, reason, message)
	}
	oc.Status.ObservedGeneration = oc.Generation
	if err := r.statusUpdate(ctx, oc); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// readClientSecretFromK8s reads the live client_secret value out of the
// materialised Secret. Returns the value at spec.secretRef.Key (the
// canonical lowercase shape the controller writes), which by contract
// matches ZITADEL_CLIENT_SECRET after this controller's writeOIDCAliases
// fix (zeroroot-ai/platform-operator#22).
func (r *OIDCClientReconciler) readClientSecretFromK8s(
	ctx context.Context,
	oc *gibsonv1alpha1.OIDCClient,
) (string, error) {
	ns := secretNamespace(oc.Spec.SecretRef, oc.Namespace)
	var sec corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Name: oc.Spec.SecretRef.Name, Namespace: ns}, &sec); err != nil {
		return "", fmt.Errorf("readClientSecretFromK8s: %w", err)
	}
	val, ok := sec.Data[oc.Spec.SecretRef.Key]
	if !ok || len(val) == 0 {
		return "", fmt.Errorf("readClientSecretFromK8s: key %q missing or empty in Secret %s/%s",
			oc.Spec.SecretRef.Key, ns, oc.Spec.SecretRef.Name)
	}
	return string(val), nil
}

// reconcileMachineUser is the MACHINE_USER applicationType branch.
//
// State machine:
//  1. EnsureMachineUser(clientName)   → userID (idempotent; 409 → lookup)
//  2. status.ClientID = userID, persist
//  3. AddIAMMember(userID, IAM_OWNER) → grants admin access (idempotent)
//  4. AddMachineUserClientSecret(userID) → {clientID, clientSecret}
//     where clientID is the user's loginName, NOT the userID.
//  5. writeSecret(clientID, clientSecret) → idp-admin-credentials
//  6. Conditions: ClientExists=True, SecretMaterialised=True, Ready=True
//
// Idempotency anchor is status.ClientID — when set, the next reconcile
// skips the create call and only rotates the secret if the K8s Secret
// is missing. Same shape as the OIDC-app branch.
func (r *OIDCClientReconciler) reconcileMachineUser(
	ctx context.Context, oc *gibsonv1alpha1.OIDCClient, zc zitadel.Client, logger logr.Logger,
) (ctrl.Result, error) {
	// Resolve project + org IDs up front — the daemon's IDP admin
	// client needs both keys in the Secret, not just client_id +
	// client_secret. Resolving here keeps the success path single-pass.
	projectID, err := zc.GetProjectIDByName(ctx, oc.Spec.ProjectRef.Name)
	if err != nil {
		if zitadel.IsNotFound(err) {
			r.setCondition(oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionFalse,
				"WaitingForProject",
				fmt.Sprintf("Zitadel project %q not found", oc.Spec.ProjectRef.Name))
			r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionFalse,
				"WaitingForProject", "Parent project does not exist yet")
			if uerr := r.statusUpdate(ctx, oc); uerr != nil {
				return ctrl.Result{}, uerr
			}
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		return r.handleTransientOrPermanent(ctx, oc, "GetProjectIDByName", err, logger)
	}
	orgID, err := zc.GetOrgIDForProject(ctx, projectID)
	if err != nil {
		return r.handleTransientOrPermanent(ctx, oc, "GetOrgIDForProject", err, logger)
	}

	// Step 1: ensure the machine user exists.
	if oc.Status.ClientID == "" {
		userID, err := zc.EnsureMachineUser(ctx, oc.Spec.ClientName)
		if err != nil {
			return r.handleTransientOrPermanent(ctx, oc, "EnsureMachineUser", err, logger)
		}
		oc.Status.ClientID = userID
		r.setCondition(oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionTrue,
			"MachineUserCreated", fmt.Sprintf("Zitadel machine user %q exists (userID=%s)", oc.Spec.ClientName, userID))
		if err := r.statusUpdate(ctx, oc); err != nil {
			return ctrl.Result{}, fmt.Errorf("persist machine userID: %w", err)
		}
		// Step 2a: enforce JWT token type. EnsureMachineUser already creates
		// the user with ACCESS_TOKEN_TYPE_JWT, but calling this here makes the
		// intent idempotent-visible and handles any pre-existing BEARER user
		// recovered via the 409 conflict path inside EnsureMachineUser.
		// See zeroroot-ai/platform-operator#65.
		if changed, terr := zc.EnsureMachineUserJWTAccessToken(ctx, userID, oc.Spec.ClientName); terr != nil {
			return r.handleTransientOrPermanent(ctx, oc, "EnsureMachineUserJWTAccessToken", terr, logger)
		} else if changed {
			logger.Info("patched Zitadel machine user to ACCESS_TOKEN_TYPE_JWT", "userID", userID)
		}
		// Step 3: grant the machine user's roles (idempotent). The daemon's
		// admin API calls require IAM_OWNER; signup-style bots need narrower
		// roles (e.g. IAM_USER_MANAGER + IAM_LOGIN_CLIENT) and may also need
		// org-scoped roles (ORG_OWNER). grantMachineUserRoles classifies each
		// role by prefix and routes IAM vs org grants. Fold into the create
		// path so the reconciler guarantees roles on first run.
		if result, gerr := r.grantMachineUserRoles(ctx, oc, zc, userID, orgID, logger); gerr != nil || !result.IsZero() {
			return result, gerr
		}
		// Step 4: mint the client-credentials secret. This regenerates
		// the secret each time, which is fine on first run; subsequent
		// reconciles short-circuit via the status.ClientID anchor.
		clientID, clientSecret, err := zc.AddMachineUserClientSecret(ctx, userID)
		if err != nil {
			return r.handleTransientOrPermanent(ctx, oc, "AddMachineUserClientSecret", err, logger)
		}
		// Step 5: write the K8s Secret with the full key set.
		if err := r.writeMachineUserSecret(ctx, oc, clientID, clientSecret, oc.Spec.ZitadelIssuer, orgID, projectID); err != nil {
			return ctrl.Result{}, err
		}
		r.setCondition(oc, gibsonv1alpha1.ConditionOIDCSecretMaterialised, metav1.ConditionTrue,
			"SecretWritten", fmt.Sprintf("K8s Secret %s populated", oc.Spec.SecretRef.Name))
		r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionTrue,
			"AllStepsComplete", "OIDCClient (machine user) is reconciled")
		oc.Status.ObservedGeneration = oc.Generation
		if err := r.statusUpdate(ctx, oc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Crash-recovery: status.ClientID is set. Always enforce JWT token type
	// here so that machine users created by older controller versions (which
	// wrote ACCESS_TOKEN_TYPE_BEARER) are silently upgraded on the next
	// reconcile. Idempotent: returns false without a PUT when already JWT.
	// See zeroroot-ai/platform-operator#65.
	if changed, terr := zc.EnsureMachineUserJWTAccessToken(ctx, oc.Status.ClientID, oc.Spec.ClientName); terr != nil {
		return r.handleTransientOrPermanent(ctx, oc, "EnsureMachineUserJWTAccessToken", terr, logger)
	} else if changed {
		logger.Info("patched existing Zitadel machine user to ACCESS_TOKEN_TYPE_JWT",
			"userID", oc.Status.ClientID)
	}

	// Re-grant roles on every reconcile (idempotent) so role-set drift is
	// reconciled — e.g. adding IAM_LOGIN_CLIENT to a bot that was
	// bootstrapped with only IAM_USER_MANAGER. Mirrors the prior
	// signup-bot-pat-minter Job's "always reconcile the role grant" step.
	if result, gerr := r.grantMachineUserRoles(ctx, oc, zc, oc.Status.ClientID, orgID, logger); gerr != nil || !result.IsZero() {
		return result, gerr
	}

	// Verify the K8s Secret has all 5 keys (issuer/org_id/project_id may
	// have been missing on a prior reconcile that ran older code). If
	// anything's missing, rotate the secret and re-write with the full key set.
	complete, err := r.machineUserSecretComplete(ctx, oc)
	if err != nil {
		return ctrl.Result{}, err
	}
	if complete {
		r.setCondition(oc, gibsonv1alpha1.ConditionOIDCSecretMaterialised, metav1.ConditionTrue,
			"SecretExists", fmt.Sprintf("K8s Secret %s present", oc.Spec.SecretRef.Name))
		r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionTrue,
			"AllStepsComplete", "OIDCClient (machine user) is reconciled")
		oc.Status.ObservedGeneration = oc.Generation
		if err := r.statusUpdate(ctx, oc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Secret missing or incomplete — re-mint client_secret (Zitadel's
	// PUT semantics regenerate it) and write the full key set.
	clientID, clientSecret, err := zc.AddMachineUserClientSecret(ctx, oc.Status.ClientID)
	if err != nil {
		return r.handleTransientOrPermanent(ctx, oc, "AddMachineUserClientSecret", err, logger)
	}
	if err := r.writeMachineUserSecret(ctx, oc, clientID, clientSecret, oc.Spec.ZitadelIssuer, orgID, projectID); err != nil {
		return ctrl.Result{}, err
	}
	r.setCondition(oc, gibsonv1alpha1.ConditionOIDCSecretMaterialised, metav1.ConditionTrue,
		"SecretRotated", fmt.Sprintf("K8s Secret %s repopulated via secret rotation", oc.Spec.SecretRef.Name))
	r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionTrue,
		"AllStepsComplete", "OIDCClient (machine user) is reconciled")
	oc.Status.ObservedGeneration = oc.Generation
	if err := r.statusUpdate(ctx, oc); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// grantMachineUserRoles grants the machine user the roles declared on
// spec.roles, classifying each by prefix:
//
//   - IAM_-prefixed roles (IAM_OWNER, IAM_USER_MANAGER, IAM_LOGIN_CLIENT, …)
//     → instance-scoped IAM members via AddIAMMember.
//   - ORG_-prefixed roles (ORG_OWNER, …) → org-scoped members on the
//     project's owning org via AddOrgMember.
//
// When spec.roles is empty the machine user is granted ["IAM_OWNER"], the
// historic default the daemon's IDP admin client relies on. Both client
// calls are idempotent (409 → PUT merge), so this is safe to invoke on
// every reconcile. Returns a non-zero Result / error only when a Zitadel
// call needs the transient/permanent handling path.
func (r *OIDCClientReconciler) grantMachineUserRoles(
	ctx context.Context,
	oc *gibsonv1alpha1.OIDCClient,
	zc zitadel.Client,
	userID, orgID string,
	logger logr.Logger,
) (ctrl.Result, error) {
	iamRoles, orgRoles := classifyMachineUserRoles(oc.Spec.Roles)

	if len(iamRoles) > 0 {
		if err := zc.AddIAMMember(ctx, userID, iamRoles); err != nil {
			return r.handleTransientOrPermanent(ctx, oc, "AddIAMMember", err, logger)
		}
		logger.V(1).Info("granted IAM roles to machine user", "userID", userID, "roles", iamRoles)
	}
	if len(orgRoles) > 0 {
		if err := zc.AddOrgMember(ctx, orgID, userID, orgRoles); err != nil {
			return r.handleTransientOrPermanent(ctx, oc, "AddOrgMember", err, logger)
		}
		logger.V(1).Info("granted org roles to machine user", "userID", userID, "orgID", orgID, "roles", orgRoles)
	}
	return ctrl.Result{}, nil
}

// classifyMachineUserRoles splits a role list into IAM (instance-scoped)
// and org-scoped role sets by prefix. An empty input defaults to a single
// IAM_OWNER grant. Roles that match neither prefix are conservatively
// treated as IAM roles so a typo or a future role family still lands
// somewhere visible rather than being silently dropped.
func classifyMachineUserRoles(roles []string) (iam, org []string) {
	if len(roles) == 0 {
		return []string{"IAM_OWNER"}, nil
	}
	for _, role := range roles {
		switch {
		case strings.HasPrefix(role, "ORG_"):
			org = append(org, role)
		default:
			iam = append(iam, role)
		}
	}
	return iam, org
}

// machineUserSecretComplete returns true iff the K8s Secret exists AND
// has the full 5-key set (client_id, client_secret, issuer, org_id,
// project_id). Used by the crash-recovery path so older 2-key Secrets
// trigger a re-write.
func (r *OIDCClientReconciler) machineUserSecretComplete(ctx context.Context, oc *gibsonv1alpha1.OIDCClient) (bool, error) {
	ns := secretNamespace(oc.Spec.SecretRef, oc.Namespace)
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: oc.Spec.SecretRef.Name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, k := range []string{"client_id", oc.Spec.SecretRef.Key, "issuer", "org_id", "project_id"} {
		if len(sec.Data[k]) == 0 {
			return false, nil
		}
	}
	return true, nil
}

func (r *OIDCClientReconciler) reconcileDeletion(ctx context.Context, oc *gibsonv1alpha1.OIDCClient) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("oidcclient", client.ObjectKeyFromObject(oc))

	if !controllerutil.ContainsFinalizer(oc, oidcClientFinalizer) {
		return ctrl.Result{}, nil
	}

	// Best-effort Zitadel cleanup, bounded by retries on transient errors.
	// MACHINE_USER deletion path: leave the Zitadel machine user behind.
	// The Zitadel machine-user/iam-member lifecycle is orthogonal to the
	// OIDCClient CR (operators may want to keep the user across CR
	// replacements). Standard OIDC-app deletion proceeds below.
	if oc.Spec.ApplicationType == gibsonv1alpha1.OIDCAppTypeMachineUser {
		controllerutil.RemoveFinalizer(oc, oidcClientFinalizer)
		if err := r.Update(ctx, oc); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer (machine user): %w", err)
		}
		return ctrl.Result{}, nil
	}
	if oc.Status.ClientID != "" {
		pat, ok, err := r.readSecretKey(ctx, oc.Namespace, oc.Spec.AdminTokenRef)
		if err == nil && ok {
			zc := r.ZitadelFactory(oc.Spec.ZitadelIssuer, pat)
			projectID, perr := zc.GetProjectIDByName(ctx, oc.Spec.ProjectRef.Name)
			if perr == nil {
				// DeleteOIDCClient takes the management-API app id, NOT
				// the OAuth client_id. Fall back to a name-lookup for
				// older CRs that never persisted AppID.
				appID := oc.Status.AppID
				if appID == "" {
					if found, lerr := zc.GetOIDCClientByName(ctx, projectID, oc.Spec.ClientName); lerr == nil && found != nil {
						appID = found.AppID
					}
				}
				if appID == "" {
					// Nothing to delete (drift cleanup path).
					return ctrl.Result{}, nil
				}
				if derr := zc.DeleteOIDCClient(ctx, projectID, appID); derr != nil {
					// Transient errors at deletion time: cap retries at 3,
					// then proceed (don't block deletion indefinitely).
					retries := transientRetriesFromAnnotation(oc)
					if retries < 3 && !zitadel.IsPermanent(derr) {
						setTransientRetryAnnotation(oc, retries+1)
						if uerr := r.Update(ctx, oc); uerr != nil {
							return ctrl.Result{}, uerr
						}
						logger.Info("Zitadel deletion transient error; retrying",
							"retry", retries+1, "err", derr.Error())
						return ctrl.Result{RequeueAfter: requeueShort}, nil
					}
					if r.Recorder != nil {
						r.Recorder.Eventf(oc, corev1.EventTypeWarning,
							"ZitadelDeleteFailed",
							"Failed to revoke Zitadel client %s after retries: %v",
							oc.Status.ClientID, derr)
					}
					logger.Info("Zitadel deletion gave up after 3 retries; proceeding with K8s GC",
						"clientID", oc.Status.ClientID, "err", derr.Error())
				}
			} else {
				logger.Info("project lookup failed during deletion; skipping Zitadel cleanup",
					"err", perr.Error())
			}
		} else {
			logger.Info("admin token unavailable during deletion; skipping Zitadel cleanup")
		}
	}

	controllerutil.RemoveFinalizer(oc, oidcClientFinalizer)
	if err := r.Update(ctx, oc); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// handleTransientOrPermanent classifies a Zitadel client error and sets
// the appropriate status condition + requeue policy.
func (r *OIDCClientReconciler) handleTransientOrPermanent(
	ctx context.Context, oc *gibsonv1alpha1.OIDCClient, op string, err error, logger logr.Logger,
) (ctrl.Result, error) {
	if zitadel.IsPermanent(err) {
		r.setCondition(oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionFalse,
			"ZitadelPermanentError",
			fmt.Sprintf("%s: %v", op, err))
		r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionFalse,
			"ZitadelPermanentError", "permanent failure — investigate and update spec")
		oc.Status.ObservedGeneration = oc.Generation
		if uerr := r.statusUpdate(ctx, oc); uerr != nil {
			return ctrl.Result{}, uerr
		}
		// No requeue on permanent errors.
		return ctrl.Result{}, nil
	}
	// Transient: requeue with backoff. Use the medium tier — controller-
	// runtime applies its own backoff curve on top.
	r.setCondition(oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionUnknown,
		"ZitadelTransientError",
		fmt.Sprintf("%s: %v", op, err))
	r.setCondition(oc, gibsonv1alpha1.ConditionReady, metav1.ConditionFalse,
		"ZitadelTransientError", "transient — retrying")
	if uerr := r.statusUpdate(ctx, oc); uerr != nil {
		return ctrl.Result{}, uerr
	}
	logger.Info("transient Zitadel error", "op", op, "err", err.Error())
	return ctrl.Result{RequeueAfter: requeueMedium}, nil
}

// writeMachineUserSecret creates/updates the K8s Secret with the full
// set of keys the daemon's IDP admin client expects: client_id,
// client_secret, issuer, org_id, project_id. Without all 5 the daemon
// either crash-loops at startup ("oauth2: invalid_client") or no-ops
// silently on admin RPCs ("Zitadel admin client init failed: empty
// org_id").
func (r *OIDCClientReconciler) writeMachineUserSecret(
	ctx context.Context, oc *gibsonv1alpha1.OIDCClient,
	clientID, clientSecret, issuer, orgID, projectID string,
) error {
	ns := secretNamespace(oc.Spec.SecretRef, oc.Namespace)
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: oc.Spec.SecretRef.Name, Namespace: ns}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sec, func() error {
		if err := controllerutil.SetControllerReference(oc, sec, r.Scheme); err != nil {
			return err
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data["client_id"] = []byte(clientID)
		sec.Data[oc.Spec.SecretRef.Key] = []byte(clientSecret)
		sec.Data["issuer"] = []byte(issuer)
		sec.Data["org_id"] = []byte(orgID)
		sec.Data["project_id"] = []byte(projectID)
		// Aliases for consumer deployments that reference the screaming-snake
		// form via secretKeyRef.key. Some deployments (gibson-tenant-operator,
		// gibson-dashboard, gibson-ext-authz) specify
		// ZITADEL_CLIENT_ID / ZITADEL_CLIENT_SECRET; emitting both shapes
		// keeps either era of consumer working without per-CR configuration.
		writeOIDCAliases(sec.Data, clientID, clientSecret)
		sec.Type = corev1.SecretTypeOpaque
		return nil
	})
	if err != nil {
		return fmt.Errorf("CreateOrUpdate machine-user Secret %s/%s: %w", ns, oc.Spec.SecretRef.Name, err)
	}
	return nil
}

// writeSecret creates or updates the K8s Secret named in spec.secretRef
// with the clientID + clientSecret, owner-referenced to the OIDCClient.
func (r *OIDCClientReconciler) writeSecret(ctx context.Context, oc *gibsonv1alpha1.OIDCClient, clientID, clientSecret string) error {
	ns := secretNamespace(oc.Spec.SecretRef, oc.Namespace)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      oc.Spec.SecretRef.Name,
			Namespace: ns,
		},
	}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, sec, func() error {
		if err := controllerutil.SetControllerReference(oc, sec, r.Scheme); err != nil {
			return err
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data["client_id"] = []byte(clientID)
		sec.Data[oc.Spec.SecretRef.Key] = []byte(clientSecret)
		writeOIDCAliases(sec.Data, clientID, clientSecret)
		sec.Type = corev1.SecretTypeOpaque
		return nil
	})
	if err != nil {
		return fmt.Errorf("CreateOrUpdate Secret %s/%s: %w", ns, oc.Spec.SecretRef.Name, err)
	}
	_ = op
	return nil
}

// writeOIDCAliases populates the canonical alternate key shapes for the
// client id and client secret on the materialised Secret. Consumer
// deployments inconsistently reference the credentials via either
// `client_id`/`client_secret` (snake_case, the controller's historical
// output) or `ZITADEL_CLIENT_ID`/`ZITADEL_CLIENT_SECRET` (screaming-snake,
// the chart-side convention picked up by some Helm-managed deployments).
// Writing both shapes makes the Secret consumer-agnostic so callers can
// pick either era without per-CR configuration.
//
// Every call OVERWRITES both alias keys — never the "write only if
// missing" pattern. A writeSecret call is by definition "this is the
// current truth from Zitadel"; preserving older values silently leaves
// the upper-case alias stale across rotations (the
// invalid_client/invalid_secret regression on dashboard sign-in that
// motivated this fix — zeroroot-ai/platform-operator#22).
func writeOIDCAliases(data map[string][]byte, clientID, clientSecret string) {
	data["ZITADEL_CLIENT_ID"] = []byte(clientID)
	data["ZITADEL_CLIENT_SECRET"] = []byte(clientSecret)
}

// secretExists checks for the K8s Secret named in spec.secretRef.
func (r *OIDCClientReconciler) secretExists(ctx context.Context, oc *gibsonv1alpha1.OIDCClient) (bool, error) {
	ns := secretNamespace(oc.Spec.SecretRef, oc.Namespace)
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: oc.Spec.SecretRef.Name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// readSecretKey reads spec.adminTokenRef from the cluster. Returns
// (value, true, nil) on success; (_, false, nil) if Secret or key
// missing; (_, _, err) on real errors.
func (r *OIDCClientReconciler) readSecretKey(ctx context.Context, fallbackNs string, ref gibsonv1alpha1.SecretKeyRef) (string, bool, error) {
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
	return string(v), true, nil
}

// setCondition writes a metav1.Condition onto the OIDCClient's status.
func (r *OIDCClientReconciler) setCondition(oc *gibsonv1alpha1.OIDCClient, t string, s metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i := range oc.Status.Conditions {
		c := &oc.Status.Conditions[i]
		if c.Type != t {
			continue
		}
		if c.Status == s && c.Reason == reason {
			c.Message = message
			c.ObservedGeneration = oc.Generation
			return
		}
		c.Status = s
		c.Reason = reason
		c.Message = message
		c.LastTransitionTime = now
		c.ObservedGeneration = oc.Generation
		return
	}
	oc.Status.Conditions = append(oc.Status.Conditions, metav1.Condition{
		Type:               t,
		Status:             s,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
		ObservedGeneration: oc.Generation,
	})
}

// statusUpdate writes status. Uses the status subresource.
func (r *OIDCClientReconciler) statusUpdate(ctx context.Context, oc *gibsonv1alpha1.OIDCClient) error {
	if err := r.Status().Update(ctx, oc); err != nil {
		return fmt.Errorf("status update: %w", err)
	}
	return nil
}

// secretNamespace returns ref.Namespace when set, fallback otherwise.
func secretNamespace(ref gibsonv1alpha1.SecretKeyRef, fallback string) string {
	if ref.Namespace != "" {
		return ref.Namespace
	}
	if fallback == "" {
		return "gibson"
	}
	return fallback
}

// toStringSlice converts the typed GrantType enum slice to plain strings
// for the Zitadel wire schema.
func toStringSlice(in []gibsonv1alpha1.OIDCGrantType) []string {
	out := make([]string, 0, len(in))
	for _, g := range in {
		out = append(out, string(g))
	}
	return out
}

// accessTokenLifetimeString renders the spec's seconds value as the Zitadel
// duration string the OIDC app config expects (e.g. 900 → "900s"). Returns ""
// when unset (0) so the instance default is left untouched.
func accessTokenLifetimeString(seconds int32) string {
	if seconds <= 0 {
		return ""
	}
	return fmt.Sprintf("%ds", seconds)
}

// toStringSliceResp is the same for ResponseType.
func toStringSliceResp(in []gibsonv1alpha1.OIDCResponseType) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r))
	}
	return out
}

const transientRetryAnnotation = "platform-operator.gibson.zeroroot.ai/deletion-retry"

func transientRetriesFromAnnotation(oc *gibsonv1alpha1.OIDCClient) int {
	if oc.Annotations == nil {
		return 0
	}
	v, ok := oc.Annotations[transientRetryAnnotation]
	if !ok {
		return 0
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func setTransientRetryAnnotation(oc *gibsonv1alpha1.OIDCClient, retries int) {
	if oc.Annotations == nil {
		oc.Annotations = map[string]string{}
	}
	oc.Annotations[transientRetryAnnotation] = fmt.Sprintf("%d", retries)
}
