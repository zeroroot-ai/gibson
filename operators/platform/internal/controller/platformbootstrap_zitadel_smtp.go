// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// smtpProviderDescription tags the one SMTP email provider this reconciler
// owns (hosted#189). FindSMTPEmailProviderByDescription uses it to recover
// the provider's id after a status wipe (CR recreation, a lost Secret store)
// without ever creating a second provider for the same mail settings.
const smtpProviderDescription = "gibson-platform-operator"

// errMissingSMTPPasswordSecretRef marks a spec.zitadel.smtp that names a
// userSecretRef with no passwordSecretRef — a permanent configuration
// error, not a "not ready yet" wait.
var errMissingSMTPPasswordSecretRef = errors.New("spec.zitadel.smtp.userSecretRef is set but passwordSecretRef is not")

// reconcileZitadelSMTP makes the Zitadel instance have exactly one active
// SMTP email provider matching spec.zitadel.smtp (hosted#189, ADR-0093
// decision 11). It is structural, not cosmetic like reconcileLoginBranding:
// every Zitadel-sent email — the Platform owner's setup link, a tenant
// Owner's setup link, invitations, an MFA reset routed through Zitadel — is
// silently undeliverable until this is correct, because Zitadel's own
// CreateInviteCode call succeeds and queues a notification even with no
// mail transport configured at all. DefaultInstance chart config only
// applies to a brand-new Zitadel instance, so an already-running instance
// (staging, measured 2026-09-27: zero SMTP providers configured) is
// corrected here, idempotently, on every reconcile.
//
// Follows the same transient/permanent convention as every other step in
// this file (e.g. reconcileZitadelProject): a transient Zitadel error
// requeues with backoff; a permanent one sets SMTPProviderReady=False and
// lets the reconcile continue to the remaining steps, picked up again on the
// next periodic resync.
func (r *PlatformBootstrapReconciler) reconcileZitadelSMTP(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	spec := pb.Spec.Zitadel.SMTP
	if spec == nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionTrue,
			"NotConfigured", "spec.zitadel.smtp not set; offline install (ADR-0093 decision 11)")
		return ctrl.Result{}, nil
	}

	pat, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.Zitadel.AdminTokenRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionFalse,
			"WaitingForAdminToken", "Zitadel admin token Secret not yet materialised")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	user, password, credsOK, err := r.resolveSMTPCredentials(ctx, spec)
	if err != nil {
		if errors.Is(err, errMissingSMTPPasswordSecretRef) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionFalse,
				"MissingPasswordSecretRef", err.Error())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !credsOK {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionFalse,
			"WaitingForCredentialsSecret", "SMTP credentials Secret not yet materialised")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	cfg := desiredSMTPProviderConfig(spec, user, password)
	hashHex := smtpSettingsHash(cfg)
	zc := r.ZitadelFactory(pb.Spec.Zitadel.Issuer, pat)

	lookup, resolveOK, result, err := r.resolveSMTPProvider(ctx, zc, pb)
	if !resolveOK {
		return result, err
	}
	id, state, found := lookup.id, lookup.state, lookup.found

	created := false
	switch {
	case !found:
		newID, aerr := zc.AddSMTPEmailProvider(ctx, cfg)
		if aerr != nil {
			return smtpZitadelErr(pb, "AddSMTPEmailProvider", aerr), nil
		}
		id = newID
		created = true
		logger.Info("created the Zitadel SMTP email provider", "id", id)
	case !state.Matches(cfg) || pb.Status.SMTPSettingsHash != hashHex:
		if uerr := zc.UpdateSMTPEmailProvider(ctx, id, cfg); uerr != nil {
			return smtpZitadelErr(pb, "UpdateSMTPEmailProvider", uerr), nil
		}
		logger.Info("corrected the Zitadel SMTP email provider settings", "id", id)
	}

	if created || !state.Active {
		if aerr := zc.ActivateEmailProvider(ctx, id); aerr != nil {
			return smtpZitadelErr(pb, "ActivateEmailProvider", aerr), nil
		}
		logger.Info("activated the Zitadel SMTP email provider", "id", id)
	}

	pb.Status.SMTPProviderID = id
	pb.Status.SMTPSettingsHash = hashHex
	setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionTrue,
		"ProviderActive", fmt.Sprintf("SMTP email provider %s active, sender %s", id, cfg.SenderAddress))
	return ctrl.Result{}, nil
}

// resolveSMTPCredentials reads spec.zitadel.smtp's optional credentials
// Secrets. ok=false with a nil error means "wait and retry" (a Secret
// referenced but not yet materialised); a non-nil error that is
// errMissingSMTPPasswordSecretRef means a permanent spec misconfiguration;
// any other non-nil error is a real Kubernetes API error the caller
// propagates unwrapped, matching readSecretKey's own contract.
func (r *PlatformBootstrapReconciler) resolveSMTPCredentials(ctx context.Context, spec *gibsonv1alpha1.ZitadelSMTPSpec) (user, password string, ok bool, err error) {
	if spec.UserSecretRef == nil {
		return "", "", true, nil
	}
	user, uok, err := r.readSecretKey(ctx, defaultChildNamespace, *spec.UserSecretRef)
	if err != nil {
		return "", "", false, err
	}
	if !uok {
		return "", "", false, nil
	}
	if spec.PasswordSecretRef == nil {
		return "", "", false, errMissingSMTPPasswordSecretRef
	}
	password, pok, err := r.readSecretKey(ctx, defaultChildNamespace, *spec.PasswordSecretRef)
	if err != nil {
		return "", "", false, err
	}
	if !pok {
		return "", "", false, nil
	}
	return user, password, true, nil
}

// desiredSMTPProviderConfig renders spec.zitadel.smtp (plus the resolved
// credentials) as the zitadel.SMTPProviderConfig the client's Add/Update
// calls expect. TLS defaults to true when unset — the CRD's
// +kubebuilder:default only applies through the API server's defaulting
// webhook path, never guaranteed for a CR built directly in a test or by an
// older client, so the zero-value (nil) case is handled explicitly here too.
func desiredSMTPProviderConfig(spec *gibsonv1alpha1.ZitadelSMTPSpec, user, password string) zitadel.SMTPProviderConfig {
	tls := true
	if spec.TLS != nil {
		tls = *spec.TLS
	}
	return zitadel.SMTPProviderConfig{
		SenderAddress: spec.FromAddress,
		SenderName:    spec.FromName,
		TLS:           tls,
		Host:          fmt.Sprintf("%s:%d", spec.Host, spec.Port),
		User:          user,
		Password:      password,
		Description:   smtpProviderDescription,
	}
}

// smtpSettingsHash hashes every field of cfg, including the password.
// Zitadel never returns a stored password on read, so this hash — not a
// live comparison — is the only way the reconciler can tell a password
// changed and needs re-applying.
func smtpSettingsHash(cfg zitadel.SMTPProviderConfig) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		cfg.SenderAddress, cfg.SenderName, strconv.FormatBool(cfg.TLS), cfg.Host, cfg.User, cfg.Password,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// smtpProviderLookup is resolveSMTPProvider's result: found reports whether
// an existing provider was located, in which case id and state are
// populated. A zero value (found=false, id="") means "no provider found by
// either path — create one," the genuinely-new-install case.
type smtpProviderLookup struct {
	id    string
	state zitadel.SMTPProviderState
	found bool
}

// resolveSMTPProvider finds the id + live state of the SMTP email provider
// this reconciler owns. It tries the persisted status.smtpProviderID first
// (the fast path on every steady-state reconcile), falling back to a
// description search — for a fresh install (id never persisted) or a status
// wiped by CR recreation — so a provider already applied is never re-created
// under a second id for the same mail settings.
//
// ok=false means the caller must return (result, err) immediately (a
// condition was already set on pb) — the same contract
// sendPlatformOwnerSetupLink documents in platformbootstrap_platformowner.go
// for the identical reason: a PERMANENT Zitadel error deliberately reports
// (ctrl.Result{}, nil) — no requeue — which is indistinguishable from
// "proceed" by result/err alone, so ok carries that meaning explicitly
// instead. ok=true's lookup is valid whether or not a provider was found.
func (r *PlatformBootstrapReconciler) resolveSMTPProvider(
	ctx context.Context,
	zc zitadel.EmailProviderClient,
	pb *gibsonv1alpha1.PlatformBootstrap,
) (lookup smtpProviderLookup, ok bool, result ctrl.Result, err error) {
	if id := pb.Status.SMTPProviderID; id != "" {
		st, gerr := zc.GetSMTPEmailProviderState(ctx, id)
		switch {
		case gerr == nil:
			return smtpProviderLookup{id: id, state: st, found: true}, true, ctrl.Result{}, nil
		case zitadel.IsNotFound(gerr):
			// Removed out from under the operator; fall through to the
			// description search below rather than recreate blindly.
		default:
			return smtpProviderLookup{}, false, smtpZitadelErr(pb, "GetSMTPEmailProviderState", gerr), nil
		}
	}

	foundID, ferr := zc.FindSMTPEmailProviderByDescription(ctx, smtpProviderDescription)
	switch {
	case ferr == nil:
		st, gerr := zc.GetSMTPEmailProviderState(ctx, foundID)
		if gerr != nil {
			return smtpProviderLookup{}, false, smtpZitadelErr(pb, "GetSMTPEmailProviderState", gerr), nil
		}
		return smtpProviderLookup{id: foundID, state: st, found: true}, true, ctrl.Result{}, nil
	case zitadel.IsNotFound(ferr):
		return smtpProviderLookup{}, true, ctrl.Result{}, nil
	default:
		return smtpProviderLookup{}, false, smtpZitadelErr(pb, "FindSMTPEmailProviderByDescription", ferr), nil
	}
}

// smtpZitadelErr classifies err (permanent vs transient, the convention
// every step in this package follows) and sets ConditionSMTPProviderReady
// accordingly, returning the ctrl.Result the caller returns immediately.
func smtpZitadelErr(pb *gibsonv1alpha1.PlatformBootstrap, op string, err error) ctrl.Result {
	if zitadel.IsPermanent(err) {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionFalse,
			"ZitadelPermanentError", fmt.Sprintf("%s: %v", op, err))
		return ctrl.Result{}
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionSMTPProviderReady, metav1.ConditionUnknown,
		"ZitadelTransientError", fmt.Sprintf("%s: %v", op, err))
	return ctrl.Result{RequeueAfter: requeueMedium}
}
