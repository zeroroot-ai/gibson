// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	pg "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/postgres"
)

// PostgresClientFactory builds a postgres admin client. Wired for test
// substitution.
type PostgresClientFactory func(ctx context.Context, cfg pg.Config) (pg.Client, error)

// reconcilePostgresBundle enforces per-database ownership + public-schema
// grants declared in spec.postgresBundle. Idempotent: only issues an
// ALTER when the current owner differs from desired. Postgres is structural
// infrastructure (ADR-0003 one-code-path) and the spec is CRD-required; no
// `PostgresBundleDisabled` skip path exists.
//
// Behavior:
//   - superuser Secret missing            → False, reason=WaitingForSuperuserSecret
//   - missing username/password in Secret → False, reason=MalformedSuperuserSecret
//   - connect / ping fails                → Unknown, reason=ClusterUnreachable, requeue
//   - permission denied on ALTER          → False, reason=PermissionDenied (permanent)
//   - any database lookup fails           → False, reason=DatabaseLookupFailed
//   - all entries reconciled              → True, reason=AllOwnershipApplied
func (r *PlatformBootstrapReconciler) reconcilePostgresBundle(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	bundle := pb.Spec.PostgresBundle

	// Read superuser Secret. CNPG layout: data.username + data.password.
	suSec, err := r.readSuperuserSecret(ctx, bundle.Cluster.SuperuserSecretRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
				"WaitingForSuperuserSecret", err.Error())
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		return ctrl.Result{}, err
	}
	username := strings.TrimSpace(string(suSec.Data["username"]))
	password := strings.TrimSpace(string(suSec.Data["password"]))
	if username == "" || password == "" {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
			"MalformedSuperuserSecret",
			fmt.Sprintf("Secret %s/%s missing username or password data key",
				suSec.Namespace, suSec.Name))
		return ctrl.Result{}, nil
	}

	cli, err := r.PostgresFactory(ctx, pg.Config{
		Host:     bundle.Cluster.Host,
		Port:     bundle.Cluster.Port,
		User:     username,
		Password: password,
		// Allow plain-text in-cluster; CNPG enforces it at the Service.
		SSLMode: "require",
	})
	if err != nil {
		// Try sslmode=disable in dev — some Kind/CNPG setups don't terminate TLS.
		if errors.Is(err, pg.ErrUnreachable) {
			cli, err = r.PostgresFactory(ctx, pg.Config{
				Host:     bundle.Cluster.Host,
				Port:     bundle.Cluster.Port,
				User:     username,
				Password: password,
				SSLMode:  "disable",
			})
		}
	}
	if err != nil {
		// deploy#1043: CNPG can leave the postgres role password diverged from
		// the superuser Secret at bootstrap. CNPG re-applies secret->role only
		// on a Secret change (cnpg.io/reload), not on role drift — so it never
		// self-corrects. On 28P01, nudge the Secret to trigger that reload; CNPG
		// realigns the role and the next requeue connects.
		if errors.Is(err, pg.ErrInvalidPassword) {
			if rerr := r.triggerSuperuserReload(ctx, suSec); rerr != nil {
				logger.Error(rerr, "failed to trigger CNPG superuser Secret reload",
					"secret", suSec.Namespace+"/"+suSec.Name)
			} else {
				logger.Info("postgres superuser password diverged from Secret; triggered CNPG reload to realign",
					"secret", suSec.Namespace+"/"+suSec.Name)
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionUnknown,
				"SuperuserPasswordReconciling",
				"postgres role password diverged from the CNPG superuser Secret; triggered a Secret reload so CNPG realigns the role, retrying")
			return ctrl.Result{RequeueAfter: requeueShort}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionUnknown,
			"ClusterUnreachable", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	defer func() { _ = cli.Close() }()

	var applied, alreadyOK int
	for _, entry := range bundle.Databases {
		changed, err := cli.EnsureDatabaseOwner(ctx, entry.Name, entry.Owner)
		if err != nil {
			if errors.Is(err, pg.ErrPermissionDeny) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
					"PermissionDenied",
					fmt.Sprintf("ALTER DATABASE %q OWNER TO %q: %v", entry.Name, entry.Owner, err))
				return ctrl.Result{}, nil
			}
			if errors.Is(err, pg.ErrInvalidIdent) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
					"InvalidIdentifier", err.Error())
				return ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
				"DatabaseLookupFailed", err.Error())
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		if changed {
			applied++
			logger.Info("ALTER DATABASE OWNER applied", "database", entry.Name, "owner", entry.Owner)
		} else {
			alreadyOK++
		}
		if err := cli.EnsurePublicSchemaGrants(ctx, entry.Name, entry.Grants); err != nil {
			if errors.Is(err, pg.ErrPermissionDeny) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
					"PermissionDenied",
					fmt.Sprintf("GRANT on schema public for db %q: %v", entry.Name, err))
				return ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionFalse,
				"GrantFailed", err.Error())
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionPostgresBundleReady, metav1.ConditionTrue,
		"AllOwnershipApplied",
		fmt.Sprintf("%d/%d databases reconciled (%d altered, %d already correct)",
			applied+alreadyOK, len(bundle.Databases), applied, alreadyOK))
	return ctrl.Result{}, nil
}

// readSuperuserSecret reads the CNPG superuser Secret and returns it.
// `ref.Key` is unused here — we always read both `username` and `password`
// data keys — but we honor ref.Name + ref.Namespace.
func (r *PlatformBootstrapReconciler) readSuperuserSecret(ctx context.Context, ref gibsonv1alpha1.SecretKeyRef) (*corev1.Secret, error) {
	ns := secretNamespace(ref, defaultChildNamespace)
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &sec); err != nil {
		return nil, err
	}
	return &sec, nil
}

// triggerSuperuserReload bumps an annotation on the CNPG superuser Secret so
// CNPG's cnpg.io/reload watch fires and re-applies the Secret's password to the
// postgres role. This is how CNPG realigns role<->Secret; it does not do so on
// role drift alone. The annotation value must change each call. deploy#1043.
func (r *PlatformBootstrapReconciler) triggerSuperuserReload(ctx context.Context, sec *corev1.Secret) error {
	patch := client.MergeFrom(sec.DeepCopy())
	if sec.Annotations == nil {
		sec.Annotations = map[string]string{}
	}
	sec.Annotations["gibson.zeroroot.ai/superuser-password-reload"] = time.Now().UTC().Format(time.RFC3339Nano)
	return r.Patch(ctx, sec, patch)
}

// DefaultPostgresClientFactory wires the real lib/pq client.
func DefaultPostgresClientFactory(ctx context.Context, cfg pg.Config) (pg.Client, error) {
	return pg.New(ctx, cfg)
}
