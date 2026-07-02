// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	pg "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/postgres"
)

// fakePG implements pg.Client for testing.
type fakePG struct {
	owners       map[string]string // db → current owner
	alterCalls   []string          // "<db>:<owner>"
	grantCalls   []string          // "<db>:<role>"
	failOwnerErr error
	failGrantErr error
}

func (f *fakePG) Ping(ctx context.Context) error { return nil }

func (f *fakePG) EnsureDatabaseOwner(ctx context.Context, db, owner string) (bool, error) {
	if f.failOwnerErr != nil {
		return false, f.failOwnerErr
	}
	if f.owners == nil {
		f.owners = map[string]string{}
	}
	if f.owners[db] == owner {
		return false, nil
	}
	f.owners[db] = owner
	f.alterCalls = append(f.alterCalls, fmt.Sprintf("%s:%s", db, owner))
	return true, nil
}

func (f *fakePG) EnsurePublicSchemaGrants(ctx context.Context, db string, grants []string) error {
	if f.failGrantErr != nil {
		return f.failGrantErr
	}
	for _, r := range grants {
		f.grantCalls = append(f.grantCalls, fmt.Sprintf("%s:%s", db, r))
	}
	return nil
}

func (f *fakePG) Close() error { return nil }

func TestReconcilePostgresBundle_MissingSecret(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).Build()
	r := &PlatformBootstrapReconciler{
		Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8),
		PostgresFactory: func(ctx context.Context, cfg pg.Config) (pg.Client, error) {
			return &fakePG{}, nil
		},
	}
	pb := postgresBundleFixture()

	if _, err := r.reconcilePostgresBundle(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPostgresBundleReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "WaitingForSuperuserSecret" {
		t.Fatalf("expected WaitingForSuperuserSecret/False, got %+v", c)
	}
}

func TestReconcilePostgresBundle_AppliesOwnerAndGrants(t *testing.T) {
	s := mustScheme(t)
	suSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "platform-postgres-superuser"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"username": []byte("postgres"), "password": []byte("pw")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(suSec).Build()
	pgcli := &fakePG{}
	r := &PlatformBootstrapReconciler{
		Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8),
		PostgresFactory: func(ctx context.Context, cfg pg.Config) (pg.Client, error) {
			return pgcli, nil
		},
	}
	pb := postgresBundleFixture()

	if _, err := r.reconcilePostgresBundle(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPostgresBundleReady)
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "AllOwnershipApplied" {
		t.Fatalf("expected AllOwnershipApplied/True, got %+v", c)
	}
	if len(pgcli.alterCalls) != 2 {
		t.Fatalf("expected 2 ALTER calls, got %v", pgcli.alterCalls)
	}
	// zitadel db has 1 grant, openfga has 0 grants → 1 grant call total.
	if len(pgcli.grantCalls) != 1 || pgcli.grantCalls[0] != "zitadel:gibson-app" {
		t.Fatalf("expected zitadel:gibson-app grant only, got %v", pgcli.grantCalls)
	}
}

func TestReconcilePostgresBundle_PermissionDenied(t *testing.T) {
	s := mustScheme(t)
	suSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "platform-postgres-superuser"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"username": []byte("postgres"), "password": []byte("pw")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(suSec).Build()
	r := &PlatformBootstrapReconciler{
		Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8),
		PostgresFactory: func(ctx context.Context, cfg pg.Config) (pg.Client, error) {
			return &fakePG{failOwnerErr: fmt.Errorf("denied: %w", pg.ErrPermissionDeny)}, nil
		},
	}
	pb := postgresBundleFixture()

	if _, err := r.reconcilePostgresBundle(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPostgresBundleReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "PermissionDenied" {
		t.Fatalf("expected PermissionDenied/False, got %+v", c)
	}
}

func TestReconcilePostgresBundle_ClusterUnreachable(t *testing.T) {
	s := mustScheme(t)
	suSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "platform-postgres-superuser"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"username": []byte("postgres"), "password": []byte("pw")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(suSec).Build()
	r := &PlatformBootstrapReconciler{
		Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8),
		PostgresFactory: func(ctx context.Context, cfg pg.Config) (pg.Client, error) {
			return nil, fmt.Errorf("dial tcp: %w", pg.ErrUnreachable)
		},
	}
	pb := postgresBundleFixture()

	result, err := r.reconcilePostgresBundle(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Fatalf("expected requeue, got %+v", result)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPostgresBundleReady)
	if c == nil || c.Status != metav1.ConditionUnknown || c.Reason != "ClusterUnreachable" {
		t.Fatalf("expected ClusterUnreachable/Unknown, got %+v", c)
	}
}

// TestReconcilePostgresBundle_InvalidPassword_TriggersReload verifies the
// deploy#1043 self-heal: on 28P01 (role password diverged from the CNPG
// Secret), the operator bumps a reload annotation on the superuser Secret so
// CNPG re-applies the password to the role, sets SuperuserPasswordReconciling,
// and requeues.
func TestReconcilePostgresBundle_InvalidPassword_TriggersReload(t *testing.T) {
	s := mustScheme(t)
	suSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "platform-postgres-superuser"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"username": []byte("postgres"), "password": []byte("pw")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(suSec).Build()
	r := &PlatformBootstrapReconciler{
		Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8),
		PostgresFactory: func(ctx context.Context, cfg pg.Config) (pg.Client, error) {
			return nil, fmt.Errorf("ping: %w", pg.ErrInvalidPassword)
		},
	}
	pb := postgresBundleFixture()

	result, err := r.reconcilePostgresBundle(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Fatalf("expected requeue, got %+v", result)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPostgresBundleReady)
	if c == nil || c.Status != metav1.ConditionUnknown || c.Reason != "SuperuserPasswordReconciling" {
		t.Fatalf("expected SuperuserPasswordReconciling/Unknown, got %+v", c)
	}
	// The Secret must have been nudged (reload annotation added) so CNPG realigns.
	var got corev1.Secret
	if err := cli.Get(context.Background(), types.NamespacedName{Namespace: "gibson", Name: "platform-postgres-superuser"}, &got); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got.Annotations["gibson.zeroroot.ai/superuser-password-reload"] == "" {
		t.Fatalf("expected reload annotation on the superuser Secret, got %v", got.Annotations)
	}
}

// TestTrimSpaceOnSecretRead verifies the defensive TrimSpace at the
// readSecretKey boundary — the historical Zitadel chart bug wrote PATs
// with trailing newlines, and we never want to embed those in HTTP
// Authorization headers.
func TestTrimSpaceOnSecretRead(t *testing.T) {
	s := mustScheme(t)
	patSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "iam-admin-pat"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"pat": []byte("real-pat-value\n")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(patSec).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}

	v, ok, err := r.readSecretKey(context.Background(), "gibson", gibsonv1alpha1.SecretKeyRef{Name: "iam-admin-pat", Key: "pat"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if v != "real-pat-value" {
		t.Fatalf("expected trimmed value, got %q", v)
	}
}

// Ensure the test-only fake postgres client compiles against pg.Client.
var _ pg.Client = (*fakePG)(nil)

// Compile-time check that error sentinels work in our wrapping pattern.
var _ = func() error { return fmt.Errorf("wrap: %w", pg.ErrPermissionDeny) }
var _ = errors.Is // keep import if other tests change

// postgresBundleFixture returns a canonical PB with a postgres bundle for tests.
func postgresBundleFixture() *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			PostgresBundle: gibsonv1alpha1.PostgresBundleSpec{
				Cluster: gibsonv1alpha1.PostgresClusterRef{
					Host: "platform-postgres-rw.cnpg-system.svc",
					Port: 5432,
					SuperuserSecretRef: gibsonv1alpha1.SecretKeyRef{
						Name:      "platform-postgres-superuser",
						Namespace: "gibson",
						Key:       "password",
					},
				},
				Databases: []gibsonv1alpha1.DatabaseRoleOwnership{
					{Name: "zitadel", Owner: "zitadel-user", Grants: []string{"gibson-app"}},
					{Name: "openfga", Owner: "openfga-user"},
				},
			},
		},
	}
}
