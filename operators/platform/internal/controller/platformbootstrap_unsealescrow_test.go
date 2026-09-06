// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// escrowFixture builds a reconciler plus a PlatformBootstrap pointing at
// `path`, optionally with an unseal Secret already minted.
func escrowFixture(t *testing.T, dest gibsonv1alpha1.UnsealEscrowDestination, path, mintedKey string) (*PlatformBootstrapReconciler, *gibsonv1alpha1.PlatformBootstrap) {
	t.Helper()
	s := mustScheme(t)
	b := fake.NewClientBuilder().WithScheme(s)
	if mintedKey != "" {
		b = b.WithObjects(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "gibson-openbao-unseal-keys", Namespace: "gibson"},
			Data:       map[string][]byte{"unsealKey": []byte(mintedKey)},
		})
	}
	cli := b.Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			UnsealEscrow: gibsonv1alpha1.UnsealEscrowSpec{
				Destination: dest,
				SourceSecret: &gibsonv1alpha1.SecretKeyRef{
					Name: "gibson-openbao-unseal-keys", Namespace: "gibson", Key: "unsealKey",
				},
			},
		},
	}
	if path != "" {
		pb.Spec.UnsealEscrow.Volume = &gibsonv1alpha1.UnsealEscrowVolumeSpec{Path: path}
	}
	return r, pb
}

func escrowCond(t *testing.T, pb *gibsonv1alpha1.PlatformBootstrap) *metav1.Condition {
	t.Helper()
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionUnsealKeyEscrowed)
	if c == nil {
		t.Fatal("UnsealKeyEscrowed condition was never set")
	}
	return c
}

// An install that declares no destination must NOT reach Ready, and the
// message has to name the field. Reaching Ready with the only copy of the
// unseal key in etcd is the failure this condition exists to prevent.
func TestUnsealEscrow_NoDestinationBlocksReady(t *testing.T) {
	r, pb := escrowFixture(t, "", "", "key-abc")
	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := escrowCond(t, pb)
	if c.Status != metav1.ConditionFalse || c.Reason != "EscrowNotConfigured" {
		t.Fatalf("got %s/%s, want False/EscrowNotConfigured", c.Status, c.Reason)
	}
	if !contains(c.Message, "spec.unsealEscrow.destination") {
		t.Errorf("message must name the field to set, got: %s", c.Message)
	}
}

// The verified-write path: file absent → written, read back, condition True.
func TestUnsealEscrow_WritesAndVerifies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "openbao-unseal.key")
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, path, "unseal-key-value")

	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := escrowCond(t, pb)
	if c.Status != metav1.ConditionTrue || c.Reason != "Escrowed" {
		t.Fatalf("got %s/%s (%s), want True/Escrowed", c.Status, c.Reason, c.Message)
	}
	got, err := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if err != nil {
		t.Fatalf("escrow file unreadable: %v", err)
	}
	if string(got) != "unseal-key-value" {
		t.Errorf("escrowed %q, want the minted key", string(got))
	}
	// The key itself must never appear in the condition message.
	if contains(c.Message, "unseal-key-value") {
		t.Errorf("condition message leaks the key: %s", c.Message)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("escrow file mode %v, want 0600", fi.Mode().Perm())
	}
}

// Re-reconciling with the same key is a no-op that stays Ready.
func TestUnsealEscrow_IdempotentOnSameKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := os.WriteFile(path, []byte("same-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, path, "same-key")
	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionTrue {
		t.Fatalf("got %s/%s, want True", c.Status, c.Reason)
	}
}

// THE ONE THAT MATTERS: a destination already holding a DIFFERENT key must not
// be overwritten. That file may be the only copy of another instance's unseal
// key, and clobbering it destroys the thing escrow exists to preserve.
func TestUnsealEscrow_RefusesToOverwriteDifferentKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := os.WriteFile(path, []byte("SOMEONE-ELSES-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, path, "our-new-key")

	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := escrowCond(t, pb)
	if c.Status != metav1.ConditionFalse || c.Reason != "EscrowConflict" {
		t.Fatalf("got %s/%s, want False/EscrowConflict", c.Status, c.Reason)
	}
	got, err := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SOMEONE-ELSES-KEY" {
		t.Fatalf("existing key was overwritten with %q — escrow destroyed the copy it exists to protect", string(got))
	}
}

// Before OpenBao bootstraps there is genuinely nothing to escrow: not an
// error, and not Ready.
func TestUnsealEscrow_WaitsForMintedKey(t *testing.T) {
	dir := t.TempDir()
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, filepath.Join(dir, "k"), "")
	res, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected a requeue while waiting for the key to be minted")
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionFalse || c.Reason != "UnsealKeyNotMinted" {
		t.Fatalf("got %s/%s, want False/UnsealKeyNotMinted", c.Status, c.Reason)
	}
}

// The kms seal source escrows to Secrets Manager itself and deletes the
// in-cluster copy, so there is nothing here to verify.
func TestUnsealEscrow_ManagedExternally(t *testing.T) {
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowManagedExternally, "", "")
	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "ManagedExternally" {
		t.Fatalf("got %s/%s, want True/ManagedExternally", c.Status, c.Reason)
	}
}

// destination=volume without a path is a config error, not a silent pass.
func TestUnsealEscrow_VolumeRequiresPath(t *testing.T) {
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, "", "key")
	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionFalse || c.Reason != "EscrowPathMissing" {
		t.Fatalf("got %s/%s, want False/EscrowPathMissing", c.Status, c.Reason)
	}
}

// An unrecognised destination is a config error, not a silent pass. Without
// this the enum could drift and escrow would quietly stop happening.
func TestUnsealEscrow_UnknownDestination(t *testing.T) {
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowDestination("s3"), "", "key")
	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionFalse || c.Reason != "EscrowDestinationInvalid" {
		t.Fatalf("got %s/%s, want False/EscrowDestinationInvalid", c.Status, c.Reason)
	}
}

// A write that cannot land must be reported and retried, NOT reported Ready.
// The directory exists and is readable but not writable, so ReadFile returns
// NotExist and the write then fails — the branch that matters.
func TestUnsealEscrow_WriteFailureIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny writes")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	// Restored so t.TempDir() can remove it: a directory needs write+execute
	// to be cleaned up, which 0600 does not give.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec // dir needs +x to be removable

	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, filepath.Join(locked, "k"), "key")
	res, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("a failed escrow must be retried")
	}
	c := escrowCond(t, pb)
	if c.Status != metav1.ConditionFalse || c.Reason != "EscrowWriteFailed" {
		t.Fatalf("got %s/%s (%s), want False/EscrowWriteFailed", c.Status, c.Reason, c.Message)
	}
}

// A destination that exists but cannot be read (here: it is a directory) must
// be reported, not treated as "absent" and overwritten.
func TestUnsealEscrow_UnreadableDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, path, "key")
	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := escrowCond(t, pb)
	if c.Status != metav1.ConditionFalse {
		t.Fatalf("got %s/%s, want False", c.Status, c.Reason)
	}
	if c.Reason != "EscrowUnreadable" && c.Reason != "EscrowWriteFailed" {
		t.Fatalf("got reason %s, want EscrowUnreadable or EscrowWriteFailed", c.Reason)
	}
}

// An operator who names only the Secret must still get escrow: the key and
// namespace fall back to what the sidecar actually writes. If these defaults
// drift, escrow silently reports UnsealKeyNotMinted forever on a cluster whose
// key exists.
func TestUnsealEscrow_SourceSecretDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, path, "defaulted-key")
	// Name only — no Key, no Namespace.
	pb.Spec.UnsealEscrow.SourceSecret = &gibsonv1alpha1.SecretKeyRef{Name: "gibson-openbao-unseal-keys"}

	if _, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionTrue {
		t.Fatalf("got %s/%s (%s), want True — defaults did not resolve", c.Status, c.Reason, c.Message)
	}
	got, err := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if err != nil || string(got) != "defaulted-key" {
		t.Fatalf("escrowed %q, want the minted key", string(got))
	}
}

// The parent directory cannot be created. Distinct from the write branch, and
// it must still be reported and retried rather than reported Ready.
func TestUnsealEscrow_MkdirFailureIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny writes")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	// Restored so t.TempDir() can remove it.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec // dir needs +x to be removable

	// A MISSING subdirectory under an unwritable parent: MkdirAll fails.
	r, pb := escrowFixture(t, gibsonv1alpha1.UnsealEscrowVolume, filepath.Join(locked, "sub", "k"), "key")
	res, err := r.reconcileUnsealEscrow(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("a failed escrow must be retried")
	}
	if c := escrowCond(t, pb); c.Status != metav1.ConditionFalse || c.Reason != "EscrowWriteFailed" {
		t.Fatalf("got %s/%s, want False/EscrowWriteFailed", c.Status, c.Reason)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
