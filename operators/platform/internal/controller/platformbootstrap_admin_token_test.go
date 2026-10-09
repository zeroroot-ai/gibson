// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// adminTokenReconciler wires a fake OpenBao and a fake Zitadel System API.
func adminTokenReconciler(t *testing.T, vc *fakeVaultClient, sys *fakeSystemClient) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultChildNamespace, Name: "vault-admin-token"},
		Data:       map[string][]byte{"token": []byte("root-token")},
	}
	// The System API key mount, with its user (ADR-0171).
	t.Setenv("ZITADEL_SYSTEM_KEY_PATH", writeTestSystemMount(t, "gibson-system-bot"))
	return &PlatformBootstrapReconciler{
		Audit:  (&audittest.Sink{}).Emitter(t),
		Client: fake.NewClientBuilder().WithScheme(s).WithObjects(tokenSecret).Build(),
		Scheme: s,
		VaultFactory: func(string, vault.TokenFunc) (vault.Client, error) {
			return vc, nil
		},
		SystemClientFactory: func(string, string, string, string) (zitadel.SystemClient, error) {
			return sys, nil
		},
		Now: func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) },
	}
}

func adminTokenBootstrap() *gibsonv1alpha1.PlatformBootstrap {
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{}, "")
	pb.Spec.VaultTransit.TokenRef = gibsonv1alpha1.SecretKeyRef{Name: "vault-admin-token", Key: "token"}
	return pb
}

func adminTokenCond(t *testing.T, pb *gibsonv1alpha1.PlatformBootstrap) *metav1.Condition {
	t.Helper()
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionAdminTokenReady)
	if c == nil {
		t.Fatal("no AdminTokenReady condition")
	}
	return c
}

// First start: OpenBao holds no token. The step mints one with the System
// API key and writes it, with the user id.
func TestReconcileAdminToken_FirstStartMints(t *testing.T) {
	vc, sys := &fakeVaultClient{}, &fakeSystemClient{}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	res, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard())
	if err != nil || !res.IsZero() {
		t.Fatalf("res=%+v err=%v, want a clean pass", res, err)
	}
	if sys.minted != 1 || vc.writes != 1 {
		t.Fatalf("minted %d, wrote %d; want one each", sys.minted, vc.writes)
	}
	stored := vc.kv[adminTokenKVKey]
	if stored[adminTokenProperty] != "pat-1" || stored[adminUserProperty] != "user-iam-admin" {
		t.Errorf("stored = %v", stored)
	}
	if c := adminTokenCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "TokenMinted" {
		t.Errorf("condition = %+v", c)
	}
}

// Restore: the restored OpenBao holds a valid token. The step mints nothing
// and writes nothing.
func TestReconcileAdminToken_RestoreMintsNothing(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {
		adminTokenProperty: "restored", mintedAtProperty: "2026-10-01T00:00:00Z",
	}}}
	sys := &fakeSystemClient{validTokens: map[string]bool{"restored": true}}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	if _, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 0 || vc.writes != 0 {
		t.Fatalf("minted %d, wrote %d; want none", sys.minted, vc.writes)
	}
	if c := adminTokenCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "TokenValid" {
		t.Errorf("condition = %+v", c)
	}
}

// Replace: Zitadel refuses the stored token. The step mints a new one and
// writes it over the old one.
func TestReconcileAdminToken_ReplacesAnInvalidToken(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {adminTokenProperty: "revoked"}}}
	sys := &fakeSystemClient{}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	if _, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 1 || vc.kv[adminTokenKVKey][adminTokenProperty] != "pat-1" {
		t.Fatalf("minted %d, stored %v; want a new token", sys.minted, vc.kv[adminTokenKVKey])
	}
}

// Each failure stops the pass, keeps what is stored, and is not Ready.
func TestReconcileAdminToken_Failures(t *testing.T) {
	cases := map[string]struct {
		vc  *fakeVaultClient
		sys *fakeSystemClient
		pb  func() *gibsonv1alpha1.PlatformBootstrap
	}{
		"no system client": {&fakeVaultClient{}, &fakeSystemClient{}, func() *gibsonv1alpha1.PlatformBootstrap {
			pb := adminTokenBootstrap()
			pb.Spec.Zitadel.SystemClient = nil
			return pb
		}},
		"openbao read fails":  {&fakeVaultClient{readErr: errors.New("sealed")}, &fakeSystemClient{}, adminTokenBootstrap},
		"zitadel unreachable": {&fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {adminTokenProperty: "x"}}}, &fakeSystemClient{validErr: errors.New("dial")}, adminTokenBootstrap},
		"mint refused":        {&fakeVaultClient{}, &fakeSystemClient{mintErr: zitadel.WrapPermanent(errors.New("403"))}, adminTokenBootstrap},
		"openbao write fails": {&fakeVaultClient{writeErr: errors.New("permission denied")}, &fakeSystemClient{}, adminTokenBootstrap},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := adminTokenReconciler(t, c.vc, c.sys)
			pb := c.pb()
			res, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("err = %v, want a requeue", err)
			}
			if res.RequeueAfter == 0 {
				t.Error("no requeue")
			}
			if cond := adminTokenCond(t, pb); cond.Status == metav1.ConditionTrue {
				t.Errorf("condition = %+v, want not True", cond)
			}
		})
	}
}

// ADR-0171: a valid token older than tokenRotateAfter gets a successor while
// it still works, and the entry records the id, the mint time and the retire
// time of the new token.
func TestReconcileAdminToken_RotatesAnOldToken(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {
		adminTokenProperty: "old", adminUserProperty: "user-iam-admin", tokenIDProperty: "pat-id-old",
		mintedAtProperty: "2026-08-01T00:00:00Z",
	}}}
	sys := &fakeSystemClient{validTokens: map[string]bool{"old": true}}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	if _, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	got := vc.kv[adminTokenKVKey]
	if sys.minted != 1 || got[adminTokenProperty] != "pat-1" || got[tokenIDProperty] != "pat-id-1" {
		t.Fatalf("minted %d, stored %v; want a successor", sys.minted, got)
	}
	if got[mintedAtProperty] != "2026-10-05T00:00:00Z" || got[retireAfterProperty] != "2026-10-05T00:10:00Z" {
		t.Errorf("mint and retire times = %q, %q", got[mintedAtProperty], got[retireAfterProperty])
	}
	if !sys.validTokens["old"] || len(sys.retired) != 0 {
		t.Errorf("the old token must keep working until the grace ends; retired %v", sys.retired)
	}
	if c := adminTokenCond(t, pb); c.Reason != "TokenRotated" {
		t.Errorf("condition = %+v", c)
	}
}

// A young token with no retire time is left as it is.
func TestReconcileAdminToken_KeepsAYoungToken(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {
		adminTokenProperty: "young", mintedAtProperty: "2026-10-04T00:00:00Z",
	}}}
	sys := &fakeSystemClient{validTokens: map[string]bool{"young": true}}
	r := adminTokenReconciler(t, vc, sys)
	if _, err := r.reconcileAdminToken(context.Background(), adminTokenBootstrap(), logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 0 || vc.writes != 0 || len(sys.retired) != 0 {
		t.Fatalf("minted %d, wrote %d, retired %v; want nothing", sys.minted, vc.writes, sys.retired)
	}
}

// consumerSecrets returns the two consumer Secrets with the tokens given.
func consumerSecrets(adminPAT, loginPAT string) []client.Object {
	return []client.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: defaultChildNamespace, Name: "iam-admin-pat"},
			Data:       map[string][]byte{"pat": []byte(adminPAT)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: defaultChildNamespace, Name: loginClientSecret},
			Data:       map[string][]byte{"pat": []byte(loginPAT)},
		},
	}
}

// retireBootstrap is adminTokenBootstrap with the admin token ref the chart
// renders.
func retireBootstrap() *gibsonv1alpha1.PlatformBootstrap {
	pb := adminTokenBootstrap()
	pb.Spec.Zitadel.AdminTokenRef = gibsonv1alpha1.SecretKeyRef{Name: "iam-admin-pat", Key: "pat"}
	return pb
}

func retireEntry(after, since string) map[string]map[string]string {
	e := map[string]string{
		adminTokenProperty: "new", adminUserProperty: "user-iam-admin", tokenIDProperty: "pat-id-new",
		mintedAtProperty: "2026-10-04T23:00:00Z", retireAfterProperty: after,
	}
	if since != "" {
		e[consumerSinceProperty] = since
	}
	return map[string]map[string]string{adminTokenKVKey: e}
}

func runRetire(t *testing.T, vc *fakeVaultClient, sys *fakeSystemClient, adminHeld string) (*gibsonv1alpha1.PlatformBootstrap, error) {
	t.Helper()
	r := adminTokenReconciler(t, vc, sys)
	for _, o := range consumerSecrets(adminHeld, "") {
		if err := r.Create(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	pb := retireBootstrap()
	_, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard())
	return pb, err
}

// Before the grace of the mint ends, the step removes nothing.
func TestReconcileAdminToken_NoRetireBeforeTheGrace(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-05T00:05:00Z", "")}
	if _, err := runRetire(t, vc, sys, "new"); err != nil {
		t.Fatal(err)
	}
	if len(sys.retired) != 0 {
		t.Fatalf("retired %v before the grace ended", sys.retired)
	}
}

// FAILING FIXTURE: a consumer Secret that still holds the old token blocks
// the retire, however long ago the mint was.
func TestReconcileAdminToken_NoRetireWhileTheConsumerHoldsTheOldToken(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-04T23:10:00Z", "")}
	if _, err := runRetire(t, vc, sys, "old"); err != nil {
		t.Fatal(err)
	}
	if len(sys.retired) != 0 {
		t.Fatalf("retired %v while the consumer holds the old token", sys.retired)
	}
	if _, set := vc.kv[adminTokenKVKey][consumerSinceProperty]; set {
		t.Fatal("recorded a consumer time for a consumer that holds the old token")
	}
}

// The first pass that sees the consumer hold the new token records the time,
// and removes nothing yet.
func TestReconcileAdminToken_RecordsWhenTheConsumerHoldsTheNewToken(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-04T23:10:00Z", "")}
	if _, err := runRetire(t, vc, sys, "new"); err != nil {
		t.Fatal(err)
	}
	if len(sys.retired) != 0 {
		t.Fatalf("retired %v on the first pass that saw the consumer", sys.retired)
	}
	if got := vc.kv[adminTokenKVKey][consumerSinceProperty]; got != "2026-10-05T00:00:00Z" {
		t.Fatalf("consumerSince = %q", got)
	}
}

// A grace after the consumer holds the new token, the step removes each other
// token of the user and clears the record.
func TestReconcileAdminToken_RetiresTheOldTokensAfterTheGrace(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-04T23:10:00Z", "2026-10-04T23:45:00Z")}
	if _, err := runRetire(t, vc, sys, "new"); err != nil {
		t.Fatal(err)
	}
	if len(sys.retired) != 1 || sys.retired[0] != "user-iam-admin:pat-id-new" {
		t.Fatalf("retired %v, want the other tokens of user-iam-admin, keeping pat-id-new", sys.retired)
	}
	got := vc.kv[adminTokenKVKey]
	if _, still := got[retireAfterProperty]; still {
		t.Errorf("the retire time is still stored after the retire: %v", got)
	}
	if _, still := got[consumerSinceProperty]; still {
		t.Errorf("the consumer time is still stored after the retire: %v", got)
	}
	if got[adminTokenProperty] != "new" {
		t.Errorf("the retire changed the token: %v", got)
	}
}

// FAILING FIXTURE: a failed retire keeps the record, so the next pass tries
// again, and the token is not Ready.
func TestReconcileAdminToken_FailedRetireKeepsTheRecord(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}, retireErr: errors.New("503")}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-04T23:10:00Z", "2026-10-04T23:45:00Z")}
	pb, err := runRetire(t, vc, sys, "new")
	if err != nil {
		t.Fatal(err)
	}
	if vc.kv[adminTokenKVKey][retireAfterProperty] == "" {
		t.Fatal("the retire time was cleared after a failed retire")
	}
	if c := adminTokenCond(t, pb); c.Status == metav1.ConditionTrue {
		t.Errorf("condition = %+v, want not Ready", c)
	}
}

// A token this operator minted minutes ago that Zitadel refuses is not
// minted again on each pass.
func TestReconcileAdminToken_DoesNotMintAgainForAFreshRefusedToken(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {
		adminTokenProperty: "fresh", mintedAtProperty: "2026-10-04T23:58:00Z",
	}}}
	sys := &fakeSystemClient{}
	pb := adminTokenBootstrap()
	res, err := adminTokenReconciler(t, vc, sys).reconcileAdminToken(context.Background(), pb, logr.Discard())
	if err != nil || res.IsZero() {
		t.Fatalf("res=%+v err=%v, want a requeue", res, err)
	}
	if sys.minted != 0 {
		t.Fatalf("minted %d for a token minted two minutes ago", sys.minted)
	}
	if c := adminTokenCond(t, pb); c.Reason != "MintedTokenRefused" {
		t.Errorf("condition = %+v", c)
	}
}

// The login-client step waits for the escrowed first token, then rotates it
// like the admin token, and never stops the reconcile.
func TestReconcileLoginClientToken(t *testing.T) {
	t.Run("waits for the escrow", func(t *testing.T) {
		vc, sys := &fakeVaultClient{}, &fakeSystemClient{}
		pb := adminTokenBootstrap()
		adminTokenReconciler(t, vc, sys).reconcileLoginClientToken(context.Background(), pb, logr.Discard())
		if sys.minted != 0 {
			t.Fatalf("minted %d before the escrow stored the first token", sys.minted)
		}
		if c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionLoginClientTokenReady); c == nil || c.Reason != "WaitingForEscrow" {
			t.Fatalf("condition = %+v", c)
		}
	})
	t.Run("a vault outage sets the condition and stops nothing", func(t *testing.T) {
		vc := &fakeVaultClient{readErr: errors.New("sealed")}
		pb := adminTokenBootstrap()
		adminTokenReconciler(t, vc, &fakeSystemClient{}).reconcileLoginClientToken(context.Background(), pb, logr.Discard())
		if c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionLoginClientTokenReady); c == nil || c.Status == metav1.ConditionTrue {
			t.Fatalf("condition = %+v", c)
		}
	})
	t.Run("no system client", func(t *testing.T) {
		pb := adminTokenBootstrap()
		pb.Spec.Zitadel.SystemClient = nil
		adminTokenReconciler(t, &fakeVaultClient{}, &fakeSystemClient{}).reconcileLoginClientToken(context.Background(), pb, logr.Discard())
		if c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionLoginClientTokenReady); c == nil || c.Reason != "SystemClientMissing" {
			t.Fatalf("condition = %+v", c)
		}
	})
	t.Run("a failed mint sets the condition", func(t *testing.T) {
		vc := &fakeVaultClient{kv: map[string]map[string]string{loginClientTokenKVKey: {adminTokenProperty: "from-setup"}}}
		sys := &fakeSystemClient{mintErr: errors.New("503")}
		pb := adminTokenBootstrap()
		adminTokenReconciler(t, vc, sys).reconcileLoginClientToken(context.Background(), pb, logr.Discard())
		if c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionLoginClientTokenReady); c == nil || c.Reason != "MintFailed" {
			t.Fatalf("condition = %+v", c)
		}
	})
	t.Run("the retire reads the login-client Secret", func(t *testing.T) {
		vc := &fakeVaultClient{kv: map[string]map[string]string{loginClientTokenKVKey: {
			adminTokenProperty: "new", adminUserProperty: "user-login-client", tokenIDProperty: "pat-id-new",
			mintedAtProperty: "2026-10-04T23:00:00Z", retireAfterProperty: "2026-10-04T23:10:00Z",
			consumerSinceProperty: "2026-10-04T23:45:00Z",
		}}}
		sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
		r := adminTokenReconciler(t, vc, sys)
		for _, o := range consumerSecrets("", "new") {
			if err := r.Create(context.Background(), o); err != nil {
				t.Fatal(err)
			}
		}
		pb := adminTokenBootstrap()
		r.reconcileLoginClientToken(context.Background(), pb, logr.Discard())
		if len(sys.retired) != 1 || sys.retired[0] != "user-login-client:pat-id-new" {
			t.Fatalf("retired %v", sys.retired)
		}
	})
	t.Run("rotates the escrowed token", func(t *testing.T) {
		vc := &fakeVaultClient{kv: map[string]map[string]string{loginClientTokenKVKey: {adminTokenProperty: "from-setup"}}}
		sys := &fakeSystemClient{validTokens: map[string]bool{"from-setup": true}}
		pb := adminTokenBootstrap()
		adminTokenReconciler(t, vc, sys).reconcileLoginClientToken(context.Background(), pb, logr.Discard())
		got := vc.kv[loginClientTokenKVKey]
		if sys.minted != 1 || got[adminTokenProperty] != "pat-1" || got[adminUserProperty] != "user-login-client" {
			t.Fatalf("minted %d, stored %v; want a successor for login-client", sys.minted, got)
		}
		if c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionLoginClientTokenReady); c == nil || c.Status != metav1.ConditionTrue {
			t.Fatalf("condition = %+v", c)
		}
	})
}

// FAILING FIXTURE: inside the second wait (the consumer holds the new token,
// but for less than one grace), nothing is removed.
func TestReconcileAdminToken_NoRetireInsideTheSecondWait(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-04T23:10:00Z", "2026-10-04T23:55:00Z")}
	if _, err := runRetire(t, vc, sys, "new"); err != nil {
		t.Fatal(err)
	}
	if len(sys.retired) != 0 {
		t.Fatalf("retired %v five minutes after the consumer got the new token", sys.retired)
	}
}

// A retire that waits for the consumer shows it in the condition.
func TestReconcileAdminToken_WaitingForTheConsumerIsVisible(t *testing.T) {
	sys := &fakeSystemClient{validTokens: map[string]bool{"new": true}}
	vc := &fakeVaultClient{kv: retireEntry("2026-10-04T23:10:00Z", "")}
	pb, err := runRetire(t, vc, sys, "old")
	if err != nil {
		t.Fatal(err)
	}
	if c := adminTokenCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "RetireWaitingForConsumer" {
		t.Fatalf("condition = %+v", c)
	}
}

// After maxRefusedMints tokens in a row that Zitadel refused, the step stops
// minting.
func TestReconcileAdminToken_StopsMintingAfterRepeatedRefusals(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {
		adminTokenProperty: "refused", mintedAtProperty: "2026-10-04T20:00:00Z", refusedMintsProperty: "2",
	}}}
	sys := &fakeSystemClient{}
	pb := adminTokenBootstrap()
	if _, err := adminTokenReconciler(t, vc, sys).reconcileAdminToken(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 0 {
		t.Fatalf("minted %d after %d refused tokens", sys.minted, maxRefusedMints)
	}
	if c := adminTokenCond(t, pb); c.Reason != "MintedTokensRefused" {
		t.Fatalf("condition = %+v", c)
	}

	// One refusal below the limit mints, and counts it.
	vc = &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {
		adminTokenProperty: "refused", mintedAtProperty: "2026-10-04T20:00:00Z",
	}}}
	sys = &fakeSystemClient{}
	if _, err := adminTokenReconciler(t, vc, sys).reconcileAdminToken(context.Background(), adminTokenBootstrap(), logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 1 || vc.kv[adminTokenKVKey][refusedMintsProperty] != "1" {
		t.Fatalf("minted %d, stored %v; want one mint and a count of 1", sys.minted, vc.kv[adminTokenKVKey])
	}
}
