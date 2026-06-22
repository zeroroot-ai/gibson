/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// fakeZitadelHandler implements the minimum Zitadel admin API surface
// the OIDCClient reconciler exercises. Returns deterministic IDs and
// secrets so the test can assert on them.
func fakeZitadelHandler() http.Handler {
	mux := http.NewServeMux()

	// Project lookup by name.
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-123","name":"gibson"}]}`))
	})

	// Application search (for the conflict + name-lookup paths).
	mux.HandleFunc("/management/v1/projects/PROJ-123/apps/_search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[]}`))
	})

	// Create OIDC client. Zitadel returns BOTH appId (management-API
	// record id) and clientId (OAuth identifier) — they are distinct
	// values and the reconciler persists both into status.
	mux.HandleFunc("/management/v1/projects/PROJ-123/apps/oidc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"appId":"APP-FAKE","clientId":"CID-FAKE","clientSecret":"SECRET-FAKE"}`))
	})

	// Get OIDC client by appID (steady-state reconcile branch). The
	// oidcConfig advertises accessTokenType=OIDC_TOKEN_TYPE_JWT so the
	// EnsureJWTAccessToken check short-circuits without issuing a PUT
	// (the test asserts both create + steady-state pass without drift).
	mux.HandleFunc("/management/v1/projects/PROJ-123/apps/APP-FAKE", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"app":{"id":"APP-FAKE","name":"test-dashboard","oidcConfig":{"appType":"OIDC_APP_TYPE_WEB","clientId":"CID-FAKE","accessTokenType":"OIDC_TOKEN_TYPE_JWT"}}}`))
	})

	// PUT oidc_config (patch path) — accepts any body, returns 200.
	// Exercised in TestEnsureJWTAccessToken when the GET above returns
	// a non-JWT type (separate handler not wired here since the
	// envtest happy path uses the JWT-already shape).
	mux.HandleFunc("/management/v1/projects/PROJ-123/apps/APP-FAKE/oidc_config",
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})

	// OIDC introspection (zeroroot-ai/platform-operator#22): accepts
	// Basic auth and validates against the deterministic fixture values.
	// Returns 200 when (clientID, clientSecret) match the fake's known
	// pair, 401 otherwise. This mirrors Zitadel's behavior where Basic
	// auth is verified BEFORE the token body is inspected.
	mux.HandleFunc("/oauth/v2/introspect", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "CID-FAKE" || pass != "SECRET-FAKE" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		_, _ = w.Write([]byte(`{"active":false}`))
	})

	// Rotate client secret (post-introspection-failure recovery path).
	mux.HandleFunc("/management/v1/projects/PROJ-123/apps/APP-FAKE/oidc_config/_generate_client_secret",
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"clientSecret":"SECRET-FAKE"}`))
		})

	return mux
}

var _ = Describe("OIDCClient reconciler", func() {
	const (
		ns          = "gibson-test"
		clientName  = "test-dashboard"
		patSecret   = "iam-admin-pat"
		patKey      = "pat"
		patValue    = "fake-pat-token"
		outSecretNm = "test-dashboard-secret"
	)

	var (
		fake       *httptest.Server
		reconciler *OIDCClientReconciler
	)

	BeforeEach(func() {
		fake = httptest.NewServer(fakeZitadelHandler())

		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))

		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: patSecret, Namespace: ns},
			Data:       map[string][]byte{patKey: []byte(patValue)},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))

		reconciler = &OIDCClientReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
			ZitadelFactory: func(issuer, pat string) zitadel.Client {
				return zitadel.New(fake.URL, pat, "")
			},
		}
	})

	AfterEach(func() {
		fake.Close()
	})

	It("mints a client and writes the Secret on first reconcile", func() {
		oc := &gibsonv1alpha1.OIDCClient{
			ObjectMeta: metav1.ObjectMeta{Name: clientName, Namespace: ns},
			Spec: gibsonv1alpha1.OIDCClientSpec{
				ZitadelIssuer:   fake.URL,
				AdminTokenRef:   gibsonv1alpha1.SecretKeyRef{Name: patSecret, Namespace: ns, Key: patKey},
				ProjectRef:      gibsonv1alpha1.ProjectReference{Name: "gibson"},
				ClientName:      clientName,
				ApplicationType: gibsonv1alpha1.OIDCAppTypeWeb,
				RedirectURIs:    []string{"https://example.com/callback"},
				SecretRef:       gibsonv1alpha1.SecretKeyRef{Name: outSecretNm, Namespace: ns, Key: "client_secret"},
			},
		}
		Expect(k8sClient.Create(ctx, oc)).To(Succeed())

		// First reconcile adds the finalizer; second runs the state machine.
		key := types.NamespacedName{Name: clientName, Namespace: ns}
		for i := 0; i < 4; i++ {
			_, err := reconciler.Reconcile(ctx, ctrlRequest(key))
			Expect(err).NotTo(HaveOccurred())
		}

		Eventually(func(g Gomega) {
			var got gibsonv1alpha1.OIDCClient
			g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			g.Expect(got.Status.ClientID).To(Equal("CID-FAKE"))

			var sec corev1.Secret
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: outSecretNm, Namespace: ns}, &sec)).To(Succeed())
			g.Expect(sec.Data["client_id"]).To(Equal([]byte("CID-FAKE")))
			g.Expect(sec.Data["client_secret"]).To(Equal([]byte("SECRET-FAKE")))
			// Screaming-snake aliases for consumers that reference the
			// credentials via ZITADEL_CLIENT_ID / ZITADEL_CLIENT_SECRET.
			g.Expect(sec.Data["ZITADEL_CLIENT_ID"]).To(Equal([]byte("CID-FAKE")))
			g.Expect(sec.Data["ZITADEL_CLIENT_SECRET"]).To(Equal([]byte("SECRET-FAKE")))
		}).Should(Succeed())
	})

	It("WaitingForAdminToken when the admin Secret is absent", func() {
		// Use a different namespace to avoid the BeforeEach-seeded Secret.
		isolatedNs := "gibson-no-token"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: isolatedNs},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))

		oc := &gibsonv1alpha1.OIDCClient{
			ObjectMeta: metav1.ObjectMeta{Name: "no-token", Namespace: isolatedNs},
			Spec: gibsonv1alpha1.OIDCClientSpec{
				ZitadelIssuer:   fake.URL,
				AdminTokenRef:   gibsonv1alpha1.SecretKeyRef{Name: "missing", Namespace: isolatedNs, Key: "pat"},
				ProjectRef:      gibsonv1alpha1.ProjectReference{Name: "gibson"},
				ClientName:      "no-token",
				ApplicationType: gibsonv1alpha1.OIDCAppTypeService,
				SecretRef:       gibsonv1alpha1.SecretKeyRef{Name: "no-token-secret", Namespace: isolatedNs, Key: "client_secret"},
			},
		}
		Expect(k8sClient.Create(ctx, oc)).To(Succeed())

		key := types.NamespacedName{Name: "no-token", Namespace: isolatedNs}
		// Two reconciles: first adds finalizer; second checks for the Secret.
		for i := 0; i < 2; i++ {
			_, err := reconciler.Reconcile(ctx, ctrlRequest(key))
			Expect(err).NotTo(HaveOccurred())
		}

		Eventually(func(g Gomega) {
			var got gibsonv1alpha1.OIDCClient
			g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			cond := findStatusCondition(got.Status.Conditions, gibsonv1alpha1.ConditionOIDCClientExists)
			g.Expect(cond).NotTo(BeNil())
			g.Expect(cond.Reason).To(Equal("WaitingForAdminToken"))
		}).Should(Succeed())
	})

	It("machine user: enforces JWT token type and writes Secret on first reconcile", func() {
		// Track PUT calls to /management/v1/users/{id}/machine so we can
		// assert EnsureMachineUserJWTAccessToken was invoked.
		var machineUserPUTCount int32

		machineNs := "gibson-machine-test"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: machineNs},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "machine-pat", Namespace: machineNs},
			Data:       map[string][]byte{"pat": []byte("fake-pat")},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))

		// Fake Zitadel handler wired for the MACHINE_USER path.
		machineMux := http.NewServeMux()

		// Project lookup.
		machineMux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-MACH","name":"gibson"}]}`))
		})
		// Get project → resourceOwner (org_id).
		machineMux.HandleFunc("/management/v1/projects/PROJ-MACH", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-MACH"}}}`))
		})
		// Create machine user.
		machineMux.HandleFunc("/management/v1/users/machine", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"userId":"UID-MACH"}`))
		})
		// GET machine user — returns BEARER so EnsureMachineUserJWTAccessToken issues a PUT.
		machineMux.HandleFunc("/management/v1/users/UID-MACH", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"user":{"machine":{"accessTokenType":"ACCESS_TOKEN_TYPE_BEARER"}}}`))
		})
		// PUT machine user (EnsureMachineUserJWTAccessToken patch).
		machineMux.HandleFunc("/management/v1/users/UID-MACH/machine", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&machineUserPUTCount, 1)
			_, _ = w.Write([]byte(`{}`))
		})
		// IAM member grant.
		machineMux.HandleFunc("/admin/v1/members", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})
		// Org member grant (ORG_-prefixed roles route here).
		machineMux.HandleFunc("/management/v1/orgs/ORG-MACH/members", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})
		// Add client secret.
		machineMux.HandleFunc("/management/v1/users/UID-MACH/secret", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"clientId":"MCID-FAKE","clientSecret":"MSECRET-FAKE"}`))
		})

		machineFake := httptest.NewServer(machineMux)
		defer machineFake.Close()

		machineReconciler := &OIDCClientReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
			ZitadelFactory: func(issuer, pat string) zitadel.Client {
				return zitadel.New(machineFake.URL, pat, "")
			},
		}

		oc := &gibsonv1alpha1.OIDCClient{
			ObjectMeta: metav1.ObjectMeta{Name: "dashboard-service", Namespace: machineNs},
			Spec: gibsonv1alpha1.OIDCClientSpec{
				ZitadelIssuer:   machineFake.URL,
				AdminTokenRef:   gibsonv1alpha1.SecretKeyRef{Name: "machine-pat", Namespace: machineNs, Key: "pat"},
				ProjectRef:      gibsonv1alpha1.ProjectReference{Name: "gibson"},
				ClientName:      "gibson-dashboard-service",
				ApplicationType: gibsonv1alpha1.OIDCAppTypeMachineUser,
				SecretRef:       gibsonv1alpha1.SecretKeyRef{Name: "dashboard-service-secret", Namespace: machineNs, Key: "client_secret"},
			},
		}
		Expect(k8sClient.Create(ctx, oc)).To(Succeed())

		key := types.NamespacedName{Name: "dashboard-service", Namespace: machineNs}
		// First reconcile adds finalizer; subsequent runs drive the state machine.
		for i := 0; i < 4; i++ {
			_, err := machineReconciler.Reconcile(ctx, ctrlRequest(key))
			Expect(err).NotTo(HaveOccurred())
		}

		Eventually(func(g Gomega) {
			var got gibsonv1alpha1.OIDCClient
			g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			g.Expect(got.Status.ClientID).NotTo(BeEmpty())

			var sec corev1.Secret
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "dashboard-service-secret", Namespace: machineNs}, &sec)).To(Succeed())
			g.Expect(sec.Data["client_id"]).To(Equal([]byte("MCID-FAKE")))
			g.Expect(sec.Data["client_secret"]).To(Equal([]byte("MSECRET-FAKE")))
			g.Expect(sec.Data["issuer"]).NotTo(BeEmpty())
			g.Expect(sec.Data["org_id"]).To(Equal([]byte("ORG-MACH")))
			g.Expect(sec.Data["project_id"]).To(Equal([]byte("PROJ-MACH")))

			// EnsureMachineUserJWTAccessToken must have issued a PUT since
			// the fake GET returns BEARER.
			g.Expect(atomic.LoadInt32(&machineUserPUTCount)).To(BeNumerically(">=", 1))
		}).Should(Succeed())
	})

	It("machine user: grants spec.roles across IAM and org members (signup-bot shape)", func() {
		var (
			iamRolesBody atomic.Value // last JSON body sent to /admin/v1/members
			orgMemberHit int32
		)

		botNs := "gibson-signup-bot-test"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: botNs},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "bot-pat", Namespace: botNs},
			Data:       map[string][]byte{"pat": []byte("fake-pat")},
		})).To(Or(Succeed(), MatchError(ContainSubstring("already exists"))))

		mux := http.NewServeMux()
		mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-BOT","name":"gibson"}]}`))
		})
		mux.HandleFunc("/management/v1/projects/PROJ-BOT", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-BOT"}}}`))
		})
		mux.HandleFunc("/management/v1/users/machine", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"userId":"UID-BOT"}`))
		})
		mux.HandleFunc("/management/v1/users/UID-BOT", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"user":{"machine":{"accessTokenType":"ACCESS_TOKEN_TYPE_JWT"}}}`))
		})
		mux.HandleFunc("/management/v1/users/UID-BOT/machine", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})
		// IAM_-prefixed roles route here; capture the body to assert the role set.
		mux.HandleFunc("/admin/v1/members", func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			iamRolesBody.Store(string(b))
			_, _ = w.Write([]byte(`{}`))
		})
		// ORG_-prefixed roles route here, pinned to the project's org id.
		mux.HandleFunc("/management/v1/orgs/ORG-BOT/members", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&orgMemberHit, 1)
			_, _ = w.Write([]byte(`{}`))
		})
		mux.HandleFunc("/management/v1/users/UID-BOT/secret", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"clientId":"BOT-CID","clientSecret":"BOT-SECRET"}`))
		})

		botFake := httptest.NewServer(mux)
		defer botFake.Close()

		botReconciler := &OIDCClientReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
			ZitadelFactory: func(issuer, pat string) zitadel.Client {
				return zitadel.New(botFake.URL, pat, "")
			},
		}

		oc := &gibsonv1alpha1.OIDCClient{
			ObjectMeta: metav1.ObjectMeta{Name: "signup-bot", Namespace: botNs},
			Spec: gibsonv1alpha1.OIDCClientSpec{
				ZitadelIssuer:   botFake.URL,
				AdminTokenRef:   gibsonv1alpha1.SecretKeyRef{Name: "bot-pat", Namespace: botNs, Key: "pat"},
				ProjectRef:      gibsonv1alpha1.ProjectReference{Name: "gibson"},
				ClientName:      "gibson-signup-bot",
				ApplicationType: gibsonv1alpha1.OIDCAppTypeMachineUser,
				Roles:           []string{"IAM_USER_MANAGER", "IAM_LOGIN_CLIENT", "ORG_OWNER"},
				SecretRef:       gibsonv1alpha1.SecretKeyRef{Name: "gibson-signup-bot-credentials", Namespace: botNs, Key: "client_secret"},
			},
		}
		Expect(k8sClient.Create(ctx, oc)).To(Succeed())

		key := types.NamespacedName{Name: "signup-bot", Namespace: botNs}
		for i := 0; i < 4; i++ {
			_, err := botReconciler.Reconcile(ctx, ctrlRequest(key))
			Expect(err).NotTo(HaveOccurred())
		}

		Eventually(func(g Gomega) {
			var got gibsonv1alpha1.OIDCClient
			g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			g.Expect(got.Status.ClientID).To(Equal("UID-BOT"))

			var sec corev1.Secret
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "gibson-signup-bot-credentials", Namespace: botNs}, &sec)).To(Succeed())
			g.Expect(sec.Data["client_id"]).To(Equal([]byte("BOT-CID")))
			g.Expect(sec.Data["client_secret"]).To(Equal([]byte("BOT-SECRET")))

			// IAM grant carried exactly the IAM_-prefixed roles, not ORG_OWNER.
			body, _ := iamRolesBody.Load().(string)
			g.Expect(body).To(ContainSubstring("IAM_USER_MANAGER"))
			g.Expect(body).To(ContainSubstring("IAM_LOGIN_CLIENT"))
			g.Expect(body).NotTo(ContainSubstring("ORG_OWNER"))

			// Org grant was routed to the project's owning org.
			g.Expect(atomic.LoadInt32(&orgMemberHit)).To(BeNumerically(">=", 1))
		}).Should(Succeed())
	})
})

var _ = Describe("classifyMachineUserRoles", func() {
	It("defaults to IAM_OWNER when empty", func() {
		iam, org := classifyMachineUserRoles(nil)
		Expect(iam).To(Equal([]string{"IAM_OWNER"}))
		Expect(org).To(BeEmpty())
	})

	It("splits IAM_ and ORG_ roles by prefix", func() {
		iam, org := classifyMachineUserRoles([]string{"IAM_USER_MANAGER", "ORG_OWNER", "IAM_LOGIN_CLIENT"})
		Expect(iam).To(Equal([]string{"IAM_USER_MANAGER", "IAM_LOGIN_CLIENT"}))
		Expect(org).To(Equal([]string{"ORG_OWNER"}))
	})

	It("treats unknown-prefix roles as IAM roles rather than dropping them", func() {
		iam, org := classifyMachineUserRoles([]string{"SOMETHING_ELSE"})
		Expect(iam).To(Equal([]string{"SOMETHING_ELSE"}))
		Expect(org).To(BeEmpty())
	})
})

// findStatusCondition is a tiny helper to avoid importing apimachinery's
// conditions util in tests.
func findStatusCondition(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}
