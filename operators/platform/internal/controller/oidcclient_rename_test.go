// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// fakeAppZitadel is an in-memory Zitadel that stores OIDC apps by appID. It
// records every lookup, create and rename so a test can assert which path the
// reconciler took. zitadel.Client is embedded (nil): any method the OIDCClient
// app path does not use panics, which is deliberate.
type fakeAppZitadel struct {
	zitadel.Client

	apps map[string]*zitadel.OIDCClient // appID -> app

	getByIDCalls   []string // appIDs passed to GetOIDCClient
	getByNameCalls []string // names passed to GetOIDCClientByName
	createCalls    int
	renames        []renameCall
	renameErr      error // when set, UpdateOIDCClientName fails with it
	projectErr     error // when set, GetProjectIDByName fails with it
}

type renameCall struct{ AppID, Name string }

func (f *fakeAppZitadel) GetProjectIDByName(context.Context, string) (string, error) {
	if f.projectErr != nil {
		return "", f.projectErr
	}
	return "PROJ", nil
}

func (f *fakeAppZitadel) GetOIDCClient(_ context.Context, _, appID string) (*zitadel.OIDCClient, error) {
	f.getByIDCalls = append(f.getByIDCalls, appID)
	a, ok := f.apps[appID]
	if !ok {
		return nil, zitadel.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (f *fakeAppZitadel) GetOIDCClientByName(_ context.Context, _, name string) (*zitadel.OIDCClient, error) {
	f.getByNameCalls = append(f.getByNameCalls, name)
	for _, a := range f.apps {
		if a.Name == name {
			cp := *a
			return &cp, nil
		}
	}
	return nil, zitadel.ErrNotFound
}

func (f *fakeAppZitadel) CreateOIDCClient(_ context.Context, req zitadel.CreateOIDCClientRequest) (appID, clientID, clientSecret string, err error) {
	f.createCalls++
	f.apps["APP-NEW"] = &zitadel.OIDCClient{AppID: "APP-NEW", ClientID: "CID-NEW", Name: req.Name}
	return "APP-NEW", "CID-NEW", "SECRET-NEW", nil
}

func (f *fakeAppZitadel) UpdateOIDCClientName(_ context.Context, _, appID, name string) error {
	if f.renameErr != nil {
		return f.renameErr
	}
	f.renames = append(f.renames, renameCall{appID, name})
	f.apps[appID].Name = name
	return nil
}

func (f *fakeAppZitadel) EnsureJWTAccessToken(context.Context, string, string) (bool, error) {
	return false, nil
}

func (f *fakeAppZitadel) VerifyClientSecret(context.Context, string, string) (bool, error) {
	return true, nil
}

// newOIDCClientRenameFixture builds a reconciler over a fake cluster that holds
// one already-reconciled OIDCClient (finalizer set, status filled, Secret
// present) and a fake Zitadel that holds its app under liveName.
func newOIDCClientRenameFixture(t *testing.T, specName, liveName, statusAppID string) (*OIDCClientReconciler, *fakeAppZitadel, types.NamespacedName) {
	t.Helper()
	const ns = "gibson"
	oc := &gibsonv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gibson-native-login", Namespace: ns,
			Finalizers: []string{oidcClientFinalizer},
		},
		Spec: gibsonv1alpha1.OIDCClientSpec{
			ZitadelURL:      "http://zitadel.invalid",
			AdminTokenRef:   gibsonv1alpha1.SecretKeyRef{Name: "pat", Namespace: ns, Key: "pat"},
			ProjectRef:      gibsonv1alpha1.ProjectReference{Name: "gibson"},
			ClientName:      specName,
			ApplicationType: gibsonv1alpha1.OIDCAppTypeNative,
			SecretRef:       gibsonv1alpha1.SecretKeyRef{Name: "out", Namespace: ns, Key: "client_secret"},
		},
		Status: gibsonv1alpha1.OIDCClientStatus{ClientID: "CID-OLD", AppID: statusAppID},
	}
	objs := []client.Object{
		oc,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "pat", Namespace: ns},
			Data:       map[string][]byte{"pat": []byte("fake-pat")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "out", Namespace: ns},
			Data:       map[string][]byte{"client_secret": []byte("S")},
		},
	}
	s := mustScheme(t)
	b := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&gibsonv1alpha1.OIDCClient{})
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	fz := &fakeAppZitadel{apps: map[string]*zitadel.OIDCClient{
		"APP-OLD": {AppID: "APP-OLD", ClientID: "CID-OLD", Name: liveName},
	}}
	r := &OIDCClientReconciler{
		Audit:          (&audittest.Sink{}).Emitter(t),
		Client:         b.Build(),
		Scheme:         s,
		Recorder:       record.NewFakeRecorder(16),
		ZitadelFactory: func(_, _ string) zitadel.Client { return fz },
	}
	return r, fz, types.NamespacedName{Name: oc.Name, Namespace: ns}
}

// (a) Once status.appID is set, the app is found by that ID. A name lookup
// would miss here, because the live app still carries its old display name.
func TestOIDCClient_FindsAppByStoredID(t *testing.T) {
	r, fz, key := newOIDCClientRenameFixture(t, "Gibson CLI", "gibson-native-login", "APP-OLD")

	_, err := r.Reconcile(context.Background(), ctrlRequest(key))
	require.NoError(t, err)

	require.Equal(t, []string{"APP-OLD"}, fz.getByIDCalls)
	require.Empty(t, fz.getByNameCalls, "must not look the app up by name once status.appID is known")
}

// (b) A spec.clientName that differs from the live app name renames the app,
// once, and a later reconcile with matching names issues no further update.
func TestOIDCClient_RenamesAppWhenClientNameChanges(t *testing.T) {
	r, fz, key := newOIDCClientRenameFixture(t, "Gibson CLI", "gibson-native-login", "APP-OLD")

	_, err := r.Reconcile(context.Background(), ctrlRequest(key))
	require.NoError(t, err)
	require.Equal(t, []renameCall{{AppID: "APP-OLD", Name: "Gibson CLI"}}, fz.renames)
	require.Equal(t, "Gibson CLI", fz.apps["APP-OLD"].Name)

	_, err = r.Reconcile(context.Background(), ctrlRequest(key))
	require.NoError(t, err)
	require.Len(t, fz.renames, 1, "a matching name must not issue another update")
}

// (c) A rename never creates a second app, and status keeps the same ids.
func TestOIDCClient_RenameDoesNotCreateDuplicateApp(t *testing.T) {
	r, fz, key := newOIDCClientRenameFixture(t, "Gibson CLI", "gibson-native-login", "APP-OLD")

	for range 3 {
		_, err := r.Reconcile(context.Background(), ctrlRequest(key))
		require.NoError(t, err)
	}

	require.Zero(t, fz.createCalls)
	require.Len(t, fz.apps, 1)
	var got gibsonv1alpha1.OIDCClient
	require.NoError(t, r.Get(context.Background(), key, &got))
	require.Equal(t, "APP-OLD", got.Status.AppID)
	require.Equal(t, "CID-OLD", got.Status.ClientID)
}

// First lookup (status.appID empty, an install from before the split) still
// adopts the existing app by name.
func TestOIDCClient_FirstLookupAdoptsAppByName(t *testing.T) {
	r, fz, key := newOIDCClientRenameFixture(t, "gibson-native-login", "gibson-native-login", "")

	_, err := r.Reconcile(context.Background(), ctrlRequest(key))
	require.NoError(t, err)

	require.Equal(t, []string{"gibson-native-login"}, fz.getByNameCalls)
	require.Zero(t, fz.createCalls)
	var got gibsonv1alpha1.OIDCClient
	require.NoError(t, r.Get(context.Background(), key, &got))
	require.Equal(t, "APP-OLD", got.Status.AppID)
}

// A permanent Zitadel error on rename is surfaced on the Ready condition and
// leaves the app and its status untouched.
func TestOIDCClient_RenameErrorIsSurfaced(t *testing.T) {
	r, fz, key := newOIDCClientRenameFixture(t, "Gibson CLI", "gibson-native-login", "APP-OLD")
	fz.renameErr = zitadel.ErrPermanent

	_, _ = r.Reconcile(context.Background(), ctrlRequest(key))

	require.Empty(t, fz.renames)
	require.Equal(t, "gibson-native-login", fz.apps["APP-OLD"].Name)
	var got gibsonv1alpha1.OIDCClient
	require.NoError(t, r.Get(context.Background(), key, &got))
	cond := findStatusCondition(got.Status.Conditions, gibsonv1alpha1.ConditionReady)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, "ZitadelPermanentError", cond.Reason)
}

// A transient Zitadel error sets ClientExists to Unknown. The next reconcile
// that succeeds must set it back to True and drop the old error text. Before
// this fix it stayed at Unknown beside Ready=True, which is what staging
// showed on all five clients on 2026-10-05, and the tenant operator reads
// ClientExists to decide that a tenant's identity is ready.
func TestOIDCClient_ARecoveredClientSaysTheClientExists(t *testing.T) {
	r, fz, key := newOIDCClientRenameFixture(t, "gibson-native-login", "gibson-native-login", "APP-OLD")
	condition := func(typ string) *metav1.Condition {
		t.Helper()
		var got gibsonv1alpha1.OIDCClient
		require.NoError(t, r.Get(context.Background(), key, &got))
		return findStatusCondition(got.Status.Conditions, typ)
	}

	fz.projectErr = zitadel.ErrUnreachable
	_, _ = r.Reconcile(context.Background(), ctrlRequest(key))
	exists := condition(gibsonv1alpha1.ConditionOIDCClientExists)
	require.NotNil(t, exists)
	require.Equal(t, metav1.ConditionUnknown, exists.Status, "a transient error must read as Unknown")

	fz.projectErr = nil
	_, err := r.Reconcile(context.Background(), ctrlRequest(key))
	require.NoError(t, err)

	ready := condition(gibsonv1alpha1.ConditionReady)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	exists = condition(gibsonv1alpha1.ConditionOIDCClientExists)
	require.NotNil(t, exists)
	require.Equal(t, metav1.ConditionTrue, exists.Status, "a reconcile that succeeded must say the client exists")
	require.Equal(t, "Verified", exists.Reason)
	require.NotContains(t, exists.Message, "unreachable", "the old error text must be gone")
}

// A client that was created keeps the reason that records how it came to
// exist. A later successful reconcile does not rewrite it.
func TestOIDCClient_ACreatedClientKeepsItsReason(t *testing.T) {
	r, _, key := newOIDCClientRenameFixture(t, "gibson-native-login", "gibson-native-login", "APP-OLD")
	var oc gibsonv1alpha1.OIDCClient
	require.NoError(t, r.Get(context.Background(), key, &oc))
	r.setCondition(&oc, gibsonv1alpha1.ConditionOIDCClientExists, metav1.ConditionTrue, "Created", "Zitadel client minted")
	require.NoError(t, r.Status().Update(context.Background(), &oc))

	_, err := r.Reconcile(context.Background(), ctrlRequest(key))
	require.NoError(t, err)

	require.NoError(t, r.Get(context.Background(), key, &oc))
	exists := findStatusCondition(oc.Status.Conditions, gibsonv1alpha1.ConditionOIDCClientExists)
	require.NotNil(t, exists)
	require.Equal(t, metav1.ConditionTrue, exists.Status)
	require.Equal(t, "Created", exists.Reason)
}
