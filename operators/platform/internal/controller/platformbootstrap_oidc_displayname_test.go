// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// A reference with displayName produces a child whose clientName is the
// displayName. The child CR name stays ref.Name. A reference without
// displayName keeps clientName == name.
func TestReconcileOIDCChildren_DisplayName(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&gibsonv1alpha1.OIDCClient{}).Build()
	r := &PlatformBootstrapReconciler{Audit: (&audittest.Sink{}).Emitter(t), Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "pb", UID: "uid-1"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			OIDCClients: []gibsonv1alpha1.OIDCClientReference{
				{Name: "gibson-native-login", DisplayName: "Gibson CLI"},
				{Name: "dashboard"},
			},
		},
	}

	_, err := r.reconcileOIDCChildren(context.Background(), pb, logr.Discard())
	require.NoError(t, err)

	get := func(name string) gibsonv1alpha1.OIDCClient {
		var oc gibsonv1alpha1.OIDCClient
		require.NoError(t, cli.Get(context.Background(),
			types.NamespacedName{Namespace: defaultChildNamespace, Name: name}, &oc))
		return oc
	}
	require.Equal(t, "Gibson CLI", get("gibson-native-login").Spec.ClientName)
	require.Equal(t, "dashboard", get("dashboard").Spec.ClientName)
}
