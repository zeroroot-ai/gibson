// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — connector_token_materializer.go
//
// The daemon-side adapter for reconciler.Materializer (ADR-0015). The token
// reconciler keeps each oauth connector's access token fresh in the tenant
// secret store; this adapter publishes that token into the Kubernetes Secret
// the ToolHive proxy mounts, so the proxy pod can start and the
// ConnectorInstance leaves Provisioning and reaches Active.
//
// The daemon writes the Secret directly — no RPC ever returns the token, and
// there is no ESO step (ADR-0015). The Secret VALUE is the full header
// "Bearer <token>"; its ownerReference points at the ConnectorInstance CR so
// Kubernetes garbage-collects it on connector delete.
package daemon

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// connectorCredSecretKey is the Secret data key the ToolHive MCPRemoteProxy
// forwards as the Authorization header (headerForward.addHeadersFromSecret in
// the connector-operator). The value is the full "Bearer <token>" header.
const connectorCredSecretKey = "authorization"

// connectorCredSecretName is the Kubernetes Secret a connector's credential
// lands in. It MUST match the connector-operator's credentialSecretName(ci.Name)
// (operators/connector/internal/controller/connectorinstance_controller.go), or
// the proxy mounts a Secret nobody writes and dies CreateContainerConfigError.
func connectorCredSecretName(instanceName string) string {
	return instanceName + "-connector-cred"
}

// connectorSecretResolver is the slice of the tenant secret store the
// materializer reads: one tenant-scoped Resolve. *secrets.Service satisfies it.
type connectorSecretResolver interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
}

// connectorTokenMaterializer implements reconciler.Materializer over a kube
// client and the tenant secret store.
type connectorTokenMaterializer struct {
	kube    client.Client
	secrets connectorSecretResolver
}

// Materialize resolves the connector's fresh access token from the tenant
// secret store and writes it into the <connector>-connector-cred Secret in the
// tenant namespace, create-or-update, with an ownerReference to the
// ConnectorInstance CR.
//
// A connector that has no access token yet (authorized-but-not-minted, or the
// grant is gone) is a quiet no-op, not an error: there is nothing to publish,
// and the reconciler already logs the refresh side. Any other resolve or write
// failure returns an error the reconciler logs and isolates — the token bytes
// never travel in it.
func (m *connectorTokenMaterializer) Materialize(ctx context.Context, d reconciler.ConnectorSandbox) error {
	tctx := auth.WithTenant(ctx, d.Tenant)

	raw, err := m.secrets.Resolve(tctx, connectorauth.AccessSecretName(d.Connector))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil // no token published yet; nothing to materialize
		}
		// The error names the connector, never the token bytes.
		return fmt.Errorf("resolve access token for connector %q: %w", d.Connector, err)
	}
	if len(raw) == 0 {
		return nil
	}

	// The proxy presents this value verbatim as the Authorization header, so it
	// is the full "Bearer <token>" header, not the raw token.
	header := append([]byte("Bearer "), raw...)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      connectorCredSecretName(d.InstanceName),
			Namespace: d.Namespace,
		},
	}
	owner := metav1.OwnerReference{
		APIVersion: connectorv1alpha1.GroupVersion.String(),
		Kind:       "ConnectorInstance",
		Name:       d.InstanceName,
		UID:        d.InstanceUID,
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, m.kube, sec, func() error {
		sec.Type = corev1.SecretTypeOpaque
		if sec.Data == nil {
			sec.Data = make(map[string][]byte, 1)
		}
		sec.Data[connectorCredSecretKey] = header
		sec.OwnerReferences = []metav1.OwnerReference{owner}
		return nil
	}); err != nil {
		return fmt.Errorf("apply connector-cred Secret %s/%s: %w",
			d.Namespace, connectorCredSecretName(d.InstanceName), err)
	}
	return nil
}
