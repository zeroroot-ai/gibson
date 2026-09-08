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
//
// There is no fallback cache (ADR-0015 decision 4). The platform's own expiry
// bookkeeping decides whether a token may be published at all: past expiry the
// adapter withdraws the Secret instead of leaving a dead bearer token mounted,
// so a revoked grant or an unreachable tenant store fails closed. Recovery is
// re-authorization, never a cached credential.
package daemon

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	// now is the clock the published token's expiry is measured on. Nil means
	// time.Now.
	now func() time.Time
}

func (m *connectorTokenMaterializer) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Materialize publishes the connector's live access token into the
// <connector>-connector-cred Secret in the tenant namespace, create-or-update,
// with an ownerReference to the ConnectorInstance CR — or withdraws that
// Secret when the stored token is past expiry.
//
// The expiry check comes first and it is the fail-closed rule (ADR-0015
// decision 4): a token the refresher can no longer renew must stop being
// served, not linger in the Secret as a cache. So the adapter publishes a live
// token, withdraws a dead one, and waits when the platform has no bookkeeping
// to prove either.
//
// A connector that has no access token yet (authorized-but-not-minted, or the
// grant is gone) is a quiet no-op, not an error: there is nothing to publish,
// and the reconciler already logs the refresh side. Any other resolve or write
// failure returns an error the reconciler logs and isolates — the token bytes
// never travel in it.
func (m *connectorTokenMaterializer) Materialize(ctx context.Context, d reconciler.ConnectorSandbox) error {
	tctx := auth.WithTenant(ctx, d.Tenant)

	meta, err := m.secrets.Resolve(tctx, connectorauth.AccessMetaSecretName(d.Connector))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil // nothing minted yet; nothing to publish or withdraw
		}
		return fmt.Errorf("resolve access metadata for connector %q: %w", d.Connector, err)
	}
	if len(meta) == 0 {
		return nil
	}
	tok, err := connectorauth.UnmarshalAccessToken(meta)
	if err != nil {
		// Unreadable bookkeeping proves neither freshness nor death, so the
		// adapter publishes nothing and says why. The refresher rewrites both
		// secrets on its next pass, because it reads unreadable metadata as
		// "needs refresh" too.
		return fmt.Errorf("connector %q: %w", d.Connector, err)
	}
	if tok.Expired(m.clock()) {
		return m.withdraw(ctx, d)
	}

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

// withdraw removes a connector's credential Secret, so an access token the
// platform can no longer renew stops being served the moment it expires
// (ADR-0015 decision 4, "no fallback cache"). The connector's proxy loses its
// credential and the ConnectorInstance reports Degraded, which is the honest
// state: the vendor would reject the expired token anyway, and leaving it
// mounted only hides that from the operator. Deleting an absent Secret is a
// success, so the withdrawal is idempotent across passes.
func (m *connectorTokenMaterializer) withdraw(ctx context.Context, d reconciler.ConnectorSandbox) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      connectorCredSecretName(d.InstanceName),
			Namespace: d.Namespace,
		},
	}
	if err := m.kube.Delete(ctx, sec); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("withdraw connector-cred Secret %s/%s: %w",
			d.Namespace, connectorCredSecretName(d.InstanceName), err)
	}
	return nil
}
