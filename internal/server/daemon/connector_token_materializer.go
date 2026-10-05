// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — connector_token_materializer.go
//
// The daemon-side adapter for reconciler.Materializer (ADR-0061). The token
// reconciler keeps each oauth connector's access token fresh in the tenant
// secret store; this adapter publishes that token into the Kubernetes Secret
// the ToolHive proxy mounts, so the proxy pod can start and the
// ConnectorInstance leaves Provisioning and reaches Active.
//
// The daemon writes the Secret directly — no RPC ever returns the token, and
// there is no ESO step (ADR-0061). The Secret VALUE is the full header
// "Bearer <token>"; its ownerReference points at the ConnectorInstance CR so
// Kubernetes garbage-collects it on connector delete.
//
// There is no fallback cache (ADR-0061). The platform's own expiry
// bookkeeping decides whether a token may be published at all: past expiry the
// adapter withdraws the Secret instead of leaving a dead bearer token mounted,
// so a revoked grant or an unreachable tenant store fails closed. Recovery is
// re-authorization, never a cached credential.
package daemon

import (
	"context"
	"encoding/json"
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
// The expiry check comes first and it is the fail-closed rule (ADR-0061):
// a token the refresher can no longer renew must stop being
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

	data := make(map[string][]byte, 1+len(d.Credentials))

	header, expired, err := m.bearerHeader(tctx, d)
	if err != nil {
		return err
	}
	if header != nil {
		data[connectorCredSecretKey] = header
	}

	// The declared credential refs (ConnectorInstanceSpec.Credentials,
	// gibson#597): each one is a tenant secret the daemon resolves by name,
	// narrowed to one property when the secret is structured, and published
	// under the env var the connector reads it as. The operator maps every
	// key of this Secret into the pod env by the same name.
	for _, ref := range d.Credentials {
		value, err := m.resolveCredentialRef(tctx, d.Connector, ref)
		if err != nil {
			return err
		}
		data[ref.TargetEnv] = value
	}

	if len(data) == 0 {
		if expired {
			return m.withdraw(ctx, d)
		}
		return nil // nothing minted and nothing declared; nothing to publish
	}

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
		// The whole data set is replaced, so a withdrawn token or a removed
		// ref leaves the Secret on the next pass instead of lingering.
		sec.Data = data
		sec.OwnerReferences = []metav1.OwnerReference{owner}
		return nil
	}); err != nil {
		return fmt.Errorf("apply connector-cred Secret %s/%s: %w",
			d.Namespace, connectorCredSecretName(d.InstanceName), err)
	}
	return nil
}

// bearerHeader resolves the connector's minted access token as the
// "Bearer <token>" header value. It returns nil when nothing is minted or
// published yet, and expired=true when the token's lifetime has passed, in
// which case the header is withheld.
func (m *connectorTokenMaterializer) bearerHeader(tctx context.Context, d reconciler.ConnectorSandbox) (header []byte, expired bool, err error) {
	meta, err := m.secrets.Resolve(tctx, connectorauth.AccessMetaSecretName(d.Connector))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, false, nil // nothing minted yet
		}
		return nil, false, fmt.Errorf("resolve access metadata for connector %q: %w", d.Connector, err)
	}
	if len(meta) == 0 {
		return nil, false, nil
	}
	tok, err := connectorauth.UnmarshalAccessToken(meta)
	if err != nil {
		return nil, false, fmt.Errorf("connector %q: %w", d.Connector, err)
	}
	if tok.Expired(m.clock()) {
		return nil, true, nil
	}

	raw, err := m.secrets.Resolve(tctx, connectorauth.AccessSecretName(d.Connector))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, false, nil // no token published yet
		}
		return nil, false, fmt.Errorf("resolve access token for connector %q: %w", d.Connector, err)
	}
	if len(raw) == 0 {
		return nil, false, nil
	}
	return append([]byte("Bearer "), raw...), false, nil
}

// resolveCredentialRef reads the tenant secret a CredentialRef names and
// narrows it to ref.Property when set. A missing secret or a missing
// property is an error, never an empty value: a connector started with an
// empty credential fails later and further from the cause.
func (m *connectorTokenMaterializer) resolveCredentialRef(tctx context.Context, connector string, ref reconciler.ConnectorCredentialRef) ([]byte, error) {
	raw, err := m.secrets.Resolve(tctx, ref.Key)
	if err != nil {
		return nil, fmt.Errorf("connector %q: resolve credential %q for %s: %w", connector, ref.Key, ref.TargetEnv, err)
	}
	if ref.Property == "" {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("connector %q: credential %q is not a JSON object, cannot read property %q: %w", connector, ref.Key, ref.Property, err)
	}
	v, ok := fields[ref.Property]
	if !ok {
		return nil, fmt.Errorf("connector %q: credential %q has no property %q", connector, ref.Key, ref.Property)
	}
	var str string
	if err := json.Unmarshal(v, &str); err == nil {
		return []byte(str), nil
	}
	return []byte(v), nil
}

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
