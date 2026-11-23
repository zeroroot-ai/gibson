// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// The CA bundle of a connector (gibson#1517).
//
// A vendor server that a private CA signs needs a pod that trusts that CA. The
// tenant names a secret of its own store that holds a PEM bundle
// (spec.caBundleSecret). The daemon reads the secret for the tenant of the
// namespace. The operator writes a Secret in that namespace, owned by the
// ConnectorInstance, and mounts it into the MCP server pod of this connector
// only. It sets SSL_CERT_FILE there to the mounted file.
//
// Three rules keep the bundle in its tenant:
//
//   - The operator writes the Secret only in the namespace tenant-<tenant> of
//     the tenant that the daemon read the secret for.
//   - The pod mounts the Secret by the name of this connector, in the namespace
//     of this connector. A Secret of another namespace is never mounted.
//   - The pod mounts a Secret only when the ConnectorInstance owns it. A Secret
//     that another party made with the same name is refused.

const (
	// caBundleKey is the key of the PEM in the data of the CA Secret. The daemon
	// returns the bundle under this key. It is the key that the CA bundles of
	// the model providers use too (gibson#1403).
	caBundleKey = cabundle.Key

	// caBundleVolume is the name of the volume of the CA Secret in the pod.
	caBundleVolume = "connector-ca"

	// caBundleMountDir is where the pod sees the bundle. The path holds no
	// other file of the pod.
	caBundleMountDir = "/etc/gibson/connector-ca"

	// caBundleFile is the value of SSL_CERT_FILE. The Go TLS stack and most
	// others read the CA certificates of this file in addition to the
	// directory of the system roots.
	caBundleFile = caBundleMountDir + "/" + caBundleKey

	// sslCertFileEnv is the variable that the TLS stack of the server reads.
	sslCertFileEnv = "SSL_CERT_FILE"
)

// ErrCABundle is the error of a CA bundle that the operator refuses.
var ErrCABundle = errors.New("the CA bundle is refused")

// caSecretName is the Kubernetes Secret that holds the CA bundle of one
// connector.
func caSecretName(connector string) string { return connector + "-connector-ca" }

// ownedByInstance reports whether the ConnectorInstance owns the Secret.
func ownedByInstance(sec *corev1.Secret, ci *connectorv1alpha1.ConnectorInstance) bool {
	for _, o := range sec.OwnerReferences {
		if o.Kind == "ConnectorInstance" && o.Name == ci.Name && o.UID == ci.UID {
			return true
		}
	}
	return false
}

// checkCABundleSecret refuses a Secret that the pod of this connector must not
// mount: a Secret of another namespace, one that the ConnectorInstance does not
// own, or one that holds anything but CA certificates.
func checkCABundleSecret(sec *corev1.Secret, ci *connectorv1alpha1.ConnectorInstance) error {
	if sec.Namespace != ci.Namespace {
		return fmt.Errorf("%w: Secret %s/%s is not in the namespace %s of the connector",
			ErrCABundle, sec.Namespace, sec.Name, ci.Namespace)
	}
	if sec.Name != caSecretName(ci.Name) {
		return fmt.Errorf("%w: Secret %s/%s is not the CA Secret of the connector", ErrCABundle, sec.Namespace, sec.Name)
	}
	if !ownedByInstance(sec, ci) {
		return fmt.Errorf("%w: Secret %s/%s is not owned by the ConnectorInstance", ErrCABundle, sec.Namespace, sec.Name)
	}
	return checkCAPEM(sec.Data[caBundleKey])
}

// checkCAPEM accepts a PEM that holds CA certificates and nothing else. A
// private key or another block type means that the tenant named the wrong
// secret, and the pod must not get it. The daemon makes the same check when it
// reads the secret, and the operator makes it again before it writes the Secret.
func checkCAPEM(data []byte) error {
	if err := cabundle.Check(data); err != nil {
		return fmt.Errorf("%w: %w", ErrCABundle, err)
	}
	return nil
}

// caBundleState reads the CA Secret of a connector. ready is false while the
// daemon loop has not written it yet.
func (r *ConnectorInstanceReconciler) caBundleState(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) (ready bool, err error) {
	if ci.Spec.CABundleSecret == "" {
		return true, nil
	}
	if ci.Spec.Shape != connectorv1alpha1.ConnectorShapeHosted {
		return false, fmt.Errorf("%w: only a Hosted connector takes a CA bundle", ErrCABundle)
	}
	var sec corev1.Secret
	if gerr := r.Get(ctx, client.ObjectKey{Namespace: ci.Namespace, Name: caSecretName(ci.Name)}, &sec); gerr != nil {
		if apierrors.IsNotFound(gerr) {
			return false, nil
		}
		return false, fmt.Errorf("read the CA Secret of %s/%s: %w", ci.Namespace, ci.Name, gerr)
	}
	if cerr := checkCABundleSecret(&sec, ci); cerr != nil {
		return false, cerr
	}
	return true, nil
}

// withCABundle adds the CA volume, the mount and SSL_CERT_FILE to the MCP
// server pod of a connector that has a bundle. A connector without one is
// not touched.
func withCABundle(ci *connectorv1alpha1.ConnectorInstance, podSpec map[string]interface{}) {
	if ci.Spec.CABundleSecret == "" {
		return
	}
	podSpec["volumes"] = []interface{}{map[string]interface{}{
		"name": caBundleVolume,
		"secret": map[string]interface{}{
			"secretName":  caSecretName(ci.Name),
			"defaultMode": int64(0o444),
			"items": []interface{}{map[string]interface{}{
				"key": caBundleKey, "path": caBundleKey,
			}},
		},
	}}
	containers := podSpec["containers"].([]interface{})
	c := containers[0].(map[string]interface{})
	c["volumeMounts"] = []interface{}{map[string]interface{}{
		"name": caBundleVolume, "mountPath": caBundleMountDir, "readOnly": true,
	}}
}
