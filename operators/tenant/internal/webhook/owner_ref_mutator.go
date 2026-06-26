// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package webhook hosts the mutating admission webhook that stamps an
// owner reference pointing at the parent Tenant on any AgentEnrollment /
// TenantMember CREATE when one is not already present.
//
// The webhook is defence-in-depth for the orphan-GC fix: the child
// controller's reconcile-time backfill guarantees convergence within
// ~30s; this webhook shrinks the window to near-zero at the API boundary.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
)

// OwnerRefMutator patches `metadata.ownerReferences` on CREATE for child
// CRs in tenant-* namespaces. Failure-open: any error returns Allowed with
// a warning so a webhook outage cannot block tenant creation flows.
type OwnerRefMutator struct {
	Client  client.Client
	decoder admission.Decoder
}

// NewOwnerRefMutator constructs a ready-to-register webhook handler.
func NewOwnerRefMutator(c client.Client) *OwnerRefMutator {
	return &OwnerRefMutator{Client: c}
}

// Handle implements the admission.Handler interface.
func (m *OwnerRefMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := logf.FromContext(ctx).WithValues(
		"component", "owner-ref-mutator",
		"kind", req.Kind.Kind,
		"namespace", req.Namespace,
		"name", req.Name,
	)

	// Only handle CREATE.
	if req.Operation != "CREATE" {
		return admission.Allowed("not a CREATE; no-op")
	}

	// Parse just enough of the object to read/set ownerReferences. We
	// avoid decoding into the typed CR to keep this handler independent of
	// the api/v1alpha1 version specifics.
	var obj struct {
		Metadata metav1.ObjectMeta `json:"metadata"`
	}
	if err := json.Unmarshal(req.Object.Raw, &obj); err != nil {
		log.Info("decode failed; allowing", "err", err)
		return admission.Allowed("").WithWarnings(
			fmt.Sprintf("owner-ref-mutator: decode failed: %v", err),
		)
	}

	// If ownerRef is already set, nothing to do.
	if len(obj.Metadata.OwnerReferences) > 0 {
		return admission.Allowed("ownerReferences already present")
	}

	// Resolve parent Tenant from the namespace annotation.
	ref, err := controller.ResolveTenantOwnerRef(ctx, m.Client, req.Namespace)
	if err != nil {
		log.Info("parent resolution failed; allowing", "err", err)
		return admission.Allowed("").WithWarnings(
			fmt.Sprintf("owner-ref-mutator: parent resolution failed: %v", err),
		)
	}
	if ref == nil {
		return admission.Allowed("no parent tenant resolvable; reconciler will backfill")
	}

	// Patch: add ownerReferences to metadata. Using JSON Patch because
	// admission.Response's expected patch format is JSON Patch, not merge.
	patch := []map[string]any{
		{
			"op":    "add",
			"path":  "/metadata/ownerReferences",
			"value": []metav1.OwnerReference{*ref},
		},
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		log.Info("patch marshal failed; allowing", "err", err)
		return admission.Allowed("").WithWarnings(
			fmt.Sprintf("owner-ref-mutator: patch marshal failed: %v", err),
		)
	}

	patchType := admissionPatchTypeJSONPatch()
	return admission.Response{
		AdmissionResponse: admissionResponseAllowedWithPatch(raw, patchType),
	}
}

// InjectDecoder satisfies admission.DecoderInjector for controller-runtime
// versions that use injection; harmless on newer versions.
func (m *OwnerRefMutator) InjectDecoder(d admission.Decoder) error {
	m.decoder = d
	return nil
}

// HandlerWebhook returns the admission.Webhook ready to be registered on
// the manager's webhook server at the desired path.
func HandlerWebhook(c client.Client) *admission.Webhook {
	return &admission.Webhook{Handler: NewOwnerRefMutator(c)}
}

// MutatePath is the URL path the MutatingWebhookConfiguration references.
const MutatePath = "/mutate-owner-ref"

// unused keeps net/http import for future predicates.
var _ = http.StatusOK
