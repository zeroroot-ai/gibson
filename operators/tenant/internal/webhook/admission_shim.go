// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package webhook

import (
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/ptr"
)

func admissionPatchTypeJSONPatch() *admissionv1.PatchType {
	t := admissionv1.PatchTypeJSONPatch
	return &t
}

// admissionResponseAllowedWithPatch returns a raw admission response that
// encodes the provided JSON patch. Extracted so the handler file stays
// free of admission/v1 boilerplate.
func admissionResponseAllowedWithPatch(patch []byte, t *admissionv1.PatchType) admissionv1.AdmissionResponse {
	return admissionv1.AdmissionResponse{
		Allowed:   true,
		Patch:     patch,
		PatchType: t,
	}
}

// unused silences linters when ptr is imported only conditionally.
var _ = ptr.To[bool]
