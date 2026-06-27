// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ctrlRequest builds a controller-runtime Request from a NamespacedName.
func ctrlRequest(nn types.NamespacedName) ctrl.Request {
	return ctrl.Request{NamespacedName: nn}
}
