// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ctrlRequest builds a controller-runtime Request from a NamespacedName.
func ctrlRequest(nn types.NamespacedName) ctrl.Request {
	return ctrl.Request{NamespacedName: nn}
}
