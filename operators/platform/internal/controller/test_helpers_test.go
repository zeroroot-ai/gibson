/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ctrlRequest builds a controller-runtime Request from a NamespacedName.
func ctrlRequest(nn types.NamespacedName) ctrl.Request {
	return ctrl.Request{NamespacedName: nn}
}
