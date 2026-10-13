// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e proves the tenant-operator of the checkout on an installed
// platform. The exit test exit-test-e2e-cluster builds the operator image from
// the checkout, points the chart-installed tenant-operator at it, and runs this
// suite against the current kube context.
//
// There is no second deploy path (ADR-0027). The suite used to deploy its own
// manager with stub env values into a cluster of its own. That manager had no
// SPIRE identity, so it could not dial the daemon and never started, and each
// run showed only the first missing value (gibson#1142). The chart is the one
// way the operator runs.
package e2e

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "tenant-operator e2e suite")
}
