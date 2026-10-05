// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package operatorrbac holds the guard that keeps each operator's generated
// ClusterRole (operators/<name>/config/rbac/role.yaml) equal to the
// +kubebuilder:rbac markers in that operator's code.
//
// Two defects reached a release without it:
//
//   - The platform operator's 13 markers stood in the doc comment of each
//     reconciler type. controller-gen reads a marker only from a comment that
//     belongs to no type, so it ignored all of them, and no role.yaml existed.
//   - The chart's hand-written ClusterRole for the tenant operator lacked two
//     rules that the code had gained. A fresh install hung with the pod
//     Running and Ready (charts 0.136.5). The chart now compares its
//     ClusterRole with role.yaml, which is only as true as this guard keeps it.
//
// The guard is a test (rbac_test.go), so it runs in the unit lane. It does not
// need controller-gen: it reads the markers with go/parser and compares the
// (group, resource, verb) set with the rules in role.yaml.
package operatorrbac
