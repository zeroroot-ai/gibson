// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package health implements readyz probes for every downstream subsystem the
// operator depends on. Each ping function accepts a narrow interface so tests
// can inject fakes without importing the concrete client packages.
package health
