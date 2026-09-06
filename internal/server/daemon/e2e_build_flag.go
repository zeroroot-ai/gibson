// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

// isTestFixturesBuild reports whether this binary was built with
// -tags=test_fixtures. Used by tests that must assert different things about a
// production build than about a test build.
const isTestFixturesBuild = true
