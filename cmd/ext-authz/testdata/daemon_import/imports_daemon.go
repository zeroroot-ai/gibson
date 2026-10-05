// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fixture is the failing fixture of TestNoDaemonImport. It imports the
// daemon, so the guard must flag it. The directory testdata keeps it out of
// the build.
package fixture

import (
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon"
)
