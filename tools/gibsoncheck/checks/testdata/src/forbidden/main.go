// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package forbidden

import (
	_ "github.com/zitadel/oidc/v3/pkg/client" // want `forbidden import "github.com/zitadel/oidc/v3/pkg/client"`
)
