// Package vaulttool is in an allowlisted path (/cmd/). The OpenFGA and
// Zitadel rule does not apply here, but the Vault client rule applies to
// every package (gibson#686).
package vaulttool

import (
	_ "github.com/hashicorp/vault/api" // want `forbidden import "github.com/hashicorp/vault/api" in "allowed/cmd/vaulttool": gibson talks to OpenBao`
	_ "github.com/zitadel/oidc/v3/pkg/client"
)
