// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vault

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

// clientTimeout bounds every Vault HTTP call, including the login and the
// mount probe performed at construction time.
const clientTimeout = 15 * time.Second

// buildClient constructs and authenticates a Vault API client from the given
// Config. It sets the address, optional namespace (Vault Enterprise), and
// performs the initial auth login. It does NOT verify KV version — that is
// done by the Provider constructor after buildClient returns.
//
// When cfg was produced by NewGuarded, the client's dialer carries the
// netguard egress guard — see installEgressGuard.
func buildClient(ctx context.Context, cfg Config) (*api.Client, error) {
	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = cfg.Address
	vaultCfg.Timeout = clientTimeout
	if cfg.guardEgress {
		installEgressGuard(vaultCfg)
	}

	client, err := api.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to create client: %w", err)
	}

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	if err := authenticate(ctx, client, cfg.Auth); err != nil {
		return nil, err
	}

	return client, nil
}

// installEgressGuard puts the netguard connect-time egress guard on the
// dialer the Vault client uses, so a connection to a loopback, link-local
// (including the cloud metadata service), private, CGNAT or reserved address
// is refused before connect(2) rather than after a response comes back.
//
// Connect-time is the only placement that holds. The address is vetted after
// DNS resolution, on every connection the client opens — so a name that
// resolves to a public address at validation time and to an internal one at
// connect time (DNS rebinding), and a public endpoint that answers with a
// redirect to an internal one, both land on the same check. A URL-shape or
// resolve-then-check test catches neither.
//
// The guard is layered onto api.DefaultConfig's HTTP client rather than
// replacing it, so the TLS settings that DefaultConfig derives from the
// environment survive. If the transport is not the stock *http.Transport
// (a future api change), the whole client is replaced with a guarded one:
// losing environment TLS tuning is acceptable, silently losing the guard is
// not.
func installEgressGuard(vaultCfg *api.Config) {
	const allowPrivate = false
	if vaultCfg.HttpClient != nil {
		if tr, ok := vaultCfg.HttpClient.Transport.(*http.Transport); ok {
			tr.DialContext = netguard.Dialer(allowPrivate).DialContext
			return
		}
	}
	vaultCfg.HttpClient = netguard.HTTPClient(clientTimeout, allowPrivate)
}

// detectKVVersion probes the mount at mountPath and returns an error when
// the mount is absent, not KV-typed, or KV v1. Uses
// `sys/internal/ui/mounts/<mountPath>` — the per-mount info endpoint that
// returns the same `options.version` data as the privileged `sys/mounts`
// list endpoint but requires only read-on-the-mount capability (no
// cross-mount enumeration).
//
// Namespace restriction: in OpenBao/Vault child namespaces, this endpoint
// is root-restricted — no policy grant (including explicit
// `sys/internal/ui/mounts/*` with `capabilities = ["read"]`) can make it
// accessible to a non-root token. Callers using namespace mode
// (Config.Namespace != "") MUST skip this check; New and NewWithRefresher
// do so automatically. The operator always provisions KV v2 in namespace
// mode, so the check is redundant there and was never reachable in the
// production deployment.
//
// Slice 4 of the OpenBao migration (PRD deploy#431, ADR-0024) narrowed
// this from `sys/mounts` so the SDK never requires a per-tenant token to
// grant cross-mount enumeration. Previous shape used
// client.Sys().ListMountsWithContext() and broke any tenant whose ACL
// policy did not include sys/mounts:read — which was every production
// tenant policy.
//
// Endpoint reference:
//   - Vault: https://developer.hashicorp.com/vault/api-docs/system/internal-ui-mounts
//   - OpenBao: https://openbao.org/api-docs/system/internal-ui-mounts.html
//
// Both declare it "unstable" but the response shape has been stable in
// practice for years. We accept the API risk in exchange for the
// policy-narrowing benefit. If the endpoint signature ever changes,
// this function is the single update site.
//
// KV v2 detection: the response's `data.options.version` is "2"; "1" or
// missing version with a "kv" type indicates a KV v1 mount that the SDK
// rejects (only KV v2 is supported by the rest of the provider's path
// construction).
func detectKVVersion(ctx context.Context, client *api.Client, mountPath string) error {
	resp, err := client.Logical().ReadWithContext(ctx, "sys/internal/ui/mounts/"+mountPath)
	if err != nil {
		return fmt.Errorf("vault: unable to read mount info for %q (check read permission on the mount path): %w", mountPath, err)
	}
	if resp == nil || resp.Data == nil {
		return fmt.Errorf("vault: KV mount %q not found at sys/internal/ui/mounts; verify the mount exists and the auth token can read it", mountPath)
	}

	mountType, _ := resp.Data["type"].(string)
	if mountType == "" {
		return fmt.Errorf("vault: mount info for %q missing type field; response: %v", mountPath, resp.Data)
	}
	if mountType != "kv" {
		return fmt.Errorf("vault: mount %q has type %q; expected \"kv\" (KV v2)", mountPath, mountType)
	}

	if optsRaw, ok := resp.Data["options"]; ok && optsRaw != nil {
		if opts, _ := optsRaw.(map[string]interface{}); opts != nil {
			if v, _ := opts["version"].(string); v == "1" {
				return fmt.Errorf(
					"vault: mount %q is KV v1; only KV v2 is supported (re-mount or create a new KV v2 mount)",
					mountPath,
				)
			}
		}
	}

	return nil
}
