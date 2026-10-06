# The platform component catalog

The catalog is the set of manifests in `manifests/`. The `gibson` binary embeds them (`catalog.go`, `//go:embed manifests/*.yaml`). The embedded catalog is the one source of each connector, tool, agent and plugin that the platform offers (ADR-0136, ADR-0065 rule R6). No other repo holds a copy, and no code syncs a copy.

## How a new connector reaches a running platform

1. Write one manifest in `manifests/<id>.yaml` with `kind: connector`. A connector has no handler code and no image build.
2. Open a pull request in `gibson`. The catalog loader validates the manifest in the tests (`catalog_test.go`).
3. Merge the pull request. The next `gibson` release embeds the manifest.
4. Upgrade the daemon to that release. At start, the daemon seeds the `platform_enabled` tuple of each catalog entry, and removes the tuple of an entry that left the catalog.

A new or changed connector thus needs a `gibson` release (owner decision of 2026-10-05, gibson#727). A signed catalog file outside `gibson` can come later, if on-prem customers need new connectors faster than they upgrade the daemon.

## A Hosted vendor connector

A `Hosted` connector runs as a pod with an image reference (ADR-0114, ADR-0136).

- The manifest names the image of the vendor in the registry of the vendor, pinned by digest. The catalog loader refuses a Hosted image with no digest.
- Nothing is mirrored, and nothing is signed again.
- The platform owner approves the connector when the manifest pull request merges. The catalog entry is that approval.

## A first-party plugin

A plugin in `plugins/<name>/` of this repo is its own Go module. The image workflow builds and signs its image, and writes the digest into its manifest through a pull request (gibson#790). No person edits that image line.
