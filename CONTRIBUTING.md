# Contributing to `gibson`

This is the platform monorepo: the daemon, the ext-authz service, three operators and the SPIFFE/JWKS sidecar, in one Go module.

If anything here is unclear, open an issue rather than guessing — an unclear
contributing guide is a bug in this file.

## Prerequisites

- Go 1.26+ (the `go.mod` toolchain directive is authoritative)
- `make`, `docker`, `kubectl`
- A kind cluster for the end-to-end suites; unit tests need none.

## Build and test

```sh
make bin          # build
make test-race    # tests under the race detector
make check        # the full local gate
```

## The merge gate

`make check` is not just tests. It runs a set of invariant guards, each of which
exists because that bug reached main once:

- `check-no-tenant-id` — **no cross-tenant identifiers.** World, timeline, reducer and knowledge graph are per-tenant and fully isolated. Anything spanning tenants is the most serious class of defect in this repo.
- `check-fga-headers` — authorization headers present where required
- `check-no-skipped-tests` — a skipped test is not a passing test
- `check-no-mcp-bridge`, `check-noun-contract`, `check-build-tags`, and others

The authz registry is generated: run `make authz-registry`, never hand-edit it.

Every pull request runs it. A red gate is a real signal: **do not** disable a
guard to get a PR through. If a guard is wrong, fix the guard in the same PR
and say why — a guard that needs re-pinning after an unrelated edit is a defect
in the guard.

## Pull requests

- **Conventional Commits in the PR title** — `feat:`, `fix:`, `chore:`,
  `docs:`, `ci:`, `test:`, `refactor:`. The subject must start lowercase;
  `pr-title-lint` enforces both.
- **One root cause per PR.** Two unrelated fixes are two pull requests.
- **Rebase, never merge.** `git fetch origin && git rebase origin/main`
- Releases are automatic via release-please. Never hand-tag, never hand-edit a
  version.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

**Elastic License 2.0** — see [LICENSE](LICENSE). Read it, download it, run it, modify it; do not offer it to third parties as a hosted or managed service. GitHub shows this repo as "NOASSERTION" because ELv2 is not OSI-approved. The surface you build against — [`sdk`](https://github.com/zeroroot-ai/sdk) and [`adk`](https://github.com/zeroroot-ai/adk) — is Apache-2.0, and what you write with them is yours.
