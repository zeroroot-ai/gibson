# Changelog

## [0.136.0](https://github.com/zeroroot-ai/gibson/compare/v0.135.1...v0.136.0) (2026-09-11)


### ⚠ BREAKING CHANGES

* **llm:** llm.providers and llm.default_provider in gibson.yaml are no longer read, and GIBSON_DEV_ENV_FALLBACK no longer exists. A provider config with no credential of its own is rejected; the daemon's environment is never a credential.

### Features

* **llm:** no platform LLM credential ([#100](https://github.com/zeroroot-ai/gibson/issues/100)) ([4c65730](https://github.com/zeroroot-ai/gibson/commit/4c6573076edb0ddb1d4ed9e717787df6ba81d891))

## [0.135.1](https://github.com/zeroroot-ai/gibson/compare/v0.135.0...v0.135.1) (2026-09-09)


### Bug Fixes

* **tenant-operator:** take the Neo4j password from the restored store before minting one ([#96](https://github.com/zeroroot-ai/gibson/issues/96)) ([bc3b209](https://github.com/zeroroot-ai/gibson/commit/bc3b20964914b71a81d3364a40d239fd486b5594))

## Changelog

This repository restarted from a fresh baseline on 2026-09-06. Release notes before that date are archived offline and do not resolve on GitHub. release-please adds each release below this line.
