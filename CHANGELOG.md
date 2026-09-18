# Changelog

## [0.137.0](https://github.com/zeroroot-ai/gibson/compare/v0.136.0...v0.137.0) (2026-09-18)


### Features

* **tenant-operator:** bind the daemon's connector-credential write into each tenant namespace ([#137](https://github.com/zeroroot-ai/gibson/issues/137)) ([b0178b6](https://github.com/zeroroot-ai/gibson/commit/b0178b60fbd19c744a3fd3019b3199d5ae4be35a))
* **tenant-operator:** per-tenant neo4j is sized by the chart, not by a dev default ([#114](https://github.com/zeroroot-ai/gibson/issues/114)) ([d6ba91c](https://github.com/zeroroot-ai/gibson/commit/d6ba91cf4d8a929123e4fa43db5114c5dcfca55e))


### Bug Fixes

* **belief:** refresh the distroless base off the stale pinned digest ([#120](https://github.com/zeroroot-ai/gibson/issues/120)) ([1c60e81](https://github.com/zeroroot-ai/gibson/commit/1c60e81e1108548a39a5641aa9e437a3aa2a4ab7))
* **catalog:** pin both zerocool agent images to a build the release policy verifies ([#126](https://github.com/zeroroot-ai/gibson/issues/126)) ([5ad07ca](https://github.com/zeroroot-ai/gibson/commit/5ad07cad38a329ce5cfbe85039edc0d549dcdef4))
* **ci:** e2e-setec-roundtrip sweeps stale throwaway SandboxClasses at run start ([#139](https://github.com/zeroroot-ai/gibson/issues/139)) ([4be932e](https://github.com/zeroroot-ai/gibson/commit/4be932e6e103172eee618f37ae940e0ec58b0419)), closes [#27](https://github.com/zeroroot-ai/gibson/issues/27)
* **ci:** pin every zeroroot-ai/.github reference to v0.5.1 ([#129](https://github.com/zeroroot-ai/gibson/issues/129)) ([6e686dd](https://github.com/zeroroot-ai/gibson/commit/6e686ddf4ff595a2aaa0a47a7bfa46224b815a05))
* **ci:** pin the org tree guards to a commit SHA ([#110](https://github.com/zeroroot-ai/gibson/issues/110)) ([733f4d9](https://github.com/zeroroot-ai/gibson/commit/733f4d950e98f731c36970001891dd719766da08))
* **ci:** the cluster exit tests name the CI rung ([#113](https://github.com/zeroroot-ai/gibson/issues/113)) ([84f8915](https://github.com/zeroroot-ai/gibson/commit/84f89155f1f4fcf87b161999c0f93cc7bd6f8dfb))
* **ci:** the exit tests name the baseline profile, not vanilla ([#112](https://github.com/zeroroot-ai/gibson/issues/112)) ([0ff4279](https://github.com/zeroroot-ai/gibson/commit/0ff4279cb347e666592d254a2a5749877bcd5139))
* **ci:** unbreak the image build ([#119](https://github.com/zeroroot-ai/gibson/issues/119)) ([61f3c62](https://github.com/zeroroot-ai/gibson/commit/61f3c626a5cb4e17ffef187b3141ec2fc691c58f))
* **connectorauth:** the vendor client refuses private addresses and plaintext ([#136](https://github.com/zeroroot-ai/gibson/issues/136)) ([7c463a6](https://github.com/zeroroot-ai/gibson/commit/7c463a6ce2b38e7dbc82faf32f4f0dec8d8eda2d))
* **ext-authz:** a machine user's token is a machine credential ([#138](https://github.com/zeroroot-ai/gibson/issues/138)) ([4c53e54](https://github.com/zeroroot-ai/gibson/commit/4c53e54073e59ff57efeea6085d2c0791d4261bc))
* **images:** apply Alpine security updates in the two runtime stages ([#121](https://github.com/zeroroot-ai/gibson/issues/121)) ([8d4ec36](https://github.com/zeroroot-ai/gibson/commit/8d4ec367008934750c84d030fdf2912c256e4e89))
* **state:** a required tenant is never answered by the default ([#134](https://github.com/zeroroot-ai/gibson/issues/134)) ([abba9a6](https://github.com/zeroroot-ai/gibson/commit/abba9a62f71a6fc82ffa50c3148865350d63425d))
* **vector:** the tenant-scoped store searches only its own tenant ([#135](https://github.com/zeroroot-ai/gibson/issues/135)) ([e4ec911](https://github.com/zeroroot-ai/gibson/commit/e4ec911ecb921c4cc938db098f6db58fc64e225d))

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
