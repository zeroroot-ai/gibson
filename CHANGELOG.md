# Changelog

## [0.138.0](https://github.com/zeroroot-ai/gibson/compare/v0.137.0...v0.138.0) (2026-09-21)


### Features

* **catalog:** an agent manifest carries the static environment its sandbox needs ([#186](https://github.com/zeroroot-ai/gibson/issues/186)) ([c327bf2](https://github.com/zeroroot-ai/gibson/commit/c327bf25548ab387121769c0b9bd92484c73bc28)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **component:** stream secret revocation and rotation to the running plugin ([#157](https://github.com/zeroroot-ai/gibson/issues/157)) ([2899438](https://github.com/zeroroot-ai/gibson/commit/2899438625adf46481cf5db4bd928d45174d76ec))
* **daemon:** the neo4j apoc contract is verified on readiness and rendered for version-links ([#198](https://github.com/zeroroot-ai/gibson/issues/198)) ([05318e5](https://github.com/zeroroot-ai/gibson/commit/05318e5d74bb38179d39543a71dd9b6a87b20e8b))
* **sandbox:** every sandboxed launch is handed the platform's edge CA ([#184](https://github.com/zeroroot-ai/gibson/issues/184)) ([26dc214](https://github.com/zeroroot-ai/gibson/commit/26dc2140f454893bd1c0be34ab78c8295a75e4d4)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)


### Bug Fixes

* **admin:** the plugin admin surface reads the install's principal and heartbeated status ([#199](https://github.com/zeroroot-ai/gibson/issues/199)) ([06d6055](https://github.com/zeroroot-ai/gibson/commit/06d60556f1fb6b8a5245bc669f26bce092dd0267)), closes [#154](https://github.com/zeroroot-ai/gibson/issues/154)
* **backup:** keep the postgres password off the pg_dump argv ([#147](https://github.com/zeroroot-ai/gibson/issues/147)) ([a1781d8](https://github.com/zeroroot-ai/gibson/commit/a1781d801873b2a57e7eed85a4efd462e96d324e))
* **backup:** validate cypher labels and types before the restore query ([#146](https://github.com/zeroroot-ai/gibson/issues/146)) ([cd6eecb](https://github.com/zeroroot-ai/gibson/commit/cd6eecbb2ffda57739d266b43fcf82a76c1896d5))
* **bank:** a launching member gets a launch timeout, not the heartbeat timeout ([#179](https://github.com/zeroroot-ai/gibson/issues/179)) ([fb941aa](https://github.com/zeroroot-ai/gibson/commit/fb941aa47e48002e9ff3954ccba31e69507c883b)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **belief:** bind loopback and keep exception text out of the response ([#150](https://github.com/zeroroot-ai/gibson/issues/150)) ([0364a0f](https://github.com/zeroroot-ai/gibson/commit/0364a0f148c6fefc29884db478d64c13b0b901fb))
* **catalog:** claude-member 0.4.3, which sends mission_run_id itself ([#193](https://github.com/zeroroot-ai/gibson/issues/193)) ([a17fe19](https://github.com/zeroroot-ai/gibson/commit/a17fe1900b1d1dd9c8bc572dd397687ce687b39b)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **catalog:** the claude agent runs claude-member 0.4.0, which trusts the platform CA ([#185](https://github.com/zeroroot-ai/gibson/issues/185)) ([e01de4d](https://github.com/zeroroot-ai/gibson/commit/e01de4de200179d1f715dc59521dd4ba5373bca8)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **catalog:** the claude agent runs claude-member 0.4.1 ([#187](https://github.com/zeroroot-ai/gibson/issues/187)) ([f6474c0](https://github.com/zeroroot-ai/gibson/commit/f6474c0fd51d7815aefb57702379547e587e6391)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **catalog:** the claude agent runs claude-member 0.4.2 ([#192](https://github.com/zeroroot-ai/gibson/issues/192)) ([6bf04f2](https://github.com/zeroroot-ai/gibson/commit/6bf04f2667db6fbadd67724be55ee98dfc8d4529)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **ci:** test containers pull from the org mirror, not docker hub ([#145](https://github.com/zeroroot-ai/gibson/issues/145)) ([446290a](https://github.com/zeroroot-ai/gibson/commit/446290ae31fe5b4c2fa67f0b7804251de2011b2a))
* **ci:** the agent exit tests give sandboxes a path to the platform on kind ([#181](https://github.com/zeroroot-ai/gibson/issues/181)) ([70355e3](https://github.com/zeroroot-ai/gibson/commit/70355e31793409be3b8749fed0597d8258363316)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **ci:** the bank exit test collects sandbox logs while the suite runs ([#180](https://github.com/zeroroot-ai/gibson/issues/180)) ([f7122d0](https://github.com/zeroroot-ai/gibson/commit/f7122d0431851804a5a8dc4cfd9ab3989ae6907c)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **ci:** the exit tests stop setting a fixture flag through a seam the chart never had ([#171](https://github.com/zeroroot-ai/gibson/issues/171)) ([0b30d0a](https://github.com/zeroroot-ai/gibson/commit/0b30d0a16143b04c6720f0c1686d383d6da761da)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **ci:** the exit-test runner's peer id lands on the chart key the daemon reads ([#161](https://github.com/zeroroot-ai/gibson/issues/161)) ([3bc11de](https://github.com/zeroroot-ai/gibson/commit/3bc11de4345472826c16cbfad4ae75d783d202ff)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **ci:** the in-cluster exit tests get 90 minutes and always print diagnostics ([#160](https://github.com/zeroroot-ai/gibson/issues/160)) ([98cf5b9](https://github.com/zeroroot-ai/gibson/commit/98cf5b94c5009bab6c1a19a8ff38684d19cedc5a)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **ci:** the in-cluster exit tests run when the schema or the entitlements reader changes ([#175](https://github.com/zeroroot-ai/gibson/issues/175)) ([add5498](https://github.com/zeroroot-ai/gibson/commit/add5498c2ce690a2dada688bc478e3f85029f93b)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **ci:** the tool-dispatch exit test finishes the run it started ([#151](https://github.com/zeroroot-ai/gibson/issues/151)) ([b7acf03](https://github.com/zeroroot-ai/gibson/commit/b7acf0322f5f0fcd67a9bd5b391ddc4c020c10b0))
* **ci:** the tool-dispatch exit test prints why a pod is not ready when it fails ([#143](https://github.com/zeroroot-ai/gibson/issues/143)) ([cc60821](https://github.com/zeroroot-ai/gibson/commit/cc608210c521d4f75f8fbc4e0a4bb0420d499908)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **daemon:** a bank's owner and a job's opener are the users the checks read ([#176](https://github.com/zeroroot-ai/gibson/issues/176)) ([d9d1e70](https://github.com/zeroroot-ai/gibson/commit/d9d1e70cae5fe61640acb1607e8c6184b0471d42)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **daemon:** a tenant-owned bank is one every tenant member may send to and read ([#177](https://github.com/zeroroot-ai/gibson/issues/177)) ([e6c1191](https://github.com/zeroroot-ai/gibson/commit/e6c1191ee9668e428b2e2e57a5a3fcb4b1805b40)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **daemon:** every registered tenant is enabled on the system backplane ([#201](https://github.com/zeroroot-ai/gibson/issues/201)) ([4031716](https://github.com/zeroroot-ai/gibson/commit/4031716adc6974e8f6b622b5c9ccbcb80e89630e)), closes [#154](https://github.com/zeroroot-ai/gibson/issues/154)
* **daemon:** the exit-test runner is a member of the platform tenant in the fixture build ([#168](https://github.com/zeroroot-ai/gibson/issues/168)) ([0227d76](https://github.com/zeroroot-ai/gibson/commit/0227d76a25eb8930085ba14e9338958740f9773e))
* **daemon:** the exit-test runner may call the bank, job and provider RPCs ([#172](https://github.com/zeroroot-ai/gibson/issues/172)) ([5a99169](https://github.com/zeroroot-ai/gibson/commit/5a99169b54004292044f36453749277f72f3e61c)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **daemon:** the harness credential store reads the colon-flat root layout ([#202](https://github.com/zeroroot-ai/gibson/issues/202)) ([7b2726f](https://github.com/zeroroot-ai/gibson/commit/7b2726f7131a4eb9479a8ef6d872e8215eca81a9)), closes [#154](https://github.com/zeroroot-ai/gibson/issues/154)
* **daemon:** the lifecycle projector publishes events in timeline order ([#167](https://github.com/zeroroot-ai/gibson/issues/167)) ([639fe19](https://github.com/zeroroot-ai/gibson/commit/639fe1998116ace59b1ee59a7a558791cacc22d2))
* **daemon:** the member launch speaks the driver's login-shape vocabulary ([#178](https://github.com/zeroroot-ai/gibson/issues/178)) ([aaf1ed2](https://github.com/zeroroot-ai/gibson/commit/aaf1ed2649e335c45e9b82c76833c0af8b4286df))
* **daemon:** the terminal status reaches the mission stream, and the suite reads it ([#165](https://github.com/zeroroot-ai/gibson/issues/165)) ([c04e1c9](https://github.com/zeroroot-ai/gibson/commit/c04e1c98bb69a961ba3048d48419a0a0e17bd8d4)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **e2e:** a failed happy path names the node's reason ([#170](https://github.com/zeroroot-ai/gibson/issues/170)) ([a40209f](https://github.com/zeroroot-ai/gibson/commit/a40209fea7fd5cdbc82a2ee93a7f88ed03b74f68)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **e2e:** the bank suite runs in the provisioned tenant ([#173](https://github.com/zeroroot-ai/gibson/issues/173)) ([239af24](https://github.com/zeroroot-ai/gibson/commit/239af24deb4cbc4dc64e38e708d24cfa8a9e8f7d)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **e2e:** the runner dials the daemon over mTLS from the socket the chart mounts ([#155](https://github.com/zeroroot-ai/gibson/issues/155)) ([3ea5e26](https://github.com/zeroroot-ai/gibson/commit/3ea5e26b72390942700bdf3edaab29e0d8ee08a5)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **e2e:** the runner's tenant reaches the daemon ([#162](https://github.com/zeroroot-ai/gibson/issues/162)) ([6269727](https://github.com/zeroroot-ai/gibson/commit/6269727f34ffac2f1df74b5bf80cc9c4d967eb42))
* **e2e:** the suite creates its target through the API and sees the daemon's status ([#164](https://github.com/zeroroot-ai/gibson/issues/164)) ([4b666cd](https://github.com/zeroroot-ai/gibson/commit/4b666cd7d91fba63c2842a5a0f79a5008f5b5177)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **e2e:** the suite runs against its target and a denial is the gate's, not any error ([#163](https://github.com/zeroroot-ai/gibson/issues/163)) ([38f2435](https://github.com/zeroroot-ai/gibson/commit/38f24354a5564d7606553995c02ebeec02d7cac9)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **e2e:** the verdict reads the node's failure reason, and diagnostics keep more daemon log ([#166](https://github.com/zeroroot-ai/gibson/issues/166)) ([43555da](https://github.com/zeroroot-ai/gibson/commit/43555dab804dc8345d8db9d1c38a107256d9441e)), closes [#14](https://github.com/zeroroot-ai/gibson/issues/14)
* **harness:** a member is identified by the run its grant names ([#188](https://github.com/zeroroot-ai/gibson/issues/188)) ([e7eb5dc](https://github.com/zeroroot-ai/gibson/commit/e7eb5dcf6b52d952030de1dd2f60f5727c18582e)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **migrations:** tenant_quotas carries concurrent_connectors in the migration set ([#174](https://github.com/zeroroot-ai/gibson/issues/174)) ([d4e40e6](https://github.com/zeroroot-ai/gibson/commit/d4e40e68d15c4861983422d011578d5ecbd015b6))
* **rework:** the agent exit tests reach the platform by selector, not by ClusterIP ([#182](https://github.com/zeroroot-ai/gibson/issues/182)) ([39f7690](https://github.com/zeroroot-ai/gibson/commit/39f7690e4c88111b6edc0e253934e401ce2f2503)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **rework:** the Envoy allowance selects the Envoy pods by the chart's labels ([#183](https://github.com/zeroroot-ai/gibson/issues/183)) ([60ccd93](https://github.com/zeroroot-ai/gibson/commit/60ccd9327492c4a66335b1e61a0db7f99318a55e)), closes [#13](https://github.com/zeroroot-ai/gibson/issues/13)
* **sandbox:** hand the member process the gvisor marker ([#153](https://github.com/zeroroot-ai/gibson/issues/153)) ([7860264](https://github.com/zeroroot-ai/gibson/commit/78602644b3dd7c4c32b723428346068e6bb09777)), closes [#152](https://github.com/zeroroot-ai/gibson/issues/152)
* **security:** delete dead authz code that comments said was live ([#149](https://github.com/zeroroot-ai/gibson/issues/149)) ([0200677](https://github.com/zeroroot-ai/gibson/commit/0200677ef160f192a72ec89af3a5435b4f629c98))
* **security:** no default credentials in code or the example env ([#148](https://github.com/zeroroot-ai/gibson/issues/148)) ([ce8ef0c](https://github.com/zeroroot-ai/gibson/commit/ce8ef0ce90278bd06d9715aab4aeb40bb72ea0cd))
* **tenant-operator:** postgres deprovision terminates the tenant's backends before the drop ([#140](https://github.com/zeroroot-ai/gibson/issues/140)) ([7a4b6ee](https://github.com/zeroroot-ai/gibson/commit/7a4b6eedfa8f05afd6d23c73a230c41183261658))

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
