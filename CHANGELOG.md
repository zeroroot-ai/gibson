# Changelog

## [0.157.0](https://github.com/zeroroot-ai/gibson/compare/v0.156.0...v0.157.0) (2026-10-07)


### Features

* **platform-operator:** rotate the Zitadel admin and login-client tokens, and retire the old ones ([#1042](https://github.com/zeroroot-ai/gibson/issues/1042)) ([de1c62f](https://github.com/zeroroot-ai/gibson/commit/de1c62fd7893f08f1f3404da668cddfd384c3ed1))


### Bug Fixes

* **audit:** a delete keeps its pending records in a ConfigMap, and a drift repair gets a record ([#1044](https://github.com/zeroroot-ai/gibson/issues/1044)) ([777495d](https://github.com/zeroroot-ai/gibson/commit/777495d3e8bfb4e576a4a861548bd574b93b7753))
* **capabilitygrant:** a host with an unknown capability ceiling is refused ([#1040](https://github.com/zeroroot-ai/gibson/issues/1040)) ([4a55897](https://github.com/zeroroot-ai/gibson/commit/4a55897d6d7fbc2721b199eff0e376690e97bd9b))
* **diff-coverage:** a trailing comment counts only where the scanner sees one ([#1022](https://github.com/zeroroot-ai/gibson/issues/1022)) ([981dec9](https://github.com/zeroroot-ai/gibson/commit/981dec91b1cf94770cdc45fb8d7111418c8c0d56)), closes [#1017](https://github.com/zeroroot-ai/gibson/issues/1017)
* **harness:** a tool or plugin grant names the agent that dispatched it ([#1043](https://github.com/zeroroot-ai/gibson/issues/1043)) ([16273e8](https://github.com/zeroroot-ai/gibson/commit/16273e8e08af453ea95b9388ac3cf41b3bed5461))
* **members:** one role resolution for the member list and the caller ([#1012](https://github.com/zeroroot-ai/gibson/issues/1012)) ([017c97a](https://github.com/zeroroot-ai/gibson/commit/017c97a1a91e501505a88cfd080131a8741a386c))

## [0.156.0](https://github.com/zeroroot-ai/gibson/compare/v0.155.0...v0.156.0) (2026-10-07)


### Features

* **capabilitygrant:** the daemon reads a rotated signing key with no restart ([#1035](https://github.com/zeroroot-ai/gibson/issues/1035)) ([53020dd](https://github.com/zeroroot-ai/gibson/commit/53020dd0e01bb2d75a69f81370ab91661f529979))
* **daemon:** each error status carries an ErrorDetail ([#1009](https://github.com/zeroroot-ai/gibson/issues/1009)) ([260d548](https://github.com/zeroroot-ai/gibson/commit/260d548a772af28df378b8dbe22d4457146f4e82))
* **ext-authz:** serve metrics on a separate metrics-only port ([#1034](https://github.com/zeroroot-ai/gibson/issues/1034)) ([adbab10](https://github.com/zeroroot-ai/gibson/commit/adbab10c55921ab29f7a6c8f63f89a688c2f3983))
* **vaulttoken:** the platform-operator moves to a rotated OpenBao token at once ([#1037](https://github.com/zeroroot-ai/gibson/issues/1037)) ([c4a6cab](https://github.com/zeroroot-ai/gibson/commit/c4a6cab71c92e0828a0acd65e6c68cd1857870d4))


### Bug Fixes

* **audit:** listed state changes write their audit record first ([#1028](https://github.com/zeroroot-ai/gibson/issues/1028)) ([d7cd223](https://github.com/zeroroot-ai/gibson/commit/d7cd2231aaae466b48d5ef5cfd71cb222c15cd94))
* **callback:** a fork claim takes its tenant from the start record ([#1020](https://github.com/zeroroot-ai/gibson/issues/1020)) ([c64d5e1](https://github.com/zeroroot-ai/gibson/commit/c64d5e1dda0658447b8eb3de5c19a33b9e204d7e))
* **capabilitygrant:** a host re-registration keeps the bounds of its enrollment ([#1026](https://github.com/zeroroot-ai/gibson/issues/1026)) ([8000e17](https://github.com/zeroroot-ai/gibson/commit/8000e173a06c82ac708925a12397287979795206))
* **graph:** a duplicate node stops the schema retry and reports the tenant ([#1011](https://github.com/zeroroot-ai/gibson/issues/1011)) ([55fb2c2](https://github.com/zeroroot-ai/gibson/commit/55fb2c23a465303deb12f44687888bc2104dea8e))
* **harness:** a callback names only the agent of its grant ([#1027](https://github.com/zeroroot-ai/gibson/issues/1027)) ([2b328ad](https://github.com/zeroroot-ai/gibson/commit/2b328adcbf8dacc9d8084b419a35eeaa3478c9b1))
* **harness:** a fork node starts only from a node of the same agent ([#1025](https://github.com/zeroroot-ai/gibson/issues/1025)) ([b1e1eea](https://github.com/zeroroot-ai/gibson/commit/b1e1eeabc72a3261120034ec3f70fc63a85fd91e))
* **harness:** a restored or forked sandbox cannot use the grant of its source ([#1029](https://github.com/zeroroot-ai/gibson/issues/1029)) ([0ca7f99](https://github.com/zeroroot-ai/gibson/commit/0ca7f99b722efc0ce0c4769f401cc75bd31d68df))
* **invitations:** an invitation call writes nothing that it cannot mail ([#1013](https://github.com/zeroroot-ai/gibson/issues/1013)) ([e3fa104](https://github.com/zeroroot-ai/gibson/commit/e3fa1042f201e7edd94c6dbf8222da87d3b84e47))

## [0.155.0](https://github.com/zeroroot-ai/gibson/compare/v0.154.0...v0.155.0) (2026-10-07)


### Features

* **signup:** a pending registration states when it arrived ([#1008](https://github.com/zeroroot-ai/gibson/issues/1008)) ([f6ddc76](https://github.com/zeroroot-ai/gibson/commit/f6ddc76ad3b4a56b14ecc3fec14651ba428724b2)), closes [#620](https://github.com/zeroroot-ai/gibson/issues/620)

## [0.154.0](https://github.com/zeroroot-ai/gibson/compare/v0.153.2...v0.154.0) (2026-10-07)


### ⚠ BREAKING CHANGES

* end-phase integration of gibson ([#1001](https://github.com/zeroroot-ai/gibson/issues/1001))
* **platform-operator:** the PlatformBootstrap has no issuer field ([#933](https://github.com/zeroroot-ai/gibson/issues/933))
* **signup:** signup has one neutral external step, and the Stripe check leaves the platform ([#895](https://github.com/zeroroot-ai/gibson/issues/895))
* **daemon:** take sdk v0.196.0, list RPCs use page tokens, dead component RPCs leave ([#894](https://github.com/zeroroot-ai/gibson/issues/894))

### Features

* **adr:** add the public index of ADR numbers ([#833](https://github.com/zeroroot-ai/gibson/issues/833)) ([d88dff1](https://github.com/zeroroot-ai/gibson/commit/d88dff14490c68847cb2e0f72ee09958a5ba2d82))
* **audit:** export each audit record to the durable bucket ([#941](https://github.com/zeroroot-ai/gibson/issues/941)) ([6df34a8](https://github.com/zeroroot-ai/gibson/commit/6df34a82f5d49b46de2914faf7ff39d70e429d51)), closes [#764](https://github.com/zeroroot-ai/gibson/issues/764)
* **belief:** a new belief version becomes current only when it is not worse ([#929](https://github.com/zeroroot-ai/gibson/issues/929)) ([f1f796b](https://github.com/zeroroot-ai/gibson/commit/f1f796b69538e6f689ca49799aaf50391b31b9a6)), closes [#789](https://github.com/zeroroot-ai/gibson/issues/789)
* **belief:** the belief trainer fits the artifacts of one tenant from the World ([#926](https://github.com/zeroroot-ai/gibson/issues/926)) ([3a9decd](https://github.com/zeroroot-ai/gibson/commit/3a9decdad38a3f0ad506b8debaca75c824048eb1))
* **belief:** the daemon loads the belief version of each tenant ([#985](https://github.com/zeroroot-ai/gibson/issues/985)) ([847bd9a](https://github.com/zeroroot-ai/gibson/commit/847bd9ae2a732263e2ff78c5224a9567307dcd12))
* **belief:** the in-node strength and the leak are fitted posteriors ([#932](https://github.com/zeroroot-ai/gibson/issues/932)) ([15103bd](https://github.com/zeroroot-ai/gibson/commit/15103bd5b5b39aa1dd2e7a6fcfb52ba37f504116))
* **brain:** a rewind records its parent as a Timeline event ([#884](https://github.com/zeroroot-ai/gibson/issues/884)) ([5e02755](https://github.com/zeroroot-ai/gibson/commit/5e0275571b3db41c726789540326a0601aedf57d))
* **brain:** the destructive action record holds blast radius and reversibility ([#842](https://github.com/zeroroot-ai/gibson/issues/842)) ([0667fa7](https://github.com/zeroroot-ai/gibson/commit/0667fa70ecc66b23a1090d082975ca27b3aa7926))
* **brain:** the planner samples the in-node strength and the leak ([#948](https://github.com/zeroroot-ai/gibson/issues/948)) ([cf91dc1](https://github.com/zeroroot-ai/gibson/commit/cf91dc110b4ffba2deeab2e26678f1a5bd8f6c84)), closes [#931](https://github.com/zeroroot-ai/gibson/issues/931)
* **brain:** the planner uses real costs and a UCT search tree ([#843](https://github.com/zeroroot-ai/gibson/issues/843)) ([a5f9e2d](https://github.com/zeroroot-ai/gibson/commit/a5f9e2d081bd9d26863980779ccce375c804809b)), closes [#695](https://github.com/zeroroot-ai/gibson/issues/695)
* **brain:** the Timeline store factory returns an error ([#973](https://github.com/zeroroot-ai/gibson/issues/973)) ([04a6db0](https://github.com/zeroroot-ai/gibson/commit/04a6db041b66d51c8db3b1cea537d8503f6cb25f))
* **catalog:** a tenant can enable a catalog plugin ([#817](https://github.com/zeroroot-ai/gibson/issues/817)) ([14c62bd](https://github.com/zeroroot-ai/gibson/commit/14c62bdd443ab80e7a5a21348a84d8e25280ce6e))
* **catalog:** a tool, a plugin or an agent states its technique coverage ([#946](https://github.com/zeroroot-ai/gibson/issues/946)) ([e7fa814](https://github.com/zeroroot-ai/gibson/commit/e7fa814e2a562b6e487cdbf8cc086a0f2a3019e8)), closes [#716](https://github.com/zeroroot-ai/gibson/issues/716)
* **ci:** add the weekly report of the open issues ([#844](https://github.com/zeroroot-ai/gibson/issues/844)) ([4d4193f](https://github.com/zeroroot-ai/gibson/commit/4d4193f87764174ef14f1c126fba30ce439184d7))
* **compliance:** one read RPC returns the audit evidence for each control ([#886](https://github.com/zeroroot-ai/gibson/issues/886)) ([ceb8193](https://github.com/zeroroot-ai/gibson/commit/ceb8193e2c5c942c9f30af0f814a5615c717f5ff))
* **connector:** a table and a store for the connectors of each tenant ([#662](https://github.com/zeroroot-ai/gibson/issues/662)) ([#947](https://github.com/zeroroot-ai/gibson/issues/947)) ([bb29583](https://github.com/zeroroot-ai/gibson/commit/bb2958306eb1ad310de336956a98f0d303859345))
* **daemon:** a rewind starts a new run at a checkpoint ([#885](https://github.com/zeroroot-ai/gibson/issues/885)) ([05c0735](https://github.com/zeroroot-ai/gibson/commit/05c073512e89debd464a0bf255c9c913d5704628))
* **daemon:** take sdk v0.196.0, list RPCs use page tokens, dead component RPCs leave ([#894](https://github.com/zeroroot-ai/gibson/issues/894)) ([5a3e2c2](https://github.com/zeroroot-ai/gibson/commit/5a3e2c28af2c83611ec09ca55d65315a49e4411b))
* **daemon:** the connector credential crosses one operator RPC, and the daemon writes no Secret ([#663](https://github.com/zeroroot-ai/gibson/issues/663)) ([#950](https://github.com/zeroroot-ai/gibson/issues/950)) ([1d5f162](https://github.com/zeroroot-ai/gibson/commit/1d5f1627f3ebfda33dc2c8861186b95f5e8635e6))
* **daemon:** two operator RPCs serve the belief trainer of a tenant ([#880](https://github.com/zeroroot-ai/gibson/issues/880)) ([e816c9b](https://github.com/zeroroot-ai/gibson/commit/e816c9bb2fa83adf26058486c41964f97b3a0dda))
* end-phase integration of gibson ([#1001](https://github.com/zeroroot-ai/gibson/issues/1001)) ([d0df2d9](https://github.com/zeroroot-ai/gibson/commit/d0df2d9e83304e3a2fce320db8e869723bc57d66))
* **graph:** the projector writes a Hypothesis node ([#832](https://github.com/zeroroot-ai/gibson/issues/832)) ([f52b158](https://github.com/zeroroot-ai/gibson/commit/f52b1580feaac45c3e4ae199ad639e0ccba092c8)), closes [#670](https://github.com/zeroroot-ai/gibson/issues/670)
* **harness:** a mission node sandbox gets the network scope of its node ([#878](https://github.com/zeroroot-ai/gibson/issues/878)) ([b1faf95](https://github.com/zeroroot-ai/gibson/commit/b1faf953fc7704086bdba68a91d09f470c48edef))
* **harness:** the callback service serves OpenJob, SendInput and CloseJob ([#840](https://github.com/zeroroot-ai/gibson/issues/840)) ([6f1f23a](https://github.com/zeroroot-ai/gibson/commit/6f1f23afc5f9f6b64e1a0997529670211ddef300))
* **metatool:** invoke_tool calls a connector through the one MCP client ([#911](https://github.com/zeroroot-ai/gibson/issues/911)) ([6ceb95e](https://github.com/zeroroot-ai/gibson/commit/6ceb95e38a3f1fc5d605094e3bccf5165a8364ed))
* **missioncatalog:** publish the parameter names of each checked-in mission ([#862](https://github.com/zeroroot-ai/gibson/issues/862)) ([62c4190](https://github.com/zeroroot-ai/gibson/commit/62c4190f39d9ecdda2ac7151b5a6b5ac7f812a52))
* **mission:** the submit check refuses an invalid starts_from ([#977](https://github.com/zeroroot-ai/gibson/issues/977)) ([71ed2e1](https://github.com/zeroroot-ai/gibson/commit/71ed2e11e8e72cfc024b01962f0a9118a9c757ba))
* **ontology:** a Domain Pack declares techniques and a belief schema extension ([#854](https://github.com/zeroroot-ai/gibson/issues/854)) ([01d3e87](https://github.com/zeroroot-ai/gibson/commit/01d3e87c0421372f63c7f34be9dc519c1f578495))
* **ontology:** a Domain Pack moves between installs, and an upstream submit is recorded ([#925](https://github.com/zeroroot-ai/gibson/issues/925)) ([f2821a1](https://github.com/zeroroot-ai/gibson/commit/f2821a1d3ecc39aa44fbde772d55cb2e54108a80))
* **ontology:** catalog Domain Pack content is an embedded data file ([#869](https://github.com/zeroroot-ai/gibson/issues/869)) ([0e37eb6](https://github.com/zeroroot-ai/gibson/commit/0e37eb606581468f4db5a45efc046187b9e3c02b))
* **platform-operator:** the operator mints the Zitadel admin token and keeps it in OpenBao ([#881](https://github.com/zeroroot-ai/gibson/issues/881)) ([88320d1](https://github.com/zeroroot-ai/gibson/commit/88320d15f37d1a040c656124af0fa595f7251150))
* **plugins:** each plugin module measures its unwired declarations against a baseline ([#962](https://github.com/zeroroot-ai/gibson/issues/962)) ([390e479](https://github.com/zeroroot-ai/gibson/commit/390e479b582ebb55ae67f0db0571917d82795f7b))
* **plugins:** the GitHub and GitLab plugins live in gibson, and the build pins their images ([#909](https://github.com/zeroroot-ai/gibson/issues/909)) ([20bc2b6](https://github.com/zeroroot-ai/gibson/commit/20bc2b65d3279b14e04799bc3bb7ce98ba1c1f03))
* **proto:** each daemon-local create, start and submit request has an idempotency_key ([#972](https://github.com/zeroroot-ai/gibson/issues/972)) ([fcecb24](https://github.com/zeroroot-ai/gibson/commit/fcecb24fed648ee0d252a7a5700966d9c6c09bd1)), closes [#694](https://github.com/zeroroot-ai/gibson/issues/694)
* **proto:** each request of a daemon-local service states its field rules ([#861](https://github.com/zeroroot-ai/gibson/issues/861)) ([704ba50](https://github.com/zeroroot-ai/gibson/commit/704ba501e1b9e9e8bbabf2d7d9d58e4919956c40))
* **signup:** signup has one neutral external step, and the Stripe check leaves the platform ([#895](https://github.com/zeroroot-ai/gibson/issues/895)) ([80d4425](https://github.com/zeroroot-ai/gibson/commit/80d4425145f0a2f96678f2bb18b7a2ce6c025a26))
* **timeline:** the trim keeps each event in the Postgres history ([#863](https://github.com/zeroroot-ai/gibson/issues/863)) ([d45b0f2](https://github.com/zeroroot-ai/gibson/commit/d45b0f2fbfbb52b5fa034bb2e21df94062069949))


### Bug Fixes

* **audit:** a state change can write its audit record first and fail on error ([#921](https://github.com/zeroroot-ai/gibson/issues/921)) ([2a8896a](https://github.com/zeroroot-ai/gibson/commit/2a8896a1c603d2108e7aa5a3d3fab96a93060155))
* **audit:** agent and plugin changes write their audit record first ([#937](https://github.com/zeroroot-ai/gibson/issues/937)) ([ab15c8a](https://github.com/zeroroot-ai/gibson/commit/ab15c8a1704e458a543585818ff686c7069ab4f6))
* **audit:** an audit write never drops, and retention is 13 months ([#838](https://github.com/zeroroot-ai/gibson/issues/838)) ([92b987e](https://github.com/zeroroot-ai/gibson/commit/92b987e998c311cc10c9a41c783aecaead1706df))
* **authz:** delete the mission relations admin and can_rewind ([#928](https://github.com/zeroroot-ai/gibson/issues/928)) ([6b650d5](https://github.com/zeroroot-ai/gibson/commit/6b650d55966f8248349970cd295efdeaaffb90ec))
* **authz:** one grant, the component approval relations leave the FGA model ([#849](https://github.com/zeroroot-ai/gibson/issues/849)) ([af9a6bc](https://github.com/zeroroot-ai/gibson/commit/af9a6bc4cb03485f0d6f74e2451fc458b3d52182))
* **authz:** the grant write uses the direct relation of each grant ([#845](https://github.com/zeroroot-ai/gibson/issues/845)) ([7dedc98](https://github.com/zeroroot-ai/gibson/commit/7dedc9898a18887655aa6aa436b3e495e6989c21))
* **authz:** the signup-progress RPCs require the dashboard service identity ([#982](https://github.com/zeroroot-ai/gibson/issues/982)) ([2f174d5](https://github.com/zeroroot-ai/gibson/commit/2f174d555682b30716c6dae0dadd54031314187b))
* **authz:** WriteAgentGrants writes the direct relation of each grant ([7dedc98](https://github.com/zeroroot-ai/gibson/commit/7dedc9898a18887655aa6aa436b3e495e6989c21)), closes [#703](https://github.com/zeroroot-ai/gibson/issues/703)
* **bank:** the bank reconciler applies the spill policy of a bank ([#866](https://github.com/zeroroot-ai/gibson/issues/866)) ([fb0f0a8](https://github.com/zeroroot-ai/gibson/commit/fb0f0a8418acb083c4265d04e1dcbe7a07eb1dac))
* **bank:** the bank reconciler closes each stale job as abandoned ([#857](https://github.com/zeroroot-ai/gibson/issues/857)) ([00f28a1](https://github.com/zeroroot-ai/gibson/commit/00f28a101779ea095eb81bd9ee81dc99f7607fd8))
* **belief:** each slice breaks its own cycles ([#902](https://github.com/zeroroot-ai/gibson/issues/902)) ([c649a1f](https://github.com/zeroroot-ai/gibson/commit/c649a1f90eefac60d5270b3227d3e77aa5a80338))
* **brain:** an event folds only after its durable append ([#825](https://github.com/zeroroot-ai/gibson/issues/825)) ([560a7b6](https://github.com/zeroroot-ai/gibson/commit/560a7b6b94d0ccff9842629dfaabf1dfa132d915))
* **brain:** the attack graph gets the relationships of the World ([#848](https://github.com/zeroroot-ai/gibson/issues/848)) ([dedf71c](https://github.com/zeroroot-ai/gibson/commit/dedf71cb167b10ae6a3826cb163699855ce11ad8))
* **brain:** the planner reads the capability catalog of the engine ([#836](https://github.com/zeroroot-ai/gibson/issues/836)) ([1fd48ad](https://github.com/zeroroot-ai/gibson/commit/1fd48adfee87d7af5f6790cbf1a244ed1b9abef8)), closes [#693](https://github.com/zeroroot-ai/gibson/issues/693)
* **brain:** the snapshot trims the in-memory Timeline with the stream ([#867](https://github.com/zeroroot-ai/gibson/issues/867)) ([88b1d99](https://github.com/zeroroot-ai/gibson/commit/88b1d99d5bc012df69ebfdac89f6ae85e3c1d594)), closes [#730](https://github.com/zeroroot-ai/gibson/issues/730)
* **braintrain:** cite no retired ADR ([#891](https://github.com/zeroroot-ai/gibson/issues/891)) ([cf5a2e2](https://github.com/zeroroot-ai/gibson/commit/cf5a2e2b6e9b561d495d40e1a88cf4fba02374f6))
* **budget:** the budget enforcer requires its team resolver ([#963](https://github.com/zeroroot-ai/gibson/issues/963)) ([8da94a6](https://github.com/zeroroot-ai/gibson/commit/8da94a64e40cb4dabd0dc18263cbd019ab293a57))
* **catalog:** the catalog states no wildcard egress ([#897](https://github.com/zeroroot-ai/gibson/issues/897)) ([01073b1](https://github.com/zeroroot-ai/gibson/commit/01073b132fda808b828ec013c6922d9a7e3556d5))
* **catalog:** the component catalog loader refuses the kind domainpack ([#850](https://github.com/zeroroot-ai/gibson/issues/850)) ([3481162](https://github.com/zeroroot-ai/gibson/commit/348116282bfe322a2d507d851d16a6e0401e0a7d)), closes [#735](https://github.com/zeroroot-ai/gibson/issues/735)
* **catalog:** the OSV connector prototype leaves the catalog ([#906](https://github.com/zeroroot-ai/gibson/issues/906)) ([9e0f916](https://github.com/zeroroot-ai/gibson/commit/9e0f9168528a979630632c60a16865113d7bf5ad))
* **ci:** the Go gates run on a pull request unless only Markdown changed ([#957](https://github.com/zeroroot-ai/gibson/issues/957)) ([5d4ed9d](https://github.com/zeroroot-ai/gibson/commit/5d4ed9d37a7e715b4abf0199757ae58ded7c258d))
* **component:** the install record holds the trust that the catalog states ([#896](https://github.com/zeroroot-ai/gibson/issues/896)) ([5310151](https://github.com/zeroroot-ai/gibson/commit/53101516269139974a78f767f1cf8bcbee82c544))
* **connector:** a connector has one runtime, a pod ([#821](https://github.com/zeroroot-ai/gibson/issues/821)) ([45a2bd1](https://github.com/zeroroot-ai/gibson/commit/45a2bd18cbc88a9f86ae9c63428c049a1d9f086c))
* **connector:** the egress of a connector follows its host list ([#964](https://github.com/zeroroot-ai/gibson/issues/964)) ([46a7147](https://github.com/zeroroot-ai/gibson/commit/46a714750be6100b8a4766cc1326b7c38dfe6df5))
* **crypto:** one client for the OpenBao wire API ([#930](https://github.com/zeroroot-ai/gibson/issues/930)) ([dc3276b](https://github.com/zeroroot-ai/gibson/commit/dc3276bef06e20861a0a80e82b6d9feb9604b2ab)), closes [#686](https://github.com/zeroroot-ai/gibson/issues/686)
* **daemon:** a pending destructive action returns blast radius and reversibility ([#903](https://github.com/zeroroot-ai/gibson/issues/903)) ([5f329a3](https://github.com/zeroroot-ai/gibson/commit/5f329a309cce8ff23c6604d1fa22bf220a8b05da)), closes [#706](https://github.com/zeroroot-ai/gibson/issues/706)
* **daemon:** a read of a stopped tenant World is unavailable ([#910](https://github.com/zeroroot-ai/gibson/issues/910)) ([205424d](https://github.com/zeroroot-ai/gibson/commit/205424d568a4919ebe5a8e8245192dcb40a2472c))
* **daemon:** component key documents use the TLS listener only ([#823](https://github.com/zeroroot-ai/gibson/issues/823)) ([a274a01](https://github.com/zeroroot-ai/gibson/commit/a274a0183c25bf798ebacb0b3c0f058623c69720))
* **daemon:** each platform SPIFFE ID is built from the trust domain of the install ([#951](https://github.com/zeroroot-ai/gibson/issues/951)) ([8fa212c](https://github.com/zeroroot-ai/gibson/commit/8fa212cfa5006673b12c1fab090f9a33d663b485))
* **daemon:** each state change of lane 3 writes its audit record first ([#939](https://github.com/zeroroot-ai/gibson/issues/939)) ([4c930da](https://github.com/zeroroot-ai/gibson/commit/4c930da5600d4c3b5ca923fccad651d990b97d70))
* **daemon:** seven request paths require their dependency, and the allowlist drops them ([#953](https://github.com/zeroroot-ai/gibson/issues/953)) ([f521756](https://github.com/zeroroot-ai/gibson/commit/f5217566bade2718f5381a6f58ee23386aae8cbc))
* **daemon:** the daemon does not start with no durable Timeline ([#877](https://github.com/zeroroot-ai/gibson/issues/877)) ([b7bdff9](https://github.com/zeroroot-ai/gibson/commit/b7bdff9d2c66b9d8b731ab0cbbe8476b00da9a79))
* **datapool:** each tenant connection carries its Redis client and its Neo4j session ([#961](https://github.com/zeroroot-ai/gibson/issues/961)) ([c2f4a2c](https://github.com/zeroroot-ai/gibson/commit/c2f4a2c2d14d23d48745d4fd80aaa1e4cebddaa2))
* **dispatch:** each agent task carries the settings of its node ([#986](https://github.com/zeroroot-ai/gibson/issues/986)) ([0c1c781](https://github.com/zeroroot-ai/gibson/commit/0c1c781eaf9d7320b9fc327180b06b10387b036e))
* **dispatch:** mission code has the sandbox and the work queue only ([#831](https://github.com/zeroroot-ai/gibson/issues/831)) ([a1edf24](https://github.com/zeroroot-ai/gibson/commit/a1edf240802b07f50ea5ac3dabd59b8ef8e976e7))
* **ext-authz:** component token replay state is in Redis, and Redis is required ([#824](https://github.com/zeroroot-ai/gibson/issues/824)) ([e58a558](https://github.com/zeroroot-ai/gibson/commit/e58a5589b7547d89e00b76ff7acec764c60b559b))
* **ext-authz:** the daemon import guard scans the real package ([#827](https://github.com/zeroroot-ai/gibson/issues/827)) ([2c10109](https://github.com/zeroroot-ai/gibson/commit/2c10109a080b1c693084cb64f6951cb479b61742)), closes [#709](https://github.com/zeroroot-ai/gibson/issues/709)
* **graph:** a graph client query runs in a read transaction only ([#875](https://github.com/zeroroot-ai/gibson/issues/875)) ([81c3ac4](https://github.com/zeroroot-ai/gibson/commit/81c3ac4325003a7c0d0d6f33428bf311fdb0b63a))
* **harness:** a mission from the callback carries the canonical constraints ([#846](https://github.com/zeroroot-ai/gibson/issues/846)) ([49d9e7c](https://github.com/zeroroot-ai/gibson/commit/49d9e7c971d34dd80b3a94b91c509d45952e5c96))
* **harness:** a tool has the sandbox path and the work queue path only ([#892](https://github.com/zeroroot-ai/gibson/issues/892)) ([37aa89a](https://github.com/zeroroot-ai/gibson/commit/37aa89ac5a3e0861b0b36b61fcc7c3da94833c02))
* **harness:** take sdk v0.197.0 and read only the canonical constraints ([#935](https://github.com/zeroroot-ai/gibson/issues/935)) ([5971011](https://github.com/zeroroot-ai/gibson/commit/5971011a12be2347721e5aaa7eb0feabbe035ba2)), closes [#683](https://github.com/zeroroot-ai/gibson/issues/683)
* **harness:** the callback peers use the trust domain of the install ([#981](https://github.com/zeroroot-ai/gibson/issues/981)) ([314447a](https://github.com/zeroroot-ai/gibson/commit/314447a248186c6820ffc1024f53797a6cd2d349))
* **harness:** the capture guard follows the structure of the code ([#904](https://github.com/zeroroot-ai/gibson/issues/904)) ([cdea7df](https://github.com/zeroroot-ai/gibson/commit/cdea7df42652df6eeb183fc21125404f70cf52dd)), closes [#704](https://github.com/zeroroot-ai/gibson/issues/704)
* **harness:** the destructive request passes blast radius and reversibility ([#900](https://github.com/zeroroot-ai/gibson/issues/900)) ([a220439](https://github.com/zeroroot-ai/gibson/commit/a2204396d4b2d8677e5ff495e600eb6cfd0817f5))
* **harness:** the result of a sandboxed agent returns to the caller ([#837](https://github.com/zeroroot-ai/gibson/issues/837)) ([dbba4d3](https://github.com/zeroroot-ai/gibson/commit/dbba4d316f489ec79f2032cfb8b2879b08443d1d))
* **metatool:** invoke_tool dispatches a native tool id and records each call once ([#907](https://github.com/zeroroot-ai/gibson/issues/907)) ([5f07b02](https://github.com/zeroroot-ai/gibson/commit/5f07b02f43ea501a94b064c465f8d4e2b5f31bc1))
* **mission:** mission lineage is a Timeline event ([#858](https://github.com/zeroroot-ai/gibson/issues/858)) ([7a80e5a](https://github.com/zeroroot-ai/gibson/commit/7a80e5a887e74dc215afa9d8bbc88b0ca006da04))
* **oss-boundary:** gibson-executor is in the Elastic License layer ([#834](https://github.com/zeroroot-ai/gibson/issues/834)) ([b15371f](https://github.com/zeroroot-ai/gibson/commit/b15371f50028a9e97cc42527c333660026be71c7))
* **platform-operator:** a skipped trusted-domain step is not Ready ([#901](https://github.com/zeroroot-ai/gibson/issues/901)) ([7581998](https://github.com/zeroroot-ai/gibson/commit/7581998c98ac3e02e5cb75174a5de9bc2245fc15)), closes [#223](https://github.com/zeroroot-ai/gibson/issues/223)
* **platform-operator:** the PlatformBootstrap has no issuer field ([#933](https://github.com/zeroroot-ai/gibson/issues/933)) ([dcbd83f](https://github.com/zeroroot-ai/gibson/commit/dcbd83f2f59c9a77fc6d3595b80e52b5e6e52a02))
* **plugins:** the GitHub and GitLab plugins declare themselves in code and run as pods ([#959](https://github.com/zeroroot-ai/gibson/issues/959)) ([bcdf863](https://github.com/zeroroot-ai/gibson/commit/bcdf8630ff6d21f48edb72fa3e44eccd253627d4))
* **providers:** each credential field has a type ([#916](https://github.com/zeroroot-ai/gibson/issues/916)) ([e5de918](https://github.com/zeroroot-ai/gibson/commit/e5de9189cf67310c6364ebf2a6667caffb84015f)), closes [#701](https://github.com/zeroroot-ai/gibson/issues/701)
* **sandbox:** a launch sends the full network scope of the node to setec ([#980](https://github.com/zeroroot-ai/gibson/issues/980)) ([d79106c](https://github.com/zeroroot-ai/gibson/commit/d79106c318a972785c753b087071ab68ec415054))
* **sandbox:** each setec request names the tenant of the caller, and sandbox.setec.tenant is gone ([#974](https://github.com/zeroroot-ai/gibson/issues/974)) ([91f9c27](https://github.com/zeroroot-ai/gibson/commit/91f9c275c3daf09990c110dc2e44c160fc86604d))
* **sandboxed:** each setec call names the tenant of the caller ([#971](https://github.com/zeroroot-ai/gibson/issues/971)) ([dfead57](https://github.com/zeroroot-ai/gibson/commit/dfead5711494432ad843cadd3044ccfb828c2e5f))
* **sandbox:** the daemon does not start without a setec address, and sandbox.enabled is gone ([#979](https://github.com/zeroroot-ai/gibson/issues/979)) ([9a27fd5](https://github.com/zeroroot-ai/gibson/commit/9a27fd5f97a0ce738d8731ae0548cde20d4e9041))
* **secrets:** a secret write or delete records its audit entry first ([#945](https://github.com/zeroroot-ai/gibson/issues/945)) ([e06caef](https://github.com/zeroroot-ai/gibson/commit/e06caeff835e4847303d7e3e4a1fe753e560dc3d))
* **secrets:** the daemon serves gibson.secrets.v1 and the old copy leaves ([#864](https://github.com/zeroroot-ai/gibson/issues/864)) ([3354875](https://github.com/zeroroot-ai/gibson/commit/33548759864bf2a09b0537ce607c20c4c06d3c60))
* **state:** a dropped subscription returns, so fgaevent retries it ([#949](https://github.com/zeroroot-ai/gibson/issues/949)) ([c1a9ed4](https://github.com/zeroroot-ai/gibson/commit/c1a9ed4e4da6db197cbf12f175c9c3a8d442467e)), closes [#944](https://github.com/zeroroot-ai/gibson/issues/944)
* **tenant-operator:** a tenant delete takes a last backup first ([#839](https://github.com/zeroroot-ai/gibson/issues/839)) ([28ebec3](https://github.com/zeroroot-ai/gibson/commit/28ebec30d23613e2a9586fb9f1729abec2fe7e34))
* **tenant-operator:** delete NullSender and the DevMode branch ([#923](https://github.com/zeroroot-ai/gibson/issues/923)) ([28e1bb2](https://github.com/zeroroot-ai/gibson/commit/28e1bb29c72cdc8783e219bac4403906d3386f33))
* **tenant-operator:** delete the retired connector tuple only when it exists ([#912](https://github.com/zeroroot-ai/gibson/issues/912)) ([3beee94](https://github.com/zeroroot-ai/gibson/commit/3beee9485836c0eec9bdbc9241192763d183f1b8)), closes [#879](https://github.com/zeroroot-ai/gibson/issues/879)
* **tenant-operator:** each tenant namespace enforces the restricted Pod Security standard ([#975](https://github.com/zeroroot-ai/gibson/issues/975)) ([e9ce3a7](https://github.com/zeroroot-ai/gibson/commit/e9ce3a7ceb02a6234616c1e324bf05cd08eb65d1))
* **tenant-operator:** the data-plane pipeline requires each store ([#936](https://github.com/zeroroot-ai/gibson/issues/936)) ([4da07dd](https://github.com/zeroroot-ai/gibson/commit/4da07dd1ea213bb6cc7479bff74d761ad4228da8))
* **tenant-operator:** the operator does not start with no daemon address ([#855](https://github.com/zeroroot-ai/gibson/issues/855)) ([c23ece4](https://github.com/zeroroot-ai/gibson/commit/c23ece4cebb3d70e517c4aeeaacda121f37b4bf8))
* **tenant-operator:** the tenant Neo4j pod meets the restricted standard ([#829](https://github.com/zeroroot-ai/gibson/issues/829)) ([0a3fb92](https://github.com/zeroroot-ai/gibson/commit/0a3fb92346c692d212515da09cb57e57464dd054))

## [0.153.2](https://github.com/zeroroot-ai/gibson/compare/v0.153.1...v0.153.2) (2026-10-05)


### Bug Fixes

* **platform-operator:** a reconcile that succeeds says the client exists ([#801](https://github.com/zeroroot-ai/gibson/issues/801)) ([806c8e7](https://github.com/zeroroot-ai/gibson/commit/806c8e70e2e2ae34694482c3c94ebc4ef84967dd))

## [0.153.1](https://github.com/zeroroot-ai/gibson/compare/v0.153.0...v0.153.1) (2026-10-05)


### Bug Fixes

* **catalog:** each entry that runs code states its content trust ([#773](https://github.com/zeroroot-ai/gibson/issues/773)) ([03a9dd4](https://github.com/zeroroot-ai/gibson/commit/03a9dd42f728b541942bee3a06ce5da463529f2a)), closes [#772](https://github.com/zeroroot-ai/gibson/issues/772)
* **graphrag:** delete the 35 functions of the graphrag package nothing reaches ([#745](https://github.com/zeroroot-ai/gibson/issues/745)) ([e77a309](https://github.com/zeroroot-ai/gibson/commit/e77a30957f706b21a4648d919f0193b5669ccd03)), closes [#508](https://github.com/zeroroot-ai/gibson/issues/508)
* **guards:** an allowlist entry that allows nothing fails the gate ([#753](https://github.com/zeroroot-ai/gibson/issues/753)) ([45744ef](https://github.com/zeroroot-ai/gibson/commit/45744efb77e73245a7e9fb6cfff833b1af4945b3))
* **harness:** every tool dispatch passes the execute gate ([#744](https://github.com/zeroroot-ai/gibson/issues/744)) ([b421395](https://github.com/zeroroot-ai/gibson/commit/b4213955395da67ca31fa3a82037f74bd6d72a4a))
* **identity:** no test reads the enroll command field ([13e07bb](https://github.com/zeroroot-ai/gibson/commit/13e07bb2462dfcab3ef8185c05c2a0b703f8beb8))
* **identity:** the daemon builds no enroll command ([#749](https://github.com/zeroroot-ai/gibson/issues/749)) ([cdff53d](https://github.com/zeroroot-ai/gibson/commit/cdff53dc6e83ead6afe4cb632793b44a34616a62))
* **identity:** the grant record states how a component enrolled ([#771](https://github.com/zeroroot-ai/gibson/issues/771)) ([90f46a6](https://github.com/zeroroot-ai/gibson/commit/90f46a6569fa68ae874e6ac5b2fef5de6e0155c1))
* **platform-operator:** the rbac markers are read, and each generated role is checked against its markers ([#768](https://github.com/zeroroot-ai/gibson/issues/768)) ([8b5ab0e](https://github.com/zeroroot-ai/gibson/commit/8b5ab0eb8f9afc4594b3e071b82a003487089bff))
* **registry:** a check-in cannot set the keys only the daemon may set ([#783](https://github.com/zeroroot-ai/gibson/issues/783)) ([6b6dae9](https://github.com/zeroroot-ai/gibson/commit/6b6dae9245b765dc641e9544c03a1d41daca833b)), closes [#782](https://github.com/zeroroot-ai/gibson/issues/782)
* **rework:** no test reads the enroll command field ([#778](https://github.com/zeroroot-ai/gibson/issues/778)) ([13e07bb](https://github.com/zeroroot-ai/gibson/commit/13e07bb2462dfcab3ef8185c05c2a0b703f8beb8))
* **settlement:** the pack states which predicates are destructive ([#770](https://github.com/zeroroot-ai/gibson/issues/770)) ([3037eda](https://github.com/zeroroot-ai/gibson/commit/3037eda8ff8824aeeb7c30a1a93d9755d746efd2)), closes [#769](https://github.com/zeroroot-ai/gibson/issues/769)
* **settlement:** the proof technique is the predicate name ([#780](https://github.com/zeroroot-ai/gibson/issues/780)) ([5a4b38b](https://github.com/zeroroot-ai/gibson/commit/5a4b38bcfb0700777a293cfcd7e8196d0d3f82b6)), closes [#779](https://github.com/zeroroot-ai/gibson/issues/779)
* **vector:** delete the 40 functions of the memory vector package nothing reaches ([#746](https://github.com/zeroroot-ai/gibson/issues/746)) ([1022434](https://github.com/zeroroot-ai/gibson/commit/1022434cc7c0b3a57cdf25911e35a3173faffd68)), closes [#508](https://github.com/zeroroot-ai/gibson/issues/508)

## [0.153.0](https://github.com/zeroroot-ai/gibson/compare/v0.152.0...v0.153.0) (2026-10-05)


### ⚠ BREAKING CHANGES

* **modelgate:** FGA model-access tuples written before this change name global objects (provider:<name>, model:<name>) and no longer grant anything. The model type loses its provider and owner relations.
* **platform-operator:** every zitadel call uses zitadelconn, under ZITADEL_URL ([#653](https://github.com/zeroroot-ai/gibson/issues/653))

### Bug Fixes

* **authz:** delete the fga relations nothing checks, and check rewind by its permission ([#657](https://github.com/zeroroot-ai/gibson/issues/657)) ([574f16c](https://github.com/zeroroot-ai/gibson/commit/574f16cf69b7cdaf5feb936d9456ccb5633322d4))
* **manifest:** delete the 67 functions of the manifest package nothing reaches ([#737](https://github.com/zeroroot-ai/gibson/issues/737)) ([be4429e](https://github.com/zeroroot-ai/gibson/commit/be4429ea093d1dd210d23ebb6f88ea42d80b4520)), closes [#508](https://github.com/zeroroot-ai/gibson/issues/508)
* **modelgate:** the model gate decides for every request, and a member is allowed by default ([#669](https://github.com/zeroroot-ai/gibson/issues/669)) ([9ec20bd](https://github.com/zeroroot-ai/gibson/commit/9ec20bda89ff38371d0e77f0e22fea2b91286ee0))
* **observability:** delete the 71 functions of the observability package nothing reaches ([#655](https://github.com/zeroroot-ai/gibson/issues/655)) ([2e03271](https://github.com/zeroroot-ai/gibson/commit/2e0327161c3eca30528d08e3b8a74d01c7b89366))
* **platform-operator:** every zitadel call uses zitadelconn, under ZITADEL_URL ([#653](https://github.com/zeroroot-ai/gibson/issues/653)) ([e2e6e02](https://github.com/zeroroot-ai/gibson/commit/e2e6e020b24fd8f28b5502c8e871555872b273b5))

## [0.152.0](https://github.com/zeroroot-ai/gibson/compare/v0.151.0...v0.152.0) (2026-10-05)


### Features

* **brain:** edge outcomes fold into the world ([#638](https://github.com/zeroroot-ai/gibson/issues/638)) ([2a99079](https://github.com/zeroroot-ai/gibson/commit/2a990797b826f431739e8265a80c8c7b354804d5))
* **connector:** declared credential refs reach the connector pod ([#639](https://github.com/zeroroot-ai/gibson/issues/639)) ([4eea790](https://github.com/zeroroot-ai/gibson/commit/4eea7903652485f05001120468f54195984558ab))
* **enrollment:** spec.maxruntime caps the agent's sandboxed run ([#641](https://github.com/zeroroot-ai/gibson/issues/641)) ([3e41afa](https://github.com/zeroroot-ai/gibson/commit/3e41afa024084f144052cda6761689a31e9ef8d3))
* **env:** the env reader set is a committed artifact with a drift gate ([#650](https://github.com/zeroroot-ai/gibson/issues/650)) ([00349d6](https://github.com/zeroroot-ai/gibson/commit/00349d6a9f204422f2c4f64c353a2a6daefa81d2))
* **identity:** the declared oidc clients of a tenantidentity are minted ([#640](https://github.com/zeroroot-ai/gibson/issues/640)) ([52ae96a](https://github.com/zeroroot-ai/gibson/commit/52ae96a4002815db16d4782de8cbb44277a3100d))
* **mission:** a join merges its sources by its declared strategy ([#646](https://github.com/zeroroot-ai/gibson/issues/646)) ([b45167c](https://github.com/zeroroot-ai/gibson/commit/b45167c0b2ebb21636b30d78931249efc768bb60))


### Bug Fixes

* **brain:** max_concurrency is a scheduler ceiling for parallel and for_each ([#636](https://github.com/zeroroot-ai/gibson/issues/636)) ([276324c](https://github.com/zeroroot-ai/gibson/commit/276324caf58c59887aefb9ce27dcfbe721b9d129))
* **component:** delete the 102 functions of the component package nothing reaches ([#647](https://github.com/zeroroot-ai/gibson/issues/647)) ([0638cf0](https://github.com/zeroroot-ai/gibson/commit/0638cf0279e0bdabebfb1c865520dbf027e70654))
* **crd:** delete AgentEnrollmentSpec.Mode and ConnectorInstanceSpec.CatalogRef, which nothing read ([8aab586](https://github.com/zeroroot-ai/gibson/commit/8aab586535eee9799c288e077a13974c7c6abaf8))
* **crd:** delete agentenrollmentspec.mode and connectorinstancespec.catalogref, which nothing read ([#637](https://github.com/zeroroot-ai/gibson/issues/637)) ([8aab586](https://github.com/zeroroot-ai/gibson/commit/8aab586535eee9799c288e077a13974c7c6abaf8))
* **finding:** delete the 98 functions of the finding package nothing reaches ([#648](https://github.com/zeroroot-ai/gibson/issues/648)) ([774d10a](https://github.com/zeroroot-ai/gibson/commit/774d10a87b912eea1e81ceca1292d80b6ab0c175))
* **harness:** the discovery tool set comes from the catalog and the validator runs on dispatch ([#643](https://github.com/zeroroot-ai/gibson/issues/643)) ([17553e1](https://github.com/zeroroot-ai/gibson/commit/17553e19c0ff9cddf6bd127a877c5e1e6cb2bacb))
* **rework:** the crd field gate runs from ast-checks, the one copy ([#649](https://github.com/zeroroot-ai/gibson/issues/649)) ([951e831](https://github.com/zeroroot-ai/gibson/commit/951e831e67f814d33ddabe3f8dcc9fdc97229497)), closes [#503](https://github.com/zeroroot-ai/gibson/issues/503)
* **tenant-operator:** every zitadel call goes to the service and claims the host by header ([#651](https://github.com/zeroroot-ai/gibson/issues/651)) ([5d89529](https://github.com/zeroroot-ai/gibson/commit/5d89529345fbc48d6f0cc2cfd7e75ac8e5d26177))
* **tooling:** one heavy run at a time, under a hard memory cap ([#645](https://github.com/zeroroot-ai/gibson/issues/645)) ([9b00c95](https://github.com/zeroroot-ai/gibson/commit/9b00c95fa53b32ab8e40e93cf3efed5efcdf24ed)), closes [#644](https://github.com/zeroroot-ai/gibson/issues/644)

## [0.151.0](https://github.com/zeroroot-ai/gibson/compare/v0.150.1...v0.151.0) (2026-10-04)


### Features

* **catalog:** capture the executor release that ships the two cluster tools ([#624](https://github.com/zeroroot-ai/gibson/issues/624)) ([04042fa](https://github.com/zeroroot-ai/gibson/commit/04042fac6f62ce2cbaa5e530161fb22a5b72a7be))
* **catalog:** capture the executor release whose cluster tools read the environment ([#632](https://github.com/zeroroot-ai/gibson/issues/632)) ([47a8d1f](https://github.com/zeroroot-ai/gibson/commit/47a8d1fcc4e04de5a8f5627e22565de43ead7e55))
* **daemon:** the mission catalog is readable and renderable by a person ([#634](https://github.com/zeroroot-ai/gibson/issues/634)) ([25d2c2b](https://github.com/zeroroot-ai/gibson/commit/25d2c2b7965972be4a1c2acfab89b28ac72d0fd0))
* **mission:** a mission's declared secrets reach the tool it dispatches ([#628](https://github.com/zeroroot-ai/gibson/issues/628)) ([0af9b8b](https://github.com/zeroroot-ai/gibson/commit/0af9b8beb67a6ccf167a9f5d0d27fc551157b30d))
* **mission:** the cluster assessment mission ([#630](https://github.com/zeroroot-ai/gibson/issues/630)) ([b0d95cf](https://github.com/zeroroot-ai/gibson/commit/b0d95cfa0fd1bb5cd09d167e6a6d0e69a3c3a8bd))
* **tools:** a dispatched tool is told what it is acting against ([#623](https://github.com/zeroroot-ai/gibson/issues/623)) ([395fdd3](https://github.com/zeroroot-ai/gibson/commit/395fdd3ce447ae5c95c68c4cb975a43dff5327c6))


### Bug Fixes

* **deadcode:** the gate walks with the image build tag ([#617](https://github.com/zeroroot-ai/gibson/issues/617)) ([67c84ac](https://github.com/zeroroot-ai/gibson/commit/67c84acc0d569f0bc9722f25f77effa22ff2f26e))
* **fgaevent:** the resubscribe backoff resets after a healthy subscription ([#627](https://github.com/zeroroot-ai/gibson/issues/627)) ([4b875b0](https://github.com/zeroroot-ai/gibson/commit/4b875b0a0644dc6330c348f439d283077c905596))
* **proto:** delete 58 served proto fields nothing reads, and gate every daemon field for a consumer ([#622](https://github.com/zeroroot-ai/gibson/issues/622)) ([302fbfa](https://github.com/zeroroot-ai/gibson/commit/302fbfa3d18c972976cff693e42d3b1f916ef1cf))

## [0.150.1](https://github.com/zeroroot-ai/gibson/compare/v0.150.0...v0.150.1) (2026-10-04)


### Bug Fixes

* **adr-0027:** delete the no-op cypher stub and the legacy branches that declared their own violation ([#595](https://github.com/zeroroot-ai/gibson/issues/595)) ([aa56a79](https://github.com/zeroroot-ai/gibson/commit/aa56a79b4118548c68409b591ce6796a562b6bef))
* **audit:** an audit entry names its actor, and actor_source leaves the wire ([#585](https://github.com/zeroroot-ai/gibson/issues/585)) ([1178f26](https://github.com/zeroroot-ai/gibson/commit/1178f26c7a6ec75c4cdab44e055abec2420fd947))
* **catalog:** the osv connector image is digest-pinned, and the loader refuses any unpinned hosted image ([#587](https://github.com/zeroroot-ai/gibson/issues/587)) ([84b1fea](https://github.com/zeroroot-ai/gibson/commit/84b1fead48080040abf07e0b34a6017b9c1f5cd3)), closes [#479](https://github.com/zeroroot-ai/gibson/issues/479)
* **config:** delete the 46 config keys nothing reads, and guard every keyed field for a reader ([#599](https://github.com/zeroroot-ai/gibson/issues/599)) ([80c6612](https://github.com/zeroroot-ai/gibson/commit/80c66125871d24c223c99f251f3a38eeca678c58))
* **crd:** every served crd field has a reader, a print column or a recorded verdict ([#598](https://github.com/zeroroot-ai/gibson/issues/598)) ([48d49c7](https://github.com/zeroroot-ai/gibson/commit/48d49c780d989fb700d4856d4104f83251a2e557))
* **db:** drop connector_sandbox and webhook_idempotency, and guard every table for a reader ([#589](https://github.com/zeroroot-ai/gibson/issues/589)) ([9b2997c](https://github.com/zeroroot-ai/gibson/commit/9b2997ce8991dbbb98918a19144b2830e8549d0c))
* **deadcode:** delete the mission tracer's dead subgraph ([#600](https://github.com/zeroroot-ai/gibson/issues/600)) ([10f2209](https://github.com/zeroroot-ai/gibson/commit/10f220998c970f448df4d35324f947770fd976f2))
* **deps:** go.mod names setec v0.118.0, a tag that exists, and CI proves every first-party tag ([64c5ff3](https://github.com/zeroroot-ai/gibson/commit/64c5ff3d642abf72ad2902e0cbeb0f7630fe3151)), closes [#196](https://github.com/zeroroot-ai/gibson/issues/196)
* **deps:** go.mod names setec v0.118.0, a tag that exists, and ci proves every first-party tag ([#596](https://github.com/zeroroot-ai/gibson/issues/596)) ([64c5ff3](https://github.com/zeroroot-ai/gibson/commit/64c5ff3d642abf72ad2902e0cbeb0f7630fe3151))
* **events:** delete the two event taxonomies nothing emits, the uncalled mission tracer and the cost tracker ([#594](https://github.com/zeroroot-ai/gibson/issues/594)) ([a79a600](https://github.com/zeroroot-ai/gibson/commit/a79a600a07f1c87c5d42f5b71f37ce1b82c83859))
* **guard:** the CRD field guard loads packages with the image's build tag ([b867a61](https://github.com/zeroroot-ai/gibson/commit/b867a618ed275e6d27af7dafaab8f2e484462a37)), closes [#503](https://github.com/zeroroot-ai/gibson/issues/503)
* **guard:** the crd field guard loads packages with the image's build tag ([#601](https://github.com/zeroroot-ai/gibson/issues/601)) ([b867a61](https://github.com/zeroroot-ai/gibson/commit/b867a618ed275e6d27af7dafaab8f2e484462a37))
* **mission:** a plugin node reaches the dispatcher with its params ([#582](https://github.com/zeroroot-ai/gibson/issues/582)) ([9672feb](https://github.com/zeroroot-ai/gibson/commit/9672febcd220e22d40d5ba9f6c55a0ff8c14fbaf))
* **quotas:** a tenant's postgres connection limit reaches the role ([#584](https://github.com/zeroroot-ai/gibson/issues/584)) ([13bb3b8](https://github.com/zeroroot-ai/gibson/commit/13bb3b8803788d030187f56ce46e6759456989ae))
* **tenant-operator:** a pass reads the tenant uncached, so the welcome email cannot repeat ([#586](https://github.com/zeroroot-ai/gibson/issues/586)) ([922ab2c](https://github.com/zeroroot-ai/gibson/commit/922ab2c513c1771519f1c99e8cb004e89cf6ac3b))
* **tooling:** delete the six cmd binaries nothing builds or runs ([#592](https://github.com/zeroroot-ai/gibson/issues/592)) ([cec816e](https://github.com/zeroroot-ai/gibson/commit/cec816e97c20c04ef09d697ff9e0eed8f38167cf))

## [0.150.0](https://github.com/zeroroot-ai/gibson/compare/v0.149.0...v0.150.0) (2026-10-02)


### Features

* **graph:** a :Target node, and the mission graph promoted into the Taxonomy ([#570](https://github.com/zeroroot-ai/gibson/issues/570)) ([e0f3363](https://github.com/zeroroot-ai/gibson/commit/e0f33638b3d0723a25042e1593750854ab3043ee)), closes [#550](https://github.com/zeroroot-ai/gibson/issues/550)
* **graph:** the mission graph records a fan-out instance and the target it ran against ([#549](https://github.com/zeroroot-ai/gibson/issues/549)) ([c664fdb](https://github.com/zeroroot-ai/gibson/commit/c664fdbffd0ea7a8dfed990c16937d8edeab8b3f))
* **guards:** every rules.yaml conforms, and every enforced_by names a real guard ([#563](https://github.com/zeroroot-ai/gibson/issues/563)) ([e3d0f80](https://github.com/zeroroot-ai/gibson/commit/e3d0f80de6cb087767db902c670add2d390ec3d8))
* **mission:** a finding from a fan-out instance is attributed to its own target ([#542](https://github.com/zeroroot-ai/gibson/issues/542)) ([f599512](https://github.com/zeroroot-ai/gibson/commit/f5995124b369e4c1d694ffcb7c3716e986532f77))
* **mission:** a for_each runs once per target, each bound to its own ([#539](https://github.com/zeroroot-ai/gibson/issues/539)) ([ddc8ca2](https://github.com/zeroroot-ai/gibson/commit/ddc8ca28cbd681108f826c90b745a0fd7a5ab08d))
* **mission:** a join after a partially failed fan-out still reports the targets that answered ([#546](https://github.com/zeroroot-ai/gibson/issues/546)) ([ac67ed7](https://github.com/zeroroot-ai/gibson/commit/ac67ed7274049e3c80a691b4436a06af2ebcd0ea))
* **mission:** an originated child runs, bound to its own target ([#552](https://github.com/zeroroot-ai/gibson/issues/552)) ([0eaaf68](https://github.com/zeroroot-ai/gibson/commit/0eaaf680e645cb8144de8f3c6ab934898cbba801))
* **mission:** the for_each node kind, on sdk v0.189.1 ([#537](https://github.com/zeroroot-ai/gibson/issues/537)) ([1a80ff3](https://github.com/zeroroot-ai/gibson/commit/1a80ff3681d4e50233c66341dee6e7f29023eda1))


### Bug Fixes

* **authz:** a check-in binds a declared secret only for a catalog component ([#577](https://github.com/zeroroot-ai/gibson/issues/577)) ([5db2291](https://github.com/zeroroot-ai/gibson/commit/5db2291e097d8a8ac933090dcf0d9548b9b7ee51))
* **ci:** record WHEN each pod became ready, and the sync's retry budget ([3e6707d](https://github.com/zeroroot-ai/gibson/commit/3e6707d387ccc5624e5c8b90336a9dc59e8a64be))
* **ci:** record when each pod became ready, and the sync's retry budget ([#533](https://github.com/zeroroot-ai/gibson/issues/533)) ([3e6707d](https://github.com/zeroroot-ai/gibson/commit/3e6707d387ccc5624e5c8b90336a9dc59e8a64be))
* **ci:** the bringup dump prints Argo's truncated message and stops there ([#575](https://github.com/zeroroot-ai/gibson/issues/575)) ([e159712](https://github.com/zeroroot-ai/gibson/commit/e1597121cec27f3c8edd874ec8c331472bd8048b))
* **ci:** the tenant_id guard scanned two paths that do not exist ([#567](https://github.com/zeroroot-ai/gibson/issues/567)) ([937d698](https://github.com/zeroroot-ai/gibson/commit/937d698cd5cfc760ed162023508b55400463690d)), closes [#559](https://github.com/zeroroot-ai/gibson/issues/559)
* **graph:** a :Mission node has one writer ([#565](https://github.com/zeroroot-ai/gibson/issues/565)) ([4e6eace](https://github.com/zeroroot-ai/gibson/commit/4e6eace0559e3838d5fac7730f84940f53ebdae9)), closes [#551](https://github.com/zeroroot-ai/gibson/issues/551)
* **graph:** the projection tick projects a mission, so its status stays true ([#569](https://github.com/zeroroot-ai/gibson/issues/569)) ([cbd3f7a](https://github.com/zeroroot-ai/gibson/commit/cbd3f7a4a023e2ac4b7807c81e3ce98bf7bcdfd9))
* **guards:** the OSS-boundary denylist names a repo that no longer exists ([#540](https://github.com/zeroroot-ai/gibson/issues/540)) ([c7ce2b3](https://github.com/zeroroot-ai/gibson/commit/c7ce2b365c91707380fc681edf9c22046fbf73cf))
* **guards:** two comments claimed a CI guard that did not exist; one is now written ([#560](https://github.com/zeroroot-ai/gibson/issues/560)) ([69848b4](https://github.com/zeroroot-ai/gibson/commit/69848b4c5b297b7556d2c278e36e0c93d9d64caf)), closes [#557](https://github.com/zeroroot-ai/gibson/issues/557)
* **mission:** a for_each inside a parallel sub-node expands ([#579](https://github.com/zeroroot-ai/gibson/issues/579)) ([688051e](https://github.com/zeroroot-ai/gibson/commit/688051ea1a45eaa11f486cf930f9f70e6a6a799a)), closes [#548](https://github.com/zeroroot-ai/gibson/issues/548)
* **rework:** a plaintext TLS mode, which gibson[#561](https://github.com/zeroroot-ai/gibson/issues/561) removed by accident ([#574](https://github.com/zeroroot-ai/gibson/issues/574)) ([aa74370](https://github.com/zeroroot-ai/gibson/commit/aa7437040bed98eaee7c979daa4595ea9a9a23e3)), closes [#553](https://github.com/zeroroot-ai/gibson/issues/553)
* **tenant-operator:** name the TLS mode instead of a boolean that reads backwards ([#561](https://github.com/zeroroot-ai/gibson/issues/561)) ([94bc0b9](https://github.com/zeroroot-ai/gibson/commit/94bc0b9f7a7eeba17c635eef8a8bee90eccf5792))

## [0.149.0](https://github.com/zeroroot-ai/gibson/compare/v0.148.3...v0.149.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* **target:** a Target carries no credential and no auth shape ([#521](https://github.com/zeroroot-ai/gibson/issues/521))

### Features

* **brain:** wire the technique×environment reputation loop ([#492](https://github.com/zeroroot-ai/gibson/issues/492)) ([ab863f8](https://github.com/zeroroot-ai/gibson/commit/ab863f87d855e5ef4c55e2df22f6dad7bcfc0fee))
* **go:** move the toolchain floor to 1.27.1 ([#514](https://github.com/zeroroot-ai/gibson/issues/514)) ([5b5250e](https://github.com/zeroroot-ai/gibson/commit/5b5250e985312cb41f9890bd6fccb6ab5a0384d4))
* **graph:** link a finding to the merge request that fixes it ([#483](https://github.com/zeroroot-ai/gibson/issues/483)) ([1a76cdb](https://github.com/zeroroot-ai/gibson/commit/1a76cdb1cd36ed82cc673fe6c31dc7170b1c1575))
* **jobnode:** a fix job resolves the open findings on its run's target ([#512](https://github.com/zeroroot-ai/gibson/issues/512)) ([6072b71](https://github.com/zeroroot-ai/gibson/commit/6072b71a5f2f3f1190085cf147ed4995749e49d6)), closes [#497](https://github.com/zeroroot-ai/gibson/issues/497)
* **mailer:** the invitation email is the onboarding, and there is only one ([#520](https://github.com/zeroroot-ai/gibson/issues/520)) ([a06ec60](https://github.com/zeroroot-ai/gibson/commit/a06ec60e5c5d52b4d68aae2ea2c60b8cdaa455f9))
* **mission:** bind {{target.*}} to the run's target, server-side ([#509](https://github.com/zeroroot-ai/gibson/issues/509)) ([fcc73e7](https://github.com/zeroroot-ai/gibson/commit/fcc73e7db4c57cfc2aa99d7d194c9a530be801d2))
* **target:** a Target carries no credential and no auth shape ([#521](https://github.com/zeroroot-ai/gibson/issues/521)) ([67795bf](https://github.com/zeroroot-ai/gibson/commit/67795bf4e0e18860c18114879735e6f5bd961736))
* **target:** a target names its secret by name, not by a dropped id ([#511](https://github.com/zeroroot-ai/gibson/issues/511)) ([b882e75](https://github.com/zeroroot-ai/gibson/commit/b882e757157515af3e75cbfc39977aea39e7f6ff))
* **taxonomy:** assign a collision-proof key form at promotion ([#281](https://github.com/zeroroot-ai/gibson/issues/281)) ([#489](https://github.com/zeroroot-ai/gibson/issues/489)) ([3fc21ea](https://github.com/zeroroot-ai/gibson/commit/3fc21ea051509560c9ec4724cd5239dc7da0694e))
* **taxonomy:** carry node-label key form and expose the projector identity seam ([#491](https://github.com/zeroroot-ai/gibson/issues/491)) ([a675583](https://github.com/zeroroot-ai/gibson/commit/a675583db9f964da5fd5c9a212ead4972c3b519c)), closes [#484](https://github.com/zeroroot-ai/gibson/issues/484)


### Bug Fixes

* **belief:** wire findings and demonstrated exploits into the belief network ([#490](https://github.com/zeroroot-ai/gibson/issues/490)) ([94ebc03](https://github.com/zeroroot-ai/gibson/commit/94ebc03c63b3ac9a26a436db6fda822ded99da8d)), closes [#478](https://github.com/zeroroot-ai/gibson/issues/478)
* **ci:** dump the pods that misbehaved, not only the ones unhealthy now ([#522](https://github.com/zeroroot-ai/gibson/issues/522)) ([f3ff3dc](https://github.com/zeroroot-ai/gibson/commit/f3ff3dcf4856536d7ecebfd8ae7d13c1c8824103))
* **ci:** name the Argo task that fails an exit-test bringup ([#517](https://github.com/zeroroot-ai/gibson/issues/517)) ([dcfebc9](https://github.com/zeroroot-ai/gibson/commit/dcfebc9bc8853cae686aaa4a6f0d3e2a9978d9af))
* **datapool:** wire the per-tenant vector handle so graph reads work ([#473](https://github.com/zeroroot-ai/gibson/issues/473)) ([36218f2](https://github.com/zeroroot-ai/gibson/commit/36218f215659cd9147b1e174b3fe2ecd9c24adce))
* **domain-packs:** packs are free, remove the entitlement gate ([#475](https://github.com/zeroroot-ai/gibson/issues/475)) ([030e2ac](https://github.com/zeroroot-ai/gibson/commit/030e2ac76486c4782f6fa1248ea8cbe99cf8d6e7))
* **graph:** ensure the tenant Neo4j schema from the projector ([#486](https://github.com/zeroroot-ai/gibson/issues/486)) ([e11554f](https://github.com/zeroroot-ai/gibson/commit/e11554fbd4aaa2ba407299ab4598687579060ad2))
* **graph:** one resolver for a node label's identity, shared by the projector and the schema ([#516](https://github.com/zeroroot-ai/gibson/issues/516)) ([a735497](https://github.com/zeroroot-ai/gibson/commit/a735497200c3e2a0d6e68b9d3894c647785abca2)), closes [#515](https://github.com/zeroroot-ai/gibson/issues/515)
* **invitations:** the invitation email names relations, not the roles people see ([#472](https://github.com/zeroroot-ai/gibson/issues/472)) ([39dac5d](https://github.com/zeroroot-ai/gibson/commit/39dac5d2666f10cf982e63fa8839d4b3c3cb0f56))
* **mailer:** drop the proxy warning, because the CLI reads the proxy now ([#530](https://github.com/zeroroot-ai/gibson/issues/530)) ([9f85267](https://github.com/zeroroot-ai/gibson/commit/9f85267d4a25e1b4fe6088a7f0d39e78851d4b40))

## [0.148.3](https://github.com/zeroroot-ai/gibson/compare/v0.148.2...v0.148.3) (2026-10-01)


### Bug Fixes

* **daemon:** report kind user for a person in WhoAmI ([#466](https://github.com/zeroroot-ai/gibson/issues/466)) ([f1b72d5](https://github.com/zeroroot-ai/gibson/commit/f1b72d54cd1f20e80cb25cc75e3641a8c4500c7b))
* **daemon:** WhoAmI reports kind user for a person ([f1b72d5](https://github.com/zeroroot-ai/gibson/commit/f1b72d54cd1f20e80cb25cc75e3641a8c4500c7b))

## [0.148.2](https://github.com/zeroroot-ai/gibson/compare/v0.148.1...v0.148.2) (2026-10-01)


### Bug Fixes

* **image:** every distroless runtime on Debian 13 static, tzdata 2026c ([#462](https://github.com/zeroroot-ai/gibson/issues/462)) ([8919f11](https://github.com/zeroroot-ai/gibson/commit/8919f119e21717e9ecaad465e005eed1b1fc1991))

## [0.148.1](https://github.com/zeroroot-ai/gibson/compare/v0.148.0...v0.148.1) (2026-10-01)


### Bug Fixes

* **daemon:** the tenant header is required only where the rule needs the tenant ([#460](https://github.com/zeroroot-ai/gibson/issues/460)) ([041d6aa](https://github.com/zeroroot-ai/gibson/commit/041d6aafffc24460bfa347e3bad00e5ec9d1bbd4))

## [0.148.0](https://github.com/zeroroot-ai/gibson/compare/v0.147.0...v0.148.0) (2026-10-01)


### Features

* **platform-operator:** let an OIDC client reference set a display name ([#458](https://github.com/zeroroot-ai/gibson/issues/458)) ([b2abfc6](https://github.com/zeroroot-ai/gibson/commit/b2abfc6d5c79a8a57e62a3381f9a749aee5e9581))

## [0.147.0](https://github.com/zeroroot-ai/gibson/compare/v0.146.5...v0.147.0) (2026-10-01)


### Features

* **missions:** a created mission is listed, pending, before it runs ([#450](https://github.com/zeroroot-ai/gibson/issues/450)) ([84b7dad](https://github.com/zeroroot-ai/gibson/commit/84b7dad7cf4a085a525a5cdb386ced2df703df9e))


### Bug Fixes

* **daemon:** return NotFound for a missing target ([#453](https://github.com/zeroroot-ai/gibson/issues/453)) ([2fbcc12](https://github.com/zeroroot-ai/gibson/commit/2fbcc12f04ff4c8700b9e73fbf0e4f1126402108))

## [0.146.5](https://github.com/zeroroot-ai/gibson/compare/v0.146.4...v0.146.5) (2026-09-30)


### Bug Fixes

* **missions:** the real CreateMission result carries the creator ([#448](https://github.com/zeroroot-ai/gibson/issues/448)) ([bb78264](https://github.com/zeroroot-ai/gibson/commit/bb78264c1c6496c1881185b67961de9cc2739c85))

## [0.146.4](https://github.com/zeroroot-ai/gibson/compare/v0.146.3...v0.146.4) (2026-09-30)


### Bug Fixes

* **image:** move the runtime base to alpine 3.22, 3.21 cannot ship the OpenSSL fix ([#446](https://github.com/zeroroot-ai/gibson/issues/446)) ([ac09972](https://github.com/zeroroot-ai/gibson/commit/ac09972879e6728841854f5d1e95c02c66cabe56))

## [0.146.3](https://github.com/zeroroot-ai/gibson/compare/v0.146.2...v0.146.3) (2026-09-30)


### Bug Fixes

* **image:** bump the alpine runtime base, libssl3 3.3.7-r2 closes two CVEs ([#444](https://github.com/zeroroot-ai/gibson/issues/444)) ([1071271](https://github.com/zeroroot-ai/gibson/commit/10712716c4f5978d8168df19559992f3d1a05077))

## [0.146.2](https://github.com/zeroroot-ai/gibson/compare/v0.146.1...v0.146.2) (2026-09-30)


### Bug Fixes

* **platform-operator:** a pass reads the CR uncached and never loses a status write ([#442](https://github.com/zeroroot-ai/gibson/issues/442)) ([38d143b](https://github.com/zeroroot-ai/gibson/commit/38d143bb25530e0c419404a52c56ca69ac48e2cc))

## [0.146.1](https://github.com/zeroroot-ai/gibson/compare/v0.146.0...v0.146.1) (2026-09-30)


### Bug Fixes

* **ext-authz:** a rule that needs no tenant reaches FGA for a user with none ([#440](https://github.com/zeroroot-ai/gibson/issues/440)) ([4698547](https://github.com/zeroroot-ai/gibson/commit/4698547ead42e3c6a0fb38b09101c69c8f52c5d9))

## [0.146.0](https://github.com/zeroroot-ai/gibson/compare/v0.145.0...v0.146.0) (2026-09-30)


### Features

* **missions:** record who created a mission, and resolve people at read time ([#438](https://github.com/zeroroot-ai/gibson/issues/438)) ([1a6c649](https://github.com/zeroroot-ai/gibson/commit/1a6c649d97b15d8d403b3d9c478417fdd490c96c))

## [0.145.0](https://github.com/zeroroot-ai/gibson/compare/v0.144.0...v0.145.0) (2026-09-30)


### Features

* **brain:** hard-gate Decider dispatch to the VoI top-k (gibson[#397](https://github.com/zeroroot-ai/gibson/issues/397)) ([faaa55e](https://github.com/zeroroot-ai/gibson/commit/faaa55ee32650d0c3ed7883b59db8a0ea1eb3e9d))
* **intelligence:** phase 2 — CEL proof-settlement, domain packs, native belief runtime, ontology self-construction ([#432](https://github.com/zeroroot-ai/gibson/issues/432)) ([faaa55e](https://github.com/zeroroot-ai/gibson/commit/faaa55ee32650d0c3ed7883b59db8a0ea1eb3e9d))


### Bug Fixes

* **ci:** link-check checks only the Markdown a PR touched (.github v0.7.2) ([#436](https://github.com/zeroroot-ai/gibson/issues/436)) ([8ebd260](https://github.com/zeroroot-ai/gibson/commit/8ebd26053bf814df83866c44f0be5cf63f680ab5))
* **ext-authz:** session gates in flight for one token share one FGA call ([#435](https://github.com/zeroroot-ai/gibson/issues/435)) ([ed2f31d](https://github.com/zeroroot-ai/gibson/commit/ed2f31d8ccc9d94ef569ae6baa20852a309b4248))

## [0.144.0](https://github.com/zeroroot-ai/gibson/compare/v0.143.8...v0.144.0) (2026-09-29)


### Features

* **authz:** a role change reaches ext-authz at once through the FGA write event ([#433](https://github.com/zeroroot-ai/gibson/issues/433)) ([242ee01](https://github.com/zeroroot-ai/gibson/commit/242ee01f220b0e4aa8a2e7cb65d9d8dcc7f67187))

## [0.143.8](https://github.com/zeroroot-ai/gibson/compare/v0.143.7...v0.143.8) (2026-09-29)


### Bug Fixes

* **rework:** the FGA cache TTL has one default, and ext-authz main reads it ([#428](https://github.com/zeroroot-ai/gibson/issues/428)) ([5aae047](https://github.com/zeroroot-ai/gibson/commit/5aae047e8cab81b6fd443660767d07c1e9ef53a5))

## [0.143.7](https://github.com/zeroroot-ai/gibson/compare/v0.143.6...v0.143.7) (2026-09-29)


### Bug Fixes

* **authz:** adopt sdk v0.183.1, a Viewer reads and never changes tenant state ([#424](https://github.com/zeroroot-ai/gibson/issues/424)) ([57171d6](https://github.com/zeroroot-ai/gibson/commit/57171d63d453f5e57f34ec8aabbf485b7a4219fc))

## [0.143.6](https://github.com/zeroroot-ai/gibson/compare/v0.143.5...v0.143.6) (2026-09-29)


### Bug Fixes

* **platform-operator:** the Platform owner becomes ready when its status write races its own user create ([#421](https://github.com/zeroroot-ai/gibson/issues/421)) ([25f8a41](https://github.com/zeroroot-ai/gibson/commit/25f8a410582eb52887fed83274771a96765ad151))

## [0.143.5](https://github.com/zeroroot-ai/gibson/compare/v0.143.4...v0.143.5) (2026-09-29)


### Bug Fixes

* **ext-authz:** the FGA decision cache expires in five seconds, and its dead invalidation hooks are gone ([#412](https://github.com/zeroroot-ai/gibson/issues/412)) ([72260c5](https://github.com/zeroroot-ai/gibson/commit/72260c5bdf0afd6075ea613c956711a133601669))
* **tenantrole:** the inline sync trusts the role it just wrote over a lagging read ([#413](https://github.com/zeroroot-ai/gibson/issues/413)) ([079e834](https://github.com/zeroroot-ai/gibson/commit/079e83486307f34aebe7b18e1716c50ade54d53c))

## [0.143.4](https://github.com/zeroroot-ai/gibson/compare/v0.143.3...v0.143.4) (2026-09-29)


### Bug Fixes

* **daemon:** report all four tenant roles, so an Editor is an Editor and an Owner is an Owner ([#404](https://github.com/zeroroot-ai/gibson/issues/404)) ([2557b58](https://github.com/zeroroot-ai/gibson/commit/2557b586051ee2c8195b08cd6ead6ad15e3e82f3))

## [0.143.3](https://github.com/zeroroot-ai/gibson/compare/v0.143.2...v0.143.3) (2026-09-29)


### Bug Fixes

* **daemon:** a tenant the Platform owner provisions brings its owner in ([#372](https://github.com/zeroroot-ai/gibson/issues/372)) ([cbc70ad](https://github.com/zeroroot-ai/gibson/commit/cbc70ade6fbf2c48c608ad0783a047a773c2517f))
* **daemon:** an MFA reset is not performed without its audit record ([#371](https://github.com/zeroroot-ai/gibson/issues/371)) ([093cb49](https://github.com/zeroroot-ai/gibson/commit/093cb497cf9c2be9875cfb9c24e72d8ce0508b50))

## [0.143.2](https://github.com/zeroroot-ai/gibson/compare/v0.143.1...v0.143.2) (2026-09-29)


### Bug Fixes

* **idp:** a setup mail Zitadel sends names Gibson, not the login client ([#368](https://github.com/zeroroot-ai/gibson/issues/368)) ([8d83ad2](https://github.com/zeroroot-ai/gibson/commit/8d83ad2240d7766ab4e6595fb56967e96df068ce))

## [0.143.1](https://github.com/zeroroot-ai/gibson/compare/v0.143.0...v0.143.1) (2026-09-29)


### Bug Fixes

* **authz:** update a conditioned tuple with two OpenFGA writes, not one ([#366](https://github.com/zeroroot-ai/gibson/issues/366)) ([d3466fd](https://github.com/zeroroot-ai/gibson/commit/d3466fdc5f5b414b8127318dc634c896ead53541))

## [0.143.0](https://github.com/zeroroot-ai/gibson/compare/v0.142.7...v0.143.0) (2026-09-28)


### Features

* **brain:** intelligence layer — belief substrate, betting market, settlement, discovery, VoI planner, daemon API ([#354](https://github.com/zeroroot-ai/gibson/issues/354)) ([6b4b85e](https://github.com/zeroroot-ai/gibson/commit/6b4b85e0f49149c710b644e42fd8d6d394e6faef))

## [0.142.7](https://github.com/zeroroot-ai/gibson/compare/v0.142.6...v0.142.7) (2026-09-28)


### Bug Fixes

* **mfa-reset:** refuse the target's already-issued tokens ([#357](https://github.com/zeroroot-ai/gibson/issues/357)) ([c488eaa](https://github.com/zeroroot-ai/gibson/commit/c488eaae6623bdeaffc664b6ffe15dd627da38e3))

## [0.142.6](https://github.com/zeroroot-ai/gibson/compare/v0.142.5...v0.142.6) (2026-09-28)


### Bug Fixes

* **idp:** reach users in any org from the factor and profile calls ([#349](https://github.com/zeroroot-ai/gibson/issues/349)) ([6c18689](https://github.com/zeroroot-ai/gibson/commit/6c1868918ae04487e029966147cd7614f3326aae))

## [0.142.5](https://github.com/zeroroot-ai/gibson/compare/v0.142.4...v0.142.5) (2026-09-28)


### Bug Fixes

* **invitations:** seed the invitee's session tuples so ext-authz lets them in ([#326](https://github.com/zeroroot-ai/gibson/issues/326)) ([ab936c1](https://github.com/zeroroot-ai/gibson/commit/ab936c111bc4189c68b4d7ccde338fa580cc1f0a))


### Performance Improvements

* **ci:** cache the lint tool binaries and the golangci-lint analysis cache ([#316](https://github.com/zeroroot-ai/gibson/issues/316)) ([7fbff0d](https://github.com/zeroroot-ai/gibson/commit/7fbff0d918c3ad8fd463b420abd97c052eb82aa2)), closes [#308](https://github.com/zeroroot-ai/gibson/issues/308)

## [0.142.4](https://github.com/zeroroot-ai/gibson/compare/v0.142.3...v0.142.4) (2026-09-28)


### Bug Fixes

* **invitations:** create the invitee as an active user, like the owners ([#310](https://github.com/zeroroot-ai/gibson/issues/310)) ([a451c5d](https://github.com/zeroroot-ai/gibson/commit/a451c5df95fdea122c31b282667275afa4d506d3))

## [0.142.3](https://github.com/zeroroot-ai/gibson/compare/v0.142.2...v0.142.3) (2026-09-27)


### Bug Fixes

* **platform-operator:** revoke Zitadel admin rights from undeclared machine users ([#285](https://github.com/zeroroot-ai/gibson/issues/285)) ([f67aa9d](https://github.com/zeroroot-ai/gibson/commit/f67aa9dc68d0e496aff9878fd58a39de40aab932))

## [0.142.2](https://github.com/zeroroot-ai/gibson/compare/v0.142.1...v0.142.2) (2026-09-27)


### Bug Fixes

* **identity:** setup links open the Login v2 verify page ([#261](https://github.com/zeroroot-ai/gibson/issues/261)) ([d142418](https://github.com/zeroroot-ai/gibson/commit/d1424188e20de1603591216c2e3a5b78bf3f390d))

## [0.142.1](https://github.com/zeroroot-ai/gibson/compare/v0.142.0...v0.142.1) (2026-09-27)


### Bug Fixes

* **platform-operator:** keep the Platform owner the only human Zitadel administrator ([#259](https://github.com/zeroroot-ai/gibson/issues/259)) ([9b1af5d](https://github.com/zeroroot-ai/gibson/commit/9b1af5d6b710d489f6aa69ebe78064e94b5a8ae8))
* **platform-operator:** make the Zitadel instance have an active SMTP provider ([#257](https://github.com/zeroroot-ai/gibson/issues/257)) ([e2f4d38](https://github.com/zeroroot-ai/gibson/commit/e2f4d3804f22865cd3d4f4f4e136c2aa72866e18))
* **tenant-operator:** require the chart to size the enterprise-deploy tier ([#258](https://github.com/zeroroot-ai/gibson/issues/258)) ([3865bf9](https://github.com/zeroroot-ai/gibson/commit/3865bf98a843cc5218cc59be9113690fc36381e9))

## [0.142.0](https://github.com/zeroroot-ai/gibson/compare/v0.141.0...v0.142.0) (2026-09-27)


### Features

* **tenant:** let an Owner or Admin reset a tenant user's MFA ([#246](https://github.com/zeroroot-ai/gibson/issues/246)) ([9f73706](https://github.com/zeroroot-ai/gibson/commit/9f73706d857757d1b61c60e70dbd60e124a14417))


### Bug Fixes

* **bootstrap-tenant-owner:** the first tenant's Owner gets a setup link, never a password ([#245](https://github.com/zeroroot-ai/gibson/issues/245)) ([43cc40f](https://github.com/zeroroot-ai/gibson/commit/43cc40f658398c2cd85e2d4596d1e5a66e96b39e))
* **invitations:** accept through a Zitadel setup link, delete org-member API writes ([#255](https://github.com/zeroroot-ai/gibson/issues/255)) ([cd65f90](https://github.com/zeroroot-ai/gibson/commit/cd65f907c884b74383bca8d416b3d6220e2242ad))

## [0.141.0](https://github.com/zeroroot-ai/gibson/compare/v0.140.0...v0.141.0) (2026-09-27)


### Features

* **tenant:** removing a tenant user deletes their Zitadel account ([#244](https://github.com/zeroroot-ai/gibson/issues/244)) ([f510fae](https://github.com/zeroroot-ai/gibson/commit/f510fae2ff97889c518271e7d962cfce0312f7b7))


### Bug Fixes

* **platform-operator:** the Platform owner's setup link names the public host ([#254](https://github.com/zeroroot-ai/gibson/issues/254)) ([0812e75](https://github.com/zeroroot-ai/gibson/commit/0812e75c660f638e5b1819c2e014c63a511fa268))
* **tenantrole:** read Zitadel's totalResult as the string it sends ([#253](https://github.com/zeroroot-ai/gibson/issues/253)) ([873858d](https://github.com/zeroroot-ai/gibson/commit/873858ddb40673c97ddf1420f06ae7a683fc725a))

## [0.140.0](https://github.com/zeroroot-ai/gibson/compare/v0.139.0...v0.140.0) (2026-09-27)


### Features

* **platform-operator:** apply the login branding as a bootstrap step ([#239](https://github.com/zeroroot-ai/gibson/issues/239)) ([711473f](https://github.com/zeroroot-ai/gibson/commit/711473fad44a44d71533debe25caa1949fd65d38))
* **platform-operator:** create the Platform owner from install values ([#240](https://github.com/zeroroot-ai/gibson/issues/240)) ([3ad083a](https://github.com/zeroroot-ai/gibson/commit/3ad083a5462fa99c5198713b9bc1fc916f39d2b3))
* **tenantrole:** sync tenant roles from Zitadel into their FGA copy ([#235](https://github.com/zeroroot-ai/gibson/issues/235)) ([fa2d750](https://github.com/zeroroot-ai/gibson/commit/fa2d7508d849f5305b90a5a2bc166039edde9cf6))


### Bug Fixes

* **platform-operator:** read Zitadel's real project role list ([#241](https://github.com/zeroroot-ai/gibson/issues/241)) ([7491798](https://github.com/zeroroot-ai/gibson/commit/7491798650abd59bdd79f125e860bc2636e49d11))
* **tenant-operator:** call Zitadel as the operator's own machine user ([#238](https://github.com/zeroroot-ai/gibson/issues/238)) ([bd9a704](https://github.com/zeroroot-ai/gibson/commit/bd9a704660c9cb0094d16769079ddc2cced0098f))
* **tenant:** read a listed project grant's grantedRoleKeys ([#243](https://github.com/zeroroot-ai/gibson/issues/243)) ([6819312](https://github.com/zeroroot-ai/gibson/commit/6819312d3ca949abbb8dedd0e18c8f4559bc5754))

## [0.139.0](https://github.com/zeroroot-ai/gibson/compare/v0.138.3...v0.139.0) (2026-09-26)


### Features

* **platform-operator:** create the four tenant roles on the gibson project ([#231](https://github.com/zeroroot-ai/gibson/issues/231)) ([b39870c](https://github.com/zeroroot-ai/gibson/commit/b39870ce8c68f21888b26d1a3a2a99167a01bb3f))
* **zitadelconntest:** add a stateful Identity fake for orgs, roles and grants ([#230](https://github.com/zeroroot-ai/gibson/issues/230)) ([0e095d6](https://github.com/zeroroot-ai/gibson/commit/0e095d67151c2d0af4164952cd4adef89c3b827d))


### Bug Fixes

* **authz:** the tenant comes from the token's org ([#233](https://github.com/zeroroot-ai/gibson/issues/233)) ([d89b720](https://github.com/zeroroot-ai/gibson/commit/d89b72031989ee91c4356f6478d6b7af10ac2da7))
* **platform-operator:** enforce the sign-in policy and unique usernames ([#232](https://github.com/zeroroot-ai/gibson/issues/232)) ([1e8ac63](https://github.com/zeroroot-ai/gibson/commit/1e8ac6385e24857d01e694b5bea95613a9216ab3))
* **platform-operator:** machine users get exactly the roles they declare ([#229](https://github.com/zeroroot-ai/gibson/issues/229)) ([fb88bd4](https://github.com/zeroroot-ai/gibson/commit/fb88bd481c1cb3640475d0f9d233bb9cbcc623d5))
* **tenant:** enforce Owner rules for ownership transfer and role assignment ([#227](https://github.com/zeroroot-ai/gibson/issues/227)) ([5b3ade4](https://github.com/zeroroot-ai/gibson/commit/5b3ade4625ead738aa44bfa77e36a212d6e9ae4d))
* **test:** pull the OpenBao test image from the org mirror ([#234](https://github.com/zeroroot-ai/gibson/issues/234)) ([2e8b5c5](https://github.com/zeroroot-ai/gibson/commit/2e8b5c5d1a83256da3db7b2b86b428a2900804fb))

## [0.138.3](https://github.com/zeroroot-ai/gibson/compare/v0.138.2...v0.138.3) (2026-09-24)


### Bug Fixes

* **idp:** the daemon reaches Zitadel by Service name and claims the host by header ([#224](https://github.com/zeroroot-ai/gibson/issues/224)) ([7343e8b](https://github.com/zeroroot-ai/gibson/commit/7343e8b099c53ced6bfb1197b000f6ef42021bf7))

## [0.138.2](https://github.com/zeroroot-ai/gibson/compare/v0.138.1...v0.138.2) (2026-09-22)


### Bug Fixes

* **identity:** the identity list names the creator and the given name ([#217](https://github.com/zeroroot-ai/gibson/issues/217)) ([a7d857f](https://github.com/zeroroot-ai/gibson/commit/a7d857f0cd15665804f220a13f6c1fdad508f300))

## [0.138.1](https://github.com/zeroroot-ai/gibson/compare/v0.138.0...v0.138.1) (2026-09-22)


### Bug Fixes

* **findings:** stamp the verified principal on a component-path finding ([#212](https://github.com/zeroroot-ai/gibson/issues/212)) ([86f5cbb](https://github.com/zeroroot-ai/gibson/commit/86f5cbbdea780b3dd813ae3ddb6f66c801303904))
* **graph:** read a Finding by the brain_id and title the projector writes ([#211](https://github.com/zeroroot-ai/gibson/issues/211)) ([8fa10d6](https://github.com/zeroroot-ai/gibson/commit/8fa10d66a9a0f95a458a53a00f3aeb3f72ad62ec)), closes [#210](https://github.com/zeroroot-ai/gibson/issues/210)
* **test:** the Postgres TLS helper waits for the real server, not the initdb one ([#206](https://github.com/zeroroot-ai/gibson/issues/206)) ([4baa0f4](https://github.com/zeroroot-ai/gibson/commit/4baa0f4dd597a08bbded94b25a8aa4e90cd75368))

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
