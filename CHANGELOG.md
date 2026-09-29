# Changelog

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
