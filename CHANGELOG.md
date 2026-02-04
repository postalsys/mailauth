# Changelog

## [4.13.0](https://github.com/postalsys/mailauth/compare/v4.12.1...v4.13.0) (2026-02-04)


### Features

* **bimi:** add BIMI headers to VMC validation output ([77ce4e8](https://github.com/postalsys/mailauth/commit/77ce4e847d79b2acf319c3b79e865225e4c97040))
* **dkim:** add timestamp, expiration, and validity status to output ([2267eb7](https://github.com/postalsys/mailauth/commit/2267eb77fbcaf79a6c0fb59681815628186a3ae9))


### Bug Fixes

* update Node.js requirement to &gt;=20.18.1 ([3280a59](https://github.com/postalsys/mailauth/commit/3280a597430cf47b640b1cc31e661ab18becf145)), closes [#109](https://github.com/postalsys/mailauth/issues/109)

## [4.12.1](https://github.com/postalsys/mailauth/compare/v4.12.0...v4.12.1) (2026-02-01)


### Bug Fixes

* upgrade fast-xml-parser to 5.3.4 to resolve DoS vulnerability ([60aef5d](https://github.com/postalsys/mailauth/commit/60aef5dfc9883047735975339efc9b1ae3de8f8f))

## [4.12.0](https://github.com/postalsys/mailauth/compare/v4.11.0...v4.12.0) (2025-12-16)


### Features

* add TypeScript type definitions and expand module exports ([c1cf880](https://github.com/postalsys/mailauth/commit/c1cf880a385fac5d2b5ecf5c1e4fa0cd3a319656))


### Bug Fixes

* correct variable name in mta-sts domain extraction ([e68e2d4](https://github.com/postalsys/mailauth/commit/e68e2d4c267130e0defe750cb95a6b8654620cc4))

## [4.11.0](https://github.com/postalsys/mailauth/compare/v4.10.0...v4.11.0) (2025-10-31)


### Features

* added `forwardemail.net` to ARC trusted list ([#86](https://github.com/postalsys/mailauth/issues/86)) ([8cb577b](https://github.com/postalsys/mailauth/commit/8cb577b5cceaf0a61f02744811ad2f9533550032))
* **cert-type:** BIMI authority information includes the type of the cert ('VMC' or 'CMC') ([0dd8db8](https://github.com/postalsys/mailauth/commit/0dd8db81b2ffc8b9d84d1a4396c65bfa9a347088))
* **deploy:** Set up automatic publishing ([f9b9c32](https://github.com/postalsys/mailauth/commit/f9b9c325e4dbac060114aa12c5887ea8c92c0bf8))
* **dkim-sign:** Added new Transfor stream class DkimSignStream to sign emails in a stream processing pipeline ([130a1a3](https://github.com/postalsys/mailauth/commit/130a1a3812fac2ad710f244510ca60887c2d33a9))


### Bug Fixes

* **ARC:** ensure that instance value is 1 if ARC chain does not exist yet ([ab4c5e9](https://github.com/postalsys/mailauth/commit/ab4c5e9ae0158e196b10f346321ca55b8f06c679))
* **ARC:** Updated built-in trust list for ARC ([ea9fc8c](https://github.com/postalsys/mailauth/commit/ea9fc8c6f8c5609b66053f1ffe95891c0b4efcb7))
* **bimi:** Bumped VMC module to add support for GLobalSign VMC root ([d0e9ecf](https://github.com/postalsys/mailauth/commit/d0e9ecf89b699aae8ad9953445f052b558250f5a))
* **bimi:** skip bimi with oversized DKIM signatures ([d666d74](https://github.com/postalsys/mailauth/commit/d666d7476cbcae8b3161c78a7e737559ad112fd9))
* **BodyHashStream:** Skip header ([3da03d2](https://github.com/postalsys/mailauth/commit/3da03d23baa90acb119c7946c2cd740a72ba069d))
* bumped 2022 in copyright notices to 2024 ([cc89823](https://github.com/postalsys/mailauth/commit/cc8982349d14b42a28581ebc52aa6de2e11b5be8))
* bumped deps ([006475e](https://github.com/postalsys/mailauth/commit/006475ee7bbf61a8c7c00de793f4007f66dba61a))
* **cli:** Updated help strings for the cli script ([8a86e51](https://github.com/postalsys/mailauth/commit/8a86e51bff0300a7daea26062481ac56904202a8))
* configure release-please to use v-only tags ([122e030](https://github.com/postalsys/mailauth/commit/122e0305b2e45715f427fdc5b6351819de1a3b59))
* **deps:** Bumped deps to clear out security warnings ([4ca35fe](https://github.com/postalsys/mailauth/commit/4ca35fef37e37ae715c420b8a52c7cb202e4b360))
* **deps:** Bumped deps to get updated vmc root store ([5ad7464](https://github.com/postalsys/mailauth/commit/5ad746450f97d348217607802e83445e08737faf))
* **deps:** Removed uuid dependency in favor of crypto.randomUUID() ([0b5d8f5](https://github.com/postalsys/mailauth/commit/0b5d8f5328d0b82f75daea7fdbd74e1e76e8b642))
* **dkim-relaxed:** Faster DKIM hash calculation for relaxed body if the body contains extremely long lines ([fd8c89e](https://github.com/postalsys/mailauth/commit/fd8c89edd87a114464f99ebf79a1e903a8287876))
* **dkim-verify:** Show the length of the source body in DKIM results ([d28663b](https://github.com/postalsys/mailauth/commit/d28663b30b0bfaf07d395e9d3eaea044c9085657))
* **dkim:** Added new output property mimeStructureStart ([8f25353](https://github.com/postalsys/mailauth/commit/8f25353fa6a67ba3e1f0c5091325007b2434a29d))
* **dkim:** New class BodyHashStream ([88d2fad](https://github.com/postalsys/mailauth/commit/88d2fad329a9a6fc8ebc1da4efc1c4844ae49507))
* **dkim:** Store byteLength in BodyHashStream ([081f823](https://github.com/postalsys/mailauth/commit/081f82340505d4beb88f12728919d851d35b6576))
* **dmarc-alignment:** Fixed tldts usage to allow private domains ([cc7dfa8](https://github.com/postalsys/mailauth/commit/cc7dfa8d820c1a4112602340192010354d51cd52))
* downgraded yargs because of ESM ([215c71a](https://github.com/postalsys/mailauth/commit/215c71aaa108744970533f346408c41b38590500))
* **ed25519:** Fixed ed25519 signing and verification ([40f1245](https://github.com/postalsys/mailauth/commit/40f12457d8f49f0ea21015fe4203b4de746ab7b8))
* expose verifyASChain ([#89](https://github.com/postalsys/mailauth/issues/89)) ([cd11d85](https://github.com/postalsys/mailauth/commit/cd11d851f3c8cea125209676f3ba26676c700c5b))
* protect against prototype pollution ([3b7515d](https://github.com/postalsys/mailauth/commit/3b7515df768ce1d2e4e02858fdfca8efca6243fb))
* **psl:** Replaced psl module with tldts for up to date public suffix list ([cab894b](https://github.com/postalsys/mailauth/commit/cab894b54a3544b33a641f377783db67a43bec0e))
* **spf:** expand macros in mx mechanism ([d8c05f9](https://github.com/postalsys/mailauth/commit/d8c05f90589e3fb5a56ecb4498e6dcb795dcc047))
* **spf:** optimize dual-stack A/AAAA void lookup counting ([3069e5a](https://github.com/postalsys/mailauth/commit/3069e5afa946589e54fe8aec8ffe186d90eca810))
* use minLength option for rsa keys ([#84](https://github.com/postalsys/mailauth/issues/84)) ([cbfed81](https://github.com/postalsys/mailauth/commit/cbfed816d953eee3c7eed99055c53f689a46a101))
* ZMS-246: add required policy headers in BIMI for Apple Mail ([#92](https://github.com/postalsys/mailauth/issues/92)) ([f6b3008](https://github.com/postalsys/mailauth/commit/f6b300837f9453877386ce3e76aff80fee01d913))
* ZMS-262 remove control chars from record add support for mappers in validateTagValueRecord ([#95](https://github.com/postalsys/mailauth/issues/95)) ([42828a6](https://github.com/postalsys/mailauth/commit/42828a6cb38add3aed35881f102488f8143407cb))
* ZMS-262: Add raw record sanitanization and validation util functions ([#93](https://github.com/postalsys/mailauth/issues/93)) ([e4842cf](https://github.com/postalsys/mailauth/commit/e4842cf222bd6db29f34c25434b5c38c44edefdc))

## [4.10.0](https://github.com/postalsys/mailauth/compare/mailauth-v4.9.5...mailauth-v4.10.0) (2025-10-31)


### Features

* added `forwardemail.net` to ARC trusted list ([#86](https://github.com/postalsys/mailauth/issues/86)) ([8cb577b](https://github.com/postalsys/mailauth/commit/8cb577b5cceaf0a61f02744811ad2f9533550032))
* **cert-type:** BIMI authority information includes the type of the cert ('VMC' or 'CMC') ([0dd8db8](https://github.com/postalsys/mailauth/commit/0dd8db81b2ffc8b9d84d1a4396c65bfa9a347088))
* **deploy:** Set up automatic publishing ([f9b9c32](https://github.com/postalsys/mailauth/commit/f9b9c325e4dbac060114aa12c5887ea8c92c0bf8))
* **dkim-sign:** Added new Transfor stream class DkimSignStream to sign emails in a stream processing pipeline ([130a1a3](https://github.com/postalsys/mailauth/commit/130a1a3812fac2ad710f244510ca60887c2d33a9))


### Bug Fixes

* **ARC:** ensure that instance value is 1 if ARC chain does not exist yet ([ab4c5e9](https://github.com/postalsys/mailauth/commit/ab4c5e9ae0158e196b10f346321ca55b8f06c679))
* **ARC:** Updated built-in trust list for ARC ([ea9fc8c](https://github.com/postalsys/mailauth/commit/ea9fc8c6f8c5609b66053f1ffe95891c0b4efcb7))
* **bimi:** Bumped VMC module to add support for GLobalSign VMC root ([d0e9ecf](https://github.com/postalsys/mailauth/commit/d0e9ecf89b699aae8ad9953445f052b558250f5a))
* **bimi:** skip bimi with oversized DKIM signatures ([d666d74](https://github.com/postalsys/mailauth/commit/d666d7476cbcae8b3161c78a7e737559ad112fd9))
* **BodyHashStream:** Skip header ([3da03d2](https://github.com/postalsys/mailauth/commit/3da03d23baa90acb119c7946c2cd740a72ba069d))
* bumped 2022 in copyright notices to 2024 ([cc89823](https://github.com/postalsys/mailauth/commit/cc8982349d14b42a28581ebc52aa6de2e11b5be8))
* bumped deps ([006475e](https://github.com/postalsys/mailauth/commit/006475ee7bbf61a8c7c00de793f4007f66dba61a))
* **cli:** Updated help strings for the cli script ([8a86e51](https://github.com/postalsys/mailauth/commit/8a86e51bff0300a7daea26062481ac56904202a8))
* **deps:** Bumped deps to clear out security warnings ([4ca35fe](https://github.com/postalsys/mailauth/commit/4ca35fef37e37ae715c420b8a52c7cb202e4b360))
* **deps:** Bumped deps to get updated vmc root store ([5ad7464](https://github.com/postalsys/mailauth/commit/5ad746450f97d348217607802e83445e08737faf))
* **deps:** Removed uuid dependency in favor of crypto.randomUUID() ([0b5d8f5](https://github.com/postalsys/mailauth/commit/0b5d8f5328d0b82f75daea7fdbd74e1e76e8b642))
* **dkim-relaxed:** Faster DKIM hash calculation for relaxed body if the body contains extremely long lines ([fd8c89e](https://github.com/postalsys/mailauth/commit/fd8c89edd87a114464f99ebf79a1e903a8287876))
* **dkim-verify:** Show the length of the source body in DKIM results ([d28663b](https://github.com/postalsys/mailauth/commit/d28663b30b0bfaf07d395e9d3eaea044c9085657))
* **dkim:** Added new output property mimeStructureStart ([8f25353](https://github.com/postalsys/mailauth/commit/8f25353fa6a67ba3e1f0c5091325007b2434a29d))
* **dkim:** New class BodyHashStream ([88d2fad](https://github.com/postalsys/mailauth/commit/88d2fad329a9a6fc8ebc1da4efc1c4844ae49507))
* **dkim:** Store byteLength in BodyHashStream ([081f823](https://github.com/postalsys/mailauth/commit/081f82340505d4beb88f12728919d851d35b6576))
* **dmarc-alignment:** Fixed tldts usage to allow private domains ([cc7dfa8](https://github.com/postalsys/mailauth/commit/cc7dfa8d820c1a4112602340192010354d51cd52))
* downgraded yargs because of ESM ([215c71a](https://github.com/postalsys/mailauth/commit/215c71aaa108744970533f346408c41b38590500))
* **ed25519:** Fixed ed25519 signing and verification ([40f1245](https://github.com/postalsys/mailauth/commit/40f12457d8f49f0ea21015fe4203b4de746ab7b8))
* expose verifyASChain ([#89](https://github.com/postalsys/mailauth/issues/89)) ([cd11d85](https://github.com/postalsys/mailauth/commit/cd11d851f3c8cea125209676f3ba26676c700c5b))
* protect against prototype pollution ([3b7515d](https://github.com/postalsys/mailauth/commit/3b7515df768ce1d2e4e02858fdfca8efca6243fb))
* **psl:** Replaced psl module with tldts for up to date public suffix list ([cab894b](https://github.com/postalsys/mailauth/commit/cab894b54a3544b33a641f377783db67a43bec0e))
* **spf:** expand macros in mx mechanism ([d8c05f9](https://github.com/postalsys/mailauth/commit/d8c05f90589e3fb5a56ecb4498e6dcb795dcc047))
* **spf:** optimize dual-stack A/AAAA void lookup counting ([3069e5a](https://github.com/postalsys/mailauth/commit/3069e5afa946589e54fe8aec8ffe186d90eca810))
* use minLength option for rsa keys ([#84](https://github.com/postalsys/mailauth/issues/84)) ([cbfed81](https://github.com/postalsys/mailauth/commit/cbfed816d953eee3c7eed99055c53f689a46a101))
* ZMS-246: add required policy headers in BIMI for Apple Mail ([#92](https://github.com/postalsys/mailauth/issues/92)) ([f6b3008](https://github.com/postalsys/mailauth/commit/f6b300837f9453877386ce3e76aff80fee01d913))
* ZMS-262 remove control chars from record add support for mappers in validateTagValueRecord ([#95](https://github.com/postalsys/mailauth/issues/95)) ([42828a6](https://github.com/postalsys/mailauth/commit/42828a6cb38add3aed35881f102488f8143407cb))
* ZMS-262: Add raw record sanitanization and validation util functions ([#93](https://github.com/postalsys/mailauth/issues/93)) ([e4842cf](https://github.com/postalsys/mailauth/commit/e4842cf222bd6db29f34c25434b5c38c44edefdc))

## [4.9.5](https://github.com/postalsys/mailauth/compare/v4.9.4...v4.9.5) (2025-09-10)


### Bug Fixes

* **spf:** expand macros in mx mechanism ([d8c05f9](https://github.com/postalsys/mailauth/commit/d8c05f90589e3fb5a56ecb4498e6dcb795dcc047))

## [4.9.4](https://github.com/postalsys/mailauth/compare/v4.9.3...v4.9.4) (2025-09-02)


### Bug Fixes

* downgraded yargs because of ESM ([215c71a](https://github.com/postalsys/mailauth/commit/215c71aaa108744970533f346408c41b38590500))

## [4.9.3](https://github.com/postalsys/mailauth/compare/v4.9.2...v4.9.3) (2025-09-02)


### Bug Fixes

* bumped deps ([006475e](https://github.com/postalsys/mailauth/commit/006475ee7bbf61a8c7c00de793f4007f66dba61a))

## [4.9.2](https://github.com/postalsys/mailauth/compare/v4.9.1...v4.9.2) (2025-08-28)


### Bug Fixes

* ZMS-262 remove control chars from record add support for mappers in validateTagValueRecord ([#95](https://github.com/postalsys/mailauth/issues/95)) ([42828a6](https://github.com/postalsys/mailauth/commit/42828a6cb38add3aed35881f102488f8143407cb))

## [4.9.1](https://github.com/postalsys/mailauth/compare/v4.9.0...v4.9.1) (2025-08-27)


### Bug Fixes

* ZMS-262: Add raw record sanitanization and validation util functions ([#93](https://github.com/postalsys/mailauth/issues/93)) ([e4842cf](https://github.com/postalsys/mailauth/commit/e4842cf222bd6db29f34c25434b5c38c44edefdc))

## [4.9.0](https://github.com/postalsys/mailauth/compare/v4.8.6...v4.9.0) (2025-08-21)


### Features

* added `forwardemail.net` to ARC trusted list ([#86](https://github.com/postalsys/mailauth/issues/86)) ([8cb577b](https://github.com/postalsys/mailauth/commit/8cb577b5cceaf0a61f02744811ad2f9533550032))


### Bug Fixes

* expose verifyASChain ([#89](https://github.com/postalsys/mailauth/issues/89)) ([cd11d85](https://github.com/postalsys/mailauth/commit/cd11d851f3c8cea125209676f3ba26676c700c5b))
* ZMS-246: add required policy headers in BIMI for Apple Mail ([#92](https://github.com/postalsys/mailauth/issues/92)) ([f6b3008](https://github.com/postalsys/mailauth/commit/f6b300837f9453877386ce3e76aff80fee01d913))

## [4.8.6](https://github.com/postalsys/mailauth/compare/v4.8.5...v4.8.6) (2025-05-26)


### Bug Fixes

* **ARC:** Updated built-in trust list for ARC ([ea9fc8c](https://github.com/postalsys/mailauth/commit/ea9fc8c6f8c5609b66053f1ffe95891c0b4efcb7))
* use minLength option for rsa keys ([#84](https://github.com/postalsys/mailauth/issues/84)) ([cbfed81](https://github.com/postalsys/mailauth/commit/cbfed816d953eee3c7eed99055c53f689a46a101))

## [4.8.5](https://github.com/postalsys/mailauth/compare/v4.8.4...v4.8.5) (2025-05-11)


### Bug Fixes

* **deps:** Bumped deps to get updated vmc root store ([5ad7464](https://github.com/postalsys/mailauth/commit/5ad746450f97d348217607802e83445e08737faf))

## [4.8.4](https://github.com/postalsys/mailauth/compare/v4.8.3...v4.8.4) (2025-04-21)


### Bug Fixes

* **bimi:** Bumped VMC module to add support for GLobalSign VMC root ([d0e9ecf](https://github.com/postalsys/mailauth/commit/d0e9ecf89b699aae8ad9953445f052b558250f5a))

## [4.8.3](https://github.com/postalsys/mailauth/compare/v4.8.2...v4.8.3) (2025-04-20)


### Bug Fixes

* protect against prototype pollution ([3b7515d](https://github.com/postalsys/mailauth/commit/3b7515df768ce1d2e4e02858fdfca8efca6243fb))

## [4.8.2](https://github.com/postalsys/mailauth/compare/v4.8.1...v4.8.2) (2024-12-19)


### Bug Fixes

* **ARC:** ensure that instance value is 1 if ARC chain does not exist yet ([ab4c5e9](https://github.com/postalsys/mailauth/commit/ab4c5e9ae0158e196b10f346321ca55b8f06c679))

## [4.8.1](https://github.com/postalsys/mailauth/compare/v4.8.0...v4.8.1) (2024-11-05)


### Bug Fixes

* **cli:** Updated help strings for the cli script ([8a86e51](https://github.com/postalsys/mailauth/commit/8a86e51bff0300a7daea26062481ac56904202a8))

## [4.8.0](https://github.com/postalsys/mailauth/compare/v4.7.3...v4.8.0) (2024-11-05)


### Features

* **cert-type:** BIMI authority information includes the type of the cert ('VMC' or 'CMC') ([0dd8db8](https://github.com/postalsys/mailauth/commit/0dd8db81b2ffc8b9d84d1a4396c65bfa9a347088))

## [4.7.3](https://github.com/postalsys/mailauth/compare/v4.7.2...v4.7.3) (2024-10-21)


### Bug Fixes

* **BodyHashStream:** Skip header ([3da03d2](https://github.com/postalsys/mailauth/commit/3da03d23baa90acb119c7946c2cd740a72ba069d))

## [4.7.2](https://github.com/postalsys/mailauth/compare/v4.7.1...v4.7.2) (2024-10-02)


### Bug Fixes

* **dkim:** Store byteLength in BodyHashStream ([081f823](https://github.com/postalsys/mailauth/commit/081f82340505d4beb88f12728919d851d35b6576))

## [4.7.1](https://github.com/postalsys/mailauth/compare/v4.7.0...v4.7.1) (2024-10-02)


### Bug Fixes

* **dkim:** New class BodyHashStream ([88d2fad](https://github.com/postalsys/mailauth/commit/88d2fad329a9a6fc8ebc1da4efc1c4844ae49507))

## [4.7.0](https://github.com/postalsys/mailauth/compare/v4.6.9...v4.7.0) (2024-10-02)


### Features

* **dkim-sign:** Added new Transfor stream class DkimSignStream to sign emails in a stream processing pipeline ([130a1a3](https://github.com/postalsys/mailauth/commit/130a1a3812fac2ad710f244510ca60887c2d33a9))

## [4.6.9](https://github.com/postalsys/mailauth/compare/v4.6.8...v4.6.9) (2024-08-22)


### Bug Fixes

* **deps:** Removed uuid dependency in favor of crypto.randomUUID() ([0b5d8f5](https://github.com/postalsys/mailauth/commit/0b5d8f5328d0b82f75daea7fdbd74e1e76e8b642))
* **dkim-relaxed:** Faster DKIM hash calculation for relaxed body if the body contains extremely long lines ([fd8c89e](https://github.com/postalsys/mailauth/commit/fd8c89edd87a114464f99ebf79a1e903a8287876))

## [4.6.8](https://github.com/postalsys/mailauth/compare/v4.6.7...v4.6.8) (2024-06-04)


### Bug Fixes

* **dmarc-alignment:** Fixed tldts usage to allow private domains ([cc7dfa8](https://github.com/postalsys/mailauth/commit/cc7dfa8d820c1a4112602340192010354d51cd52))

## [4.6.7](https://github.com/postalsys/mailauth/compare/v4.6.6...v4.6.7) (2024-05-30)


### Bug Fixes

* **psl:** Replaced psl module with tldts for up to date public suffix list ([cab894b](https://github.com/postalsys/mailauth/commit/cab894b54a3544b33a641f377783db67a43bec0e))

## [4.6.6](https://github.com/postalsys/mailauth/compare/v4.6.5...v4.6.6) (2024-05-13)


### Bug Fixes

* **deps:** Bumped deps to clear out security warnings ([4ca35fe](https://github.com/postalsys/mailauth/commit/4ca35fef37e37ae715c420b8a52c7cb202e4b360))

## [4.6.5](https://github.com/postalsys/mailauth/compare/v4.6.4...v4.6.5) (2024-02-12)


### Bug Fixes

* **dkim:** Added new output property mimeStructureStart ([8f25353](https://github.com/postalsys/mailauth/commit/8f25353fa6a67ba3e1f0c5091325007b2434a29d))

## [4.6.4](https://github.com/postalsys/mailauth/compare/v4.6.3...v4.6.4) (2024-02-05)


### Bug Fixes

* **ed25519:** Fixed ed25519 signing and verification ([40f1245](https://github.com/postalsys/mailauth/commit/40f12457d8f49f0ea21015fe4203b4de746ab7b8))

## [4.6.3](https://github.com/postalsys/mailauth/compare/v4.6.2...v4.6.3) (2024-01-26)


### Bug Fixes

* bumped 2022 in copyright notices to 2024 ([cc89823](https://github.com/postalsys/mailauth/commit/cc8982349d14b42a28581ebc52aa6de2e11b5be8))

## [4.6.2](https://github.com/postalsys/mailauth/compare/v4.6.1...v4.6.2) (2024-01-25)

### Bug Fixes

-   **bimi:** skip bimi with undersized DKIM signatures ([d666d74](https://github.com/postalsys/mailauth/commit/d666d7476cbcae8b3161c78a7e737559ad112fd9))

## [4.6.1](https://github.com/postalsys/mailauth/compare/v4.6.0...v4.6.1) (2024-01-24)

### Bug Fixes

-   **dkim-verify:** Show the length of the source body in DKIM results ([d28663b](https://github.com/postalsys/mailauth/commit/d28663b30b0bfaf07d395e9d3eaea044c9085657))

## [4.6.0](https://github.com/postalsys/mailauth/compare/v4.5.2...v4.6.0) (2023-11-02)

### Features

-   **deploy:** Set up automatic publishing ([f9b9c32](https://github.com/postalsys/mailauth/commit/f9b9c325e4dbac060114aa12c5887ea8c92c0bf8))
