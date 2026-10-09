# Changelog

## [7.2.0](https://github.com/postalsys/mailauth/compare/v7.1.1...v7.2.0) (2026-10-09)


### Features

* **bimi:** apply the exact Assertion Record syntax in strict mode ([85c4363](https://github.com/postalsys/mailauth/commit/85c4363f3238ce0ba80cbece81abf5af92bb0840)), closes [#166](https://github.com/postalsys/mailauth/issues/166)
* **dkim:** over-sign header field names repeated in headerList ([021218f](https://github.com/postalsys/mailauth/commit/021218fd733ccb86f941e8aa9a80e2add7967b0e)), closes [#153](https://github.com/postalsys/mailauth/issues/153)


### Bug Fixes

* **arc:** check a large authResults value without running out of stack ([624e8a3](https://github.com/postalsys/mailauth/commit/624e8a3bfd881d81f783f496a1ffc7c8a24bebba))
* **arc:** do not modify the caller's seal options ([5c57a9d](https://github.com/postalsys/mailauth/commit/5c57a9dd1be2b24dbb32ee78b04f2ca41f47c26d)), closes [#159](https://github.com/postalsys/mailauth/issues/159)
* **arc:** fail a chain whose d= is not a host name ([2f0babe](https://github.com/postalsys/mailauth/commit/2f0babeac0fe41b17bde53c110d54c3f04a748b3))
* **arc:** refuse an ARC-Authentication-Results value that breaks the header ([43713b4](https://github.com/postalsys/mailauth/commit/43713b4aa9cd7e3efff5bc35e11385d0c4be758a)), closes [#161](https://github.com/postalsys/mailauth/issues/161)
* **arc:** seal a malformed chain with cv=fail ([c9a4e85](https://github.com/postalsys/mailauth/commit/c9a4e8555d7e1f525d67d855a3a6737d69124dbe)), closes [#162](https://github.com/postalsys/mailauth/issues/162)
* **arc:** seal with the computed chain status and AAR in authenticate() ([d6f7efc](https://github.com/postalsys/mailauth/commit/d6f7efcd35fa14489c3adc089b430818e5bab806)), closes [#160](https://github.com/postalsys/mailauth/issues/160)
* **auth-results:** write a U-label domain unquoted in strict mode ([a24ffd6](https://github.com/postalsys/mailauth/commit/a24ffd631bdae835edcbe65a28e357d33f60be00)), closes [#169](https://github.com/postalsys/mailauth/issues/169)
* **bimi:** check the SVG Tiny PS document rules, add strict mode ([4cf9bfc](https://github.com/postalsys/mailauth/commit/4cf9bfc31ece9b8f2a477db841808c038da65b49)), closes [#165](https://github.com/postalsys/mailauth/issues/165)
* **bimi:** count From addresses with the parser of the DMARC check ([0fb165e](https://github.com/postalsys/mailauth/commit/0fb165eb00a06b0fd372e7bb757e99528479f583))
* **bimi:** ignore an invalid BIMI-Selector header ([7f62164](https://github.com/postalsys/mailauth/commit/7f6216476b2eda34c91dde23f3c047e07ed67471)), closes [#167](https://github.com/postalsys/mailauth/issues/167)
* **bimi:** read the avp= avatar preference tag ([f577b50](https://github.com/postalsys/mailauth/commit/f577b5056476a5ffda325d44e7cfe0d7a8eb7547)), closes [#164](https://github.com/postalsys/mailauth/issues/164)
* **bimi:** report validateVMC() results in Authentication-Results ([6b03caa](https://github.com/postalsys/mailauth/commit/6b03caa9ffba2bc0e1d86177ad5a2b1f4f9d55d6)), closes [#168](https://github.com/postalsys/mailauth/issues/168)
* **bimi:** restrict logo and evidence downloads ([658d8c2](https://github.com/postalsys/mailauth/commit/658d8c22fb3087a37f5ccbd4f0b1e874d7f53fd2))
* **bimi:** validate logos against an SVG Tiny PS element allowlist ([0cf9679](https://github.com/postalsys/mailauth/commit/0cf9679c3fb185a63fd3541350a62cf68eda04c8))
* **bimi:** validate the logo from l= before building BIMI headers ([bdc7b90](https://github.com/postalsys/mailauth/commit/bdc7b907f329c1af1a983e7f845e901621aaee09))
* **dkim:** check the key type against a= in both modes ([4b9ef52](https://github.com/postalsys/mailauth/commit/4b9ef52f446486611b622e2f1e2fb82656e85223)), closes [#146](https://github.com/postalsys/mailauth/issues/146)
* **dkim:** encode i= as dkim-quoted-printable and check its syntax ([59f63e1](https://github.com/postalsys/mailauth/commit/59f63e1334565605979d4e9d8b8d364cd1f9c365)), closes [#150](https://github.com/postalsys/mailauth/issues/150)
* **dkim:** never align a signature when From has no single Author Domain ([ac882e2](https://github.com/postalsys/mailauth/commit/ac882e26bca1dd0c88ee7afc3cffecbb4d47db51))
* **dkim:** parse key records without removing whitespace inside values ([4b40376](https://github.com/postalsys/mailauth/commit/4b4037603d5b45e628f962ae2e986221b4eb4fdb)), closes [#149](https://github.com/postalsys/mailauth/issues/149)
* **dkim:** read the canonicalization option like a c= value ([1383056](https://github.com/postalsys/mailauth/commit/1383056d50220a0f61698964f35493a381335143)), closes [#152](https://github.com/postalsys/mailauth/issues/152)
* **dkim:** reject a d= that is not a host name and never align it ([387db0c](https://github.com/postalsys/mailauth/commit/387db0c639903fab54fa49d2674329664e7ffeca))
* **dkim:** reject an l= larger than the canonicalized body in strict mode ([5139833](https://github.com/postalsys/mailauth/commit/5139833901adeef37443d53fd3ad8960188dabae)), closes [#147](https://github.com/postalsys/mailauth/issues/147)
* **dkim:** report a key record name that can not exist as no key ([d4f60ca](https://github.com/postalsys/mailauth/commit/d4f60cace9e8a555964a140476aa616aa2de005c)), closes [#145](https://github.com/postalsys/mailauth/issues/145)
* **dkim:** report signatures that are skipped for a missing key ([bda5402](https://github.com/postalsys/mailauth/commit/bda540242cc93e6cefe73c5b75efbb8f41544163)), closes [#151](https://github.com/postalsys/mailauth/issues/151)
* **dkim:** validate the c= syntax and canonicalize with the parsed value ([5da00a5](https://github.com/postalsys/mailauth/commit/5da00a553f45482e6ef5209d6894c196401a0fbc)), closes [#148](https://github.com/postalsys/mailauth/issues/148)
* **dmarc:** discard a policy record with whitespace before v=DMARC1 in strict mode ([d84decf](https://github.com/postalsys/mailauth/commit/d84decf7db25efd3385d0102410d0e2aa1f458d7)), closes [#143](https://github.com/postalsys/mailauth/issues/143)
* **dmarc:** discard record fragments without "=" ([0cdcf56](https://github.com/postalsys/mailauth/commit/0cdcf56e1ea9d55c4c614cd7214c74fc783729fb)), closes [#142](https://github.com/postalsys/mailauth/issues/142)
* **dmarc:** parse the From header by the RFC 5322 grammar ([08da841](https://github.com/postalsys/mailauth/commit/08da8419de7aa987cd04a366c3d04fe6b858d4d9))
* **dmarc:** reject a From local-part with a domain literal between its words ([ec0af9e](https://github.com/postalsys/mailauth/commit/ec0af9e7adc895170357e408c1598cbdb8f3fc03))
* **dmarc:** reject an Author Domain with control or format characters ([e1f1bb7](https://github.com/postalsys/mailauth/commit/e1f1bb7e79327e9cc92d665cb85c645cc36ab35f))
* **mailauth:** use the HELO name from the Received header with trustReceived ([f7e2869](https://github.com/postalsys/mailauth/commit/f7e2869f1b6009863945698b337527be289d3fab)), closes [#156](https://github.com/postalsys/mailauth/issues/156)
* **mta-sts:** limit retries of a new policy ID while a cached policy is used ([599b988](https://github.com/postalsys/mailauth/commit/599b988b992be4a5b4ddda6b69cfb32565c95924)), closes [#170](https://github.com/postalsys/mailauth/issues/170)
* **received:** do not guess the client IP when the HELO adds ";" or Exim comments ([49b9a45](https://github.com/postalsys/mailauth/commit/49b9a45422aa8973e4c8b0de7004bfd4ef705a20))
* **received:** take the client IP only from an unambiguous from clause ([be23ede](https://github.com/postalsys/mailauth/commit/be23edebe3115040367fc77f0c30323fa6726f70))
* **spf:** accept 0 for maxVoidCount and maxResolveCount ([e1826d7](https://github.com/postalsys/mailauth/commit/e1826d7a25d5f3121b109bed467b4e3834100ded)), closes [#158](https://github.com/postalsys/mailauth/issues/158)
* **spf:** accept a MAIL FROM or HELO domain with a single trailing dot ([11256ae](https://github.com/postalsys/mailauth/commit/11256ae23a8c653394e5998e7c39c58b5e0ff04d))
* **spf:** check the expanded explanation string for US-ASCII ([b4e844e](https://github.com/postalsys/mailauth/commit/b4e844e814b368769466dff063246972271a8f36)), closes [#155](https://github.com/postalsys/mailauth/issues/155)
* **spf:** do not count the %{p} PTR query as a void lookup ([46f3298](https://github.com/postalsys/mailauth/commit/46f3298fcb672a5897d94e6b792219a68091bb9f)), closes [#154](https://github.com/postalsys/mailauth/issues/154)
* **spf:** report the reason of macro syntax errors in the permerror comment ([d3fe2bf](https://github.com/postalsys/mailauth/commit/d3fe2bfbce43550a27b8dac5a27931e55297203f)), closes [#157](https://github.com/postalsys/mailauth/issues/157)
* **spf:** split macro values on exactly the delimiters that are listed ([98c32c0](https://github.com/postalsys/mailauth/commit/98c32c09054a6651cacda089c07ddd22ff5fd470))
* **types:** mark DMARCResult policy fields optional and cite RFC 9989 9.1 ([10dd7fe](https://github.com/postalsys/mailauth/commit/10dd7fee7e7fa8994649ffd7409d97a3a722c316)), closes [#144](https://github.com/postalsys/mailauth/issues/144)

## [7.1.1](https://github.com/postalsys/mailauth/compare/v7.1.0...v7.1.1) (2026-10-04)


### Bug Fixes

* **deps:** update libmime to 5.4.7 and nodemailer to 10.0.14 ([0c39b00](https://github.com/postalsys/mailauth/commit/0c39b007889bb58aaf55d39d1867fc7b0df73158))

## [7.1.0](https://github.com/postalsys/mailauth/compare/v7.0.0...v7.1.0) (2026-09-27)


### Features

* **cli:** add --reject-rsa-sha1 to the report command ([#140](https://github.com/postalsys/mailauth/issues/140)) ([fc8e965](https://github.com/postalsys/mailauth/commit/fc8e9651e304ff6d9f3249e2f3c1db7e481c7d8c))
* **dkim:** add rejectRsaSha1 to reject rsa-sha1 signatures without the strict mode ([#138](https://github.com/postalsys/mailauth/issues/138)) ([92d2c23](https://github.com/postalsys/mailauth/commit/92d2c23027d443dc62dc93a49b54d561beb3f2ed))


### Bug Fixes

* **dmarc:** count a subdomain with a dangling CNAME as existing for np ([#137](https://github.com/postalsys/mailauth/issues/137)) ([b38ecef](https://github.com/postalsys/mailauth/commit/b38ecef53b56e479863dd96cae1a6fe24c970353))

## [7.0.0](https://github.com/postalsys/mailauth/compare/v6.0.0...v7.0.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **dmarc:** the DMARC result no longer has pct, which is historic in RFC 9989, and BIMI no longer reads it. policy can differ from before for non-existent subdomains (np), for t=y records, and for records with an invalid p, sp or np.

### Features

* **dmarc:** apply np, t and the RFC 9989 rules for invalid policies ([c11740c](https://github.com/postalsys/mailauth/commit/c11740c0c9b18a9329e82c5eacfb63cfb3a3420a))
* fix RFC compliance findings and add a strict mode ([#136](https://github.com/postalsys/mailauth/issues/136)) ([62e0dd1](https://github.com/postalsys/mailauth/commit/62e0dd16359b3964cb579230035a980bf054a06f))

## [6.0.0](https://github.com/postalsys/mailauth/compare/v5.0.3...v6.0.0) (2026-09-26)


### ⚠ BREAKING CHANGES

* **dmarc:** DMARC verdicts can change. A subdomain whose parent publishes no record is now its own Organizational Domain, so a signature or SPF domain of the parent no longer aligns with it. Subdomains of names the Public Suffix List lists as suffixes but that publish a DMARC record (for example blogspot.com) now inherit that policy. The result's domain is the Tree Walk Organizational Domain, and is the author domain when no record is found.

### Features

* **dmarc:** find policies and organizational domains with the RFC 9989 DNS Tree Walk ([8ab1da2](https://github.com/postalsys/mailauth/commit/8ab1da24aa5f1be7939393bd79a9834802aa911d))

## [5.0.3](https://github.com/postalsys/mailauth/compare/v5.0.2...v5.0.3) (2026-09-03)


### Bug Fixes

* **dkim:** canonicalize a CR that is not a line ending as body content ([68dfb42](https://github.com/postalsys/mailauth/commit/68dfb4262fdae1bedb17019ab8c3c59bc2f4cf8d))
* **dkim:** canonicalize a lone CR as body content in the simple algorithm ([aa54b0e](https://github.com/postalsys/mailauth/commit/aa54b0e75f65a274d2f56ea4df6f58bc86c080fc))
* **dkim:** fold a header line that is not a well formed field ([227cf48](https://github.com/postalsys/mailauth/commit/227cf48fb42dbb93bcebfd1acbc8484032e03db9))
* **dkim:** read the signature timestamp once per signature ([c8c6cd8](https://github.com/postalsys/mailauth/commit/c8c6cd8d41fd176d59522bde85022b7ab0f1e324))
* **dkim:** sign and verify a message that has no body ([0b7c6ed](https://github.com/postalsys/mailauth/commit/0b7c6ed6723a8cdf2f65334af7d0783a373ab5e8))
* **dkim:** stop emitting signatures and seals that cover nothing ([4eefa97](https://github.com/postalsys/mailauth/commit/4eefa9793fa6755d2e11b1fcaa4581b7f1b32515))
* **dkim:** treat only SP and HTAB as whitespace in header canonicalization ([734db62](https://github.com/postalsys/mailauth/commit/734db62d09376c631e548f6c8b44a56ba38659c5))

## [5.0.2](https://github.com/postalsys/mailauth/compare/v5.0.1...v5.0.2) (2026-08-19)


### Bug Fixes

* **spf:** expand %{d} macro to the domain currently being evaluated ([#126](https://github.com/postalsys/mailauth/issues/126)) ([53c4522](https://github.com/postalsys/mailauth/commit/53c45220a1af41febb5b901c251ed4cc66de511e))

## [5.0.1](https://github.com/postalsys/mailauth/compare/v5.0.0...v5.0.1) (2026-08-07)


### Bug Fixes

* **cli:** replace yargs with commander ([#120](https://github.com/postalsys/mailauth/issues/120)) ([7a8a527](https://github.com/postalsys/mailauth/commit/7a8a5273413137482890519b0185cb9ef14ebea3))

## [5.0.0](https://github.com/postalsys/mailauth/compare/v4.13.3...v5.0.0) (2026-08-06)


### ⚠ BREAKING CHANGES

* Node.js 20 is no longer supported, the minimum is now 22.19.0 (the engine floor of undici 8).
* **dmarc:** adkim=s and aspf=s now actually fail when only the organizational domains match. Previously strict alignment fell through to the relaxed comparison, so these records behaved as adkim=r/aspf=r and such messages passed. Senders that publish strict alignment but sign or send from a different host under the same organizational domain will flip from pass to fail. dmarc.status.header.from now reports the From domain rather than the organizational domain, dmarc.status.header.d reports the domain the record was found at, and dkim.results[].status.aligned is false for org-level-only matches when the domain publishes adkim=s.

### Features

* add seal-only mode to the seal CLI command ([#119](https://github.com/postalsys/mailauth/issues/119)) ([afdfc3d](https://github.com/postalsys/mailauth/commit/afdfc3d1cb7b61aecbf60eda96f2c0be87b0c9cf))


### Bug Fixes

* **arc:** report public key failures instead of a bare arc=fail ([3464be7](https://github.com/postalsys/mailauth/commit/3464be70dd2449038e3c0381acbe4565d28370ba))
* **cli:** validate seal-only options and dedupe the seal command paths ([17dd59c](https://github.com/postalsys/mailauth/commit/17dd59ca472efc477fe041de48d2c2d8a730f3e7))
* close residual parser and DMARC discovery edge cases ([f1c28e1](https://github.com/postalsys/mailauth/commit/f1c28e10f331bea1f23ff2d861e00c7700f3b97f))
* **dmarc:** normalize tag values and report the correct identifiers ([e5dc758](https://github.com/postalsys/mailauth/commit/e5dc75827ff190912515572546bea0745c3629ff))
* enforce DMARC strict identifier alignment (adkim=s/aspf=s) ([0c4bab7](https://github.com/postalsys/mailauth/commit/0c4bab7f747c70121f72b76b53ad704712f3a56d))
* harden tag and header parsers against crafted property keys ([7eb9ea2](https://github.com/postalsys/mailauth/commit/7eb9ea24ed19032b63e9f9993971b77b8d77109e))
* require Node.js &gt;= 22.19.0 ([1c689c5](https://github.com/postalsys/mailauth/commit/1c689c5444821e5e188cef35c5aa3de3b2d8cfbe))
* **tools:** do not treat a legacy getAlignment options object as strict ([2007ab4](https://github.com/postalsys/mailauth/commit/2007ab41cccc41b531f3e5ec65899264b6e3441d))

## [4.13.3](https://github.com/postalsys/mailauth/compare/v4.13.2...v4.13.3) (2026-05-14)


### Bug Fixes

* force release ([e9407f0](https://github.com/postalsys/mailauth/commit/e9407f052a7e4b837d9e1884c21cdb15ceeb1e12))

## [4.13.2](https://github.com/postalsys/mailauth/compare/v4.13.1...v4.13.2) (2026-04-10)


### Bug Fixes

* prevent chunk-boundary-dependent DKIM relaxed body hash ([9ae9745](https://github.com/postalsys/mailauth/commit/9ae9745a4b82737c2ef9cfe6de083e9f934b57e4)), closes [#115](https://github.com/postalsys/mailauth/issues/115)

## [4.13.1](https://github.com/postalsys/mailauth/compare/v4.13.0...v4.13.1) (2026-03-03)


### Bug Fixes

* trigger build ([33b05b7](https://github.com/postalsys/mailauth/commit/33b05b7df806b0104c3ac3a93986f6406b02393a))

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
