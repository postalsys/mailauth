# Changelog

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
