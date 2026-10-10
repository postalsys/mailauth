# DKIM2 vectors from croessner/dkim2

`public-golden.json` is `lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/public-golden.json` of [croessner/dkim2](https://github.com/croessner/dkim2) at commit `182bc43a4f0cd8d948c0d199ad8bf6c3f847ec72` (5 October 2026), unchanged. croessner/dkim2 is an independent DKIM2 implementation in Go built for draft-ietf-dkim-dkim2-spec-06 and draft-ietf-dkim-dkim2-dns-00.

The file holds synthetic messages with their SMTP envelopes, and the public RSA and Ed25519 keys they are signed with. The expected results are not part of the file, they are in `lib/verifier_vector_test.go` of that repository (`publicGoldenCases`), which `test/dkim2/interop-test.js` repeats. The vectors are verified at the time `1700000000`, the keys are published under the selectors `rsa.test` and `ed.test`.

The file is distributed under the Apache License 2.0 in `LICENSE`, copyright 2026 Christian Roessner.
