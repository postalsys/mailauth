# DKIM2 messages signed by stalwart mail-auth

`messages.json` holds DKIM2 signed messages made by [stalwartlabs/mail-auth](https://github.com/stalwartlabs/mail-auth) at commit `beca6d3a420a9dc59321684d5597e8b05efc4e4b` (8 October 2026), an independent DKIM2 implementation in Rust that follows draft-ietf-dkim-dkim2-spec-04. Each entry has the message, and the SMTP envelope of its last hop. `dns` holds the key records the messages are signed with. The keys, the DNS records and the unsigned messages come from the `resources/dkim2` directory of that repository.

The messages cover originator signatures with Ed25519, and with RSA and Ed25519 together with flags, a nonce and several recipients, over the six example messages of that repository, the null reverse-path, a forwarder that does not change the message, a forwarder that changes it with a Recipe computed by mail-auth, and a hop with `nd=`. They are used by `test/dkim2/interop-test.js`.

`xcheck.rs.txt` is the test module that made them. To make them again, copy it to `src/dkim2/verify/tests/xcheck.rs` of a mail-auth checkout, add `mod xcheck;` to `src/dkim2/verify/tests.rs`, and run `XCHECK_DIR=<dir> cargo test --lib xcheck_sign`. The same module verifies messages signed by mailauth with `xcheck_verify`.

The files of mail-auth are distributed under the MIT license in `LICENSE` (mail-auth is also available under Apache-2.0).
