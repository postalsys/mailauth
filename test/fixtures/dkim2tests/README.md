# DKIM2 test vectors from turscar/dkim2tests

`vectors.json` holds the test vectors of [turscar/dkim2tests](https://forge.turscar.ie/turscar/dkim2tests) at commit `a382236fbbf3697977b36d01c8cf59ffe39c3200` (11 September 2026), converted from the TOML files of its `tests` directory into one JSON file. Each entry keeps the fields of the TOML file (see `structure.go` in that repository), with `OriginalMessage` and `SignedMessage` always filled in. The vectors were made with an independent DKIM2 implementation, [turscar/dkim2](https://forge.turscar.ie/Turscar/dkim2), against draft-ietf-dkim-dkim2-spec-02.

They are used by `test/dkim2/interop-test.js`. The vectors are distributed under the BSD 2-Clause license in `LICENSE`, copyright (c) 2026 Turscar.

To refresh the vectors, parse every `tests/*.toml` file of a new commit of that repository, fill an empty `OriginalMessage` or `SignedMessage` from the file named by `OriginalFile` or `SignedFile`, and keep these fields as they are: `Name`, `Comments`, `Spec`, `Section`, `OriginalMessage`, `SignedMessage`, `MailFrom`, `RcptTo`, `ExpectedState`, `ExpectedError`, `CanonicalDkim2Headers`, `ExpectedFlags`, `PrivateKeys` and `DNS`. Then update the commit above, and check `VECTOR_DEFECTS` in the test: it lists vectors whose expectations do not match their own messages, and asserts that the defect is still there.
