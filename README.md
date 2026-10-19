# StillOS KYA-OS Verifier

An independent, verify-only implementation of the [KYA-OS](https://kya-os.org) v1 verification
primitives. Zero dependencies; Node standard library only.

```
TOTAL 49/49 vectors matched        conformance suite 1.2.0
```

Published and maintained by **Still OS Digital Holdings LLC** (Wyoming).

## Purpose

The KYA-OS Conformance Attestation Program measures implementations against a pre-signed vector
suite rather than accepting asserted compliance. A conformance program cannot, however, produce
independent evidence about itself. As of 2026-10-19 the builders registry contained eight
entries, and the only two carrying a conformance claim both belonged to the project. The
reference implementation's own listing records this directly:

> the conformance vectors derive from this codebase, so its full-suite pass is self-reported,
> not independent evidence.

This repository is a second implementation, built by an unrelated party. It shares no code with
`@kya-os/mcp` and takes no `@kya-os/*` dependency; each primitive is implemented from the
underlying RFCs and the published specifications. The published vectors are consumed as data.

It is intended for two audiences: operators who need to verify KYA-OS artifacts without adopting
the reference stack, and reviewers who need a second implementation against which to compare
results.

## Verification

Requires Node 18 or later. There is no installation step.

```bash
git clone https://github.com/stillmarcus24/stillos-kyaos-verifier
cd stillos-kyaos-verifier

node kyaos_verify.cjs              # run the suite      -> 49/49, exit 0
node kyaos_verify.cjs --suite-hash # verify the vectors -> matches: true
node kyaos_verify.cjs --self-test  # unit self-test     -> 41/41
node kyaos_verify.cjs --report     # emit report.json   (the published report contract)
```

`--suite-hash` recomputes the vector-set hash from the committed vector bytes using this
repository's own JCS and SHA-256 implementations and compares the result with the pinned
`vectorSetHash`. Verification therefore does not require trusting this copy of the suite: if any
byte of any vector file were altered, the command fails.

Continuous integration runs all three checks on every push with no installation step, so the
zero-dependency property cannot lapse silently.

## Scope of the claim

| | |
|---|---|
| **Ladder** | Entity Card. Not Core. A bare level designation is ambiguous per `CONFORMANCE.md`. |
| **Rung** | Card L3-minus. All nine vector categories pass; the holder-of-key proof is verified standalone. |
| **Status** | Self-reported. Only the Conformance Attestation Program can certify a claim. |
| **Suite** | 1.2.0, 49 vectors, `vectorSetHash` recomputed independently. |

The following are outside the claim and are not asserted anywhere in this repository:

- **RFC 9449 `cnf.jkt` token fusion and live revocation status.** Vectors are consumed as pinned
  data; the implementation performs no network access.
- **Any Core level.** Core L1 through L3 require key generation, signing, credential issuance, a
  delegation graph, revocation management and a session layer. This is a verifier and implements
  none of them.
- **Any Audit Assurance Profile level.** Per `CONFORMANCE.md`, passing the reference suite
  "is not evidence" of observer independence or operational durability.
- **Certification.** A local vector pass is not KYA-OS certification, and that term is not used
  here.

## Coverage

| category | vectors | | category | vectors |
|---|---|---|---|---|
| signed-proof | 9/9 | | entity-card | 7/7 |
| negotiation | 8/8 | | card-proof | 7/7 |
| delegation-chain | 6/6 | | audit-integrity | 3/3 |
| did-key-resolution | 3/3 | | did-web-resolution | 3/3 |
| status-list | 3/3 | | **total** | **49/49** |

29 of the 49 vectors are negative cases (`expected: "fail"`): tampered payloads, broken
delegation chains, revoked credentials, malformed DIDs and replayed nonces. These pass only when
the implementation rejects the artifact.

The implementation is fail-closed. An unmet security property returns a rejection rather than
raising; a category that is not implemented reports `error`, which the published report contract
counts as a mismatch. A non-answer costs a vector and cannot earn one.

## Prior art

`conformance/verify.py` in the reference repository is a Python standard-library verifier which,
by its own documentation, "shares no code with the TypeScript reference." A zero-shared-code
verifier therefore already existed. It covers the positive `org.kya-os/proof.v1` vector and the
positive audit-integrity vector: two positive vectors across two categories. The distinction
offered here is independence of party, together with coverage of all nine categories including
the 29 negative cases.

npm additionally carries `@kya-os/verifier` and `@kya-os/id`. This is not the first KYA-OS
verifier and is not presented as such.

## Implementation notes

Each primitive below carries a specific failure mode that the suite tests directly.

- **RFC 8785 JCS.** Object keys sort by UTF-16 code unit, not by code point. The suite exercises
  this: with the keys `U+1F600` (`😀`) and `U+FB01` (`ﬁ`), a code-point sort passes a vector it is
  required to reject.
- **RFC 9162 Merkle.** `leaf = SHA256(0x00 ‖ digest)`, `interior = SHA256(0x01 ‖ L ‖ R)`.
- **Audit event digest.** `SHA256("org.kya-os.audit.event.v1" ‖ 0x00 ‖ JCS(event))`.
- **eddsa-jcs-2022.** Ed25519 over `SHA256(JCS(proofOptions − proofValue)) ‖ SHA256(JCS(doc − proof))`;
  `proofValue` is base58btc multibase.
- **Detached JWS.** Signing input per `SPEC-ENTITY-CARD.md` §8.4.

Every card-proof vector carries the same nonce, so vectors are evaluated in isolation with the
replay seam reset between them. Without that isolation the first vector consumes the nonce and
the remainder are rejected as replays; because all of them are negative cases, the suite would
report 49/49 while the specific defect in each went unexercised. A pass obtained for the wrong
reason is the condition this suite exists to detect.

## Provenance and disclosure

The vector files are copied verbatim from the reference repository; see
[`suite/NOTICE.md`](suite/NOTICE.md) for the upstream MIT notice.

Every public claim in this repository was verified against primary evidence before publication.
The audit is published in full, unedited, including the claims that were withdrawn or corrected
during review: [`CLAIMS-AUDIT.md`](CLAIMS-AUDIT.md).

Each construction implemented here is normatively published — the detached-JWS signing input in
`SPEC-ENTITY-CARD.md` §8.4, audit domain separation in `AUDITABILITY.md`. Two
reference-implementation source files were also consulted to confirm two preimages. Independence
here means no shared code and no dependency; it does not mean the reference source was never
read, and reviewers are entitled to know that when weighing the claim.

## Contact

Correspondence, corrections and security reports: open an issue, or
[stillmarcus24@gmail.com](mailto:stillmarcus24@gmail.com).

Corrections to anything stated here are welcome and will be published with the same prominence
as the original claim.

## License

MIT; see [`LICENSE`](LICENSE). Vector files: MIT, Copyright (c) 2026 KYA-OS.
