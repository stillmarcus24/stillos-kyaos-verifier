# KYA-OS submission — claim-by-claim evidence gate
Audited 2026-10-19 before any publication. Every row is a claim we would make publicly.
Verdicts: **VERIFIED** (checked against primary evidence) · **CORRECTED** (was wrong, now restated)
· **WITHDRAWN** (cannot be supported, removed) · **DISCLOSE** (true but requires a caveat stated up front).

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | "We pass 49/49 vectors of KYA-OS conformance suite 1.2.0" | **VERIFIED** | `node core/kyaos_verify.cjs` → 49/49, deterministic over 3 consecutive runs. Vector count matches `SUITE-MANIFEST.json` `vectorCount: 49`. |
| 2 | "Our run is against the genuine published suite" | **VERIFIED** | `--suite-hash` independently recomputes `sha256:8184227c315ce5f322652d827d070ee510bcb12576aef7471521d67a04b064c6` from the committed vector bytes using our own JCS + SHA-256, and it equals the pinned `vectorSetHash`. Recipe implemented from CONFORMANCE.md, not copied. |
| 3 | "No dependency on `@kya-os/*`" | **VERIFIED** | 4 `require()` calls, all Node stdlib (`fs`, `path`, `crypto`, `zlib`). Module loads standalone. The single `@kya-os` string in the file is a comment. 868 lines. |
| 4 | "The only two conformance claims in the registry are the project's own" | **VERIFIED** | All 8 entries in `registry/builders/` read directly. Only `kya-os-mcp` and `kya-os-demo-server` carry a `conformance` block (both `verified`, both suite **1.1.0**). The two genuine third parties — `hobbsidian` (integration), `knowthat-ai` (service) — carry **no conformance claim at all**. Only one entry is `kind: implementation`: the reference implementation. |
| 5 | "The reference implementation's full-suite pass is self-reported, not independent" | **VERIFIED** | Their own registry listing states it verbatim: *"the conformance vectors derive from this codebase, so its full-suite pass is self-reported, not independent evidence."* Quoting them, not characterising them. |
| 6 | "Both existing verified claims are pinned to suite 1.1.0, which had an inverted status-list defect" | **VERIFIED** | `CHANGELOG.md` L314-320 verbatim: the 1.1.0 `StatusList2021Credential` *"carried a proof that did not verify… The suite therefore **passed an implementation that never checked a list's proof and failed one that did**."* Fixed in 1.2.0. Our claim is against 1.2.0. |
| 7 | "AAP-4 cannot be self-certified" | **VERIFIED** | CONFORMANCE.md §Audit Assurance Profile: AAP-4 requires "the observer provider contract, **independent administration**, checkpoint view comparison/fork detection"; and "Passing the in-memory reference suite demonstrates the contract; it is **not evidence** that a production datastore, KMS, or observer deployment satisfies its operational durability or independence claims." No entry in the registry claims any AAP level. |
| 8 | ~~"StillOS KYA-OS Verifier is Core L3 / full scope"~~ | 🚨 **WITHDRAWN — THIS WAS A FALSE CLAIM AND IT WAS IN THE DRAFT** | Core L3 (CONFORMANCE.md L184-222) requires **L3.1-L3.4 VC ISSUANCE**, **L3.14-L3.19 a delegation GRAPH**, **L3.20 StatusList CREATION**, **L3.22 CASCADING REVOCATION**, **L3.23-L3.24 OUTBOUND proof building**, all of **L2 session management** (handshake, nonce store, TTL, `kyaos_` session IDs) and **L3.26 audit logging MUST**. We built a **verifier**. We do none of those. Restated as `level: L3, scope: subset, categories: [all 9]`, which the registry renders as a named subset and never as a bare level. |
| 9 | ~~"First/only verifier for KYA-OS"~~ | 🚨 **WITHDRAWN — never publish this** | npm carries **`@kya-os/verifier` 1.8.3** ("Isomorphic verifier middleware for XMCP-I proof validation") and **`@kya-os/id` 0.6.0** ("Verifier-only identity SDK"). A verifier already exists. Our differentiator is **independence**, not novelty. |
| 10 | "We implemented from the published specs" | **DISCLOSE** | True — every construction is normatively documented: detached JWS signing input in `SPEC-ENTITY-CARD.md` **§8.4** (`<protected>..<signature>`, JCS canonical bytes of covered claims); audit domain separation in `AUDITABILITY.md` **L507-512** (`<domain> + NUL + JCS(value)`, domain `org.kya-os.audit.event.v1`). **But we also read `src/card/status-list-proof.ts` and `src/middleware/with-kya-os.delegation-verify.ts` to confirm two preimages.** That must be stated in the submission. "Independent" = no shared code and no dependency; it does **not** mean we never looked at their source. |
| 11 | "Every `@kya-os/*` npm package is published by a single account" | **VERIFIED — INTERNAL ONLY, DO NOT PUT IN THE PR** | 25 of 26 `@kya-os/*` packages publish under `h0bb5` (the 26th, `cli-effects`, under `marshallborham`). This is the strategic *reason* independence has value. Published on their own registry PR it reads as an accusation about a named maintainer. Same law as `crime_watch`: **exposure, never violation; observation, never accusation.** |
| 12 | "`probeUrl` is optional for our entry kind" | **VERIFIED** | `scripts/validate.mjs` mentions `probeUrl` exactly once, as *"optional https URL of a live MCP endpoint"*. The schema's own prose says "service and implementation kinds only" but the validator does not enforce presence. **No endpoint has to be faked.** |
| 13 | "`status: verified` is not something we can assert" | **VERIFIED** | Schema: `attestationUrl` is **required when** status is verified/revoked and **forbidden below** that rung; the credential URL is `https://builders.kya-os.org/credentials/<id32>.json`, issued only by the Program. Our entry is `self-reported` and carries no `attestationUrl`. |
| 14 | "The site advertises suite 1.1.0/48 vectors; HEAD is 1.2.0/49" | **VERIFIED** | `builders.kya-os.org/conformance/` rendered "suite 1.1.0 · 48 vectors · pinned sha256:38f34222…"; repo `SUITE-MANIFEST.json` is 1.2.0/49. We target HEAD and say which. |

## What we may claim publicly, exactly
> An independent, verify-only implementation of the KYA-OS v1 verify primitives, with no dependency
> on `@kya-os/*`, passing **49 of 49** vectors of conformance suite **1.2.0** — whose pinned
> `vectorSetHash` our implementation reproduces independently. Scope is the nine vector categories;
> this is **not** a Core-L3 claim (no issuance, no delegation graph, no revocation management, no
> session layer) and **not** an AAP claim. Status: self-reported, pending Program verification.

## What differentiates it — three facts, all checkable by a third party
1. **Independence is the product, not the feature.** The only two conformance claims in the registry
   are the project's own, and the reference implementation says in writing that its own pass is not
   independent evidence. A second, dependency-free implementation is the one thing a conformance
   program cannot generate for itself.
2. **First claim against suite 1.2.0.** Both existing claims sit at 1.1.0, the suite whose own
   changelog says it *passed* implementations that skipped the status-list proof check and *failed*
   those that performed it. Our pass is on the corrected suite, and we verify the list's proof
   before reading a bit.
3. **AAP-4 is the position nobody can take alone.** It requires an independently-administered
   observer with fork detection. StillOS already operates one — sealed hourly notary heads with
   divergence detection (ALS #42) and the MCPShip joint reference window (ALS #47), two parties with
   no shared code converging on identical counts. That is the scarce asset; the listing is the door.

## Standing instruction
Do not describe a local vector pass as "KYA-OS certified", "compliant", or "L3". The only body that
can certify is the Conformance Attestation Program, and the only honest word for our current state
is **self-reported**.

---

# Second gate — 2026-10-19, pre-publication, after the 14 rows above
The 14 rows audited every TECHNICAL claim and passed. They missed four things, three of which
would have shipped. Found by running THEIR tooling instead of reading prose about it.

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 15 | `homepage` + `repo` in the draft entry resolve | 🚨 **CORRECTED — BOTH 404'd** | `https://stillosdigitalholdings.com/kyaos` → **404**, `https://github.com/stillmarcus24/stillos-kyaos-verifier` → **404**. `homepage` is a **required** schema field. A verifier listing whose "go read the source" link is dead is the demand_hunter-pitched-a-404 defect. Fixed by pointing both at the repo URL — precedented by their own `revoked-demo.json`, which uses a GitHub URL as `homepage`. **This removes any need to touch Caddy**, whose config is runtime-memory-only. |
| 16 | "Our entry claims L3" is an unambiguous statement | 🚨 **CORRECTED — A BARE LEVEL IS FORBIDDEN** | `CONFORMANCE.md` L15-25: **three independent ladders**, two reusing the names L1-L3 — **Core**, **Entity Card**, **AAP**. Verbatim: *"A conformance claim MUST name its ladder… A bare 'L2' is ambiguous; write 'Core L2', 'Card L2', or 'AAP-2'."* Row 8 withdrew *Core* L3 correctly and then left a bare `"L3"`, which still reads as Core L3. The correct ladder for this implementation is **Card**, and the rung is **L3-minus**: Card L3 = L2 + live holder-of-key proof **fused with the token's RFC 9449 `cnf.jkt`** (`L3`) **or standalone** (`L3-minus`) **plus a fresh (live) revocation status**. We do neither the `cnf.jkt` fusion nor a live revocation fetch — vectors are consumed as pinned data. The registry schema's enum is only `L1|L2|L3` and cannot express a ladder or the `-minus`, so both go in `description` verbatim. |
| 17 | Our `--json` output is a submission-ready report | 🚨 **CORRECTED — THEIR ENFORCER REFUSES IT** | `make-claim.mjs` L63-97 enforces the published report contract field-for-field and refuses anything else. Ours emitted `matched` with a nested `suite` block and **no top-level `adapter`**, so it dies at **L64** (`report.adapter must be a non-empty string`) before reading one vector. Fixed: new `--report` mode emits the contract exactly (`adapter`/`total`/`passed`/`failed`/`results[]`/`allMatched`). **`NOT_IMPLEMENTED` maps to `actual: "error"`, never `"fail"`** — "fail" would read as a correct rejection and could score `ok: true` against an `expected: fail` vector, i.e. a pass for the wrong reason. Verified cold: 49/49, 9 categories, unique ids, 0 missing descriptions. Their registry validator also caught a **280-char cap** on `description` (ours was 294). |
| 18 | "Independence is the one thing a conformance program cannot generate for itself" | ⚠️ **NARROWED — I FOUND EVIDENCE AGAINST MY OWN DIFFERENTIATOR** | **`conformance/verify.py` exists in their own repo at v1.15.0 (HTTP 200, read directly)** and its docstring says it *"shares NO code with the reference adapter."* So they DID generate a zero-shared-code verifier for themselves and my framing was wrong. What survives, and it is checkable: verify.py *"verifies the **positive** `org.kya-os/proof.v1` vector"* plus the positive audit-integrity vector — **2 positive vectors across 2 categories, no negative vectors.** Our run is **49 vectors across all 9 categories, of which 29 are must-reject**. The honest differentiator is **independence of PARTY plus negative-vector coverage**, not "nobody else has zero shared code." |

## Sequence this forces — the registry PR is NOT first
`CONTRIBUTING.md` L71 + the submission template: `status` becomes `in-verification` **when the
submission issue is open**, and the issue URL goes on the entry as **`evidenceUrl`** (schema L139:
*"the conformance submission issue or verification thread"*). The claim also pins a **40-hex commit
in OUR repo** — the program clones and re-runs at exactly that commit. So: **repo first, issue
second, registry PR third**, carrying `evidenceUrl` and `in-verification` rather than a bare
`self-reported` with no link. Every commit needs **DCO sign-off (`git commit -s`)** — CONTRIBUTING L101/L140.

## Open question for the submission issue, not an overclaim
`conformance/README.md` L16: *"The measurement instrument is the published vector suite: suite
**1.1.0**, 48 vectors."* We claim **1.2.0 / 49**. Their starter's `fetch-suite` also pins 1.1.0 at
v1.15.0 (`vectorSetHash: sha256:38f34222…`). Their L4 says the program re-runs *"your git commit and
the suite it ran"*, which reads as permitting a 1.2.0 pin — but it is **not confirmed**, and 1.1.0 is
the suite their own changelog says *passed* implementations that skipped the status-list proof check.
**Ask it as a question in the issue. Do not assert they will re-run 1.2.0.**

## Evidence persisted off RAM
The basis for rows 4, 5, 6, 12, 13, 14, 16, 17 was a clone in **`/dev/shm` — tmpfs**, which would
vanish on reboot and leave published claims with no backing. Snapshotted to
`state/kyaos/evidence/` (registry snapshot, CONFORMANCE.md, CONTRIBUTING.md, conformance/README.md,
report.contract.md, make-claim.mjs). **LAW: an instrument whose input lives in /tmp or /dev/shm has no input.**
