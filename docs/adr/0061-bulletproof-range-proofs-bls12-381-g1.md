# ADR-0061: Bulletproof range proofs for BLS12-381 G1 Pedersen commitments

## Status

**Accepted (design), 2026-10-24, by maintainer Satya.** Q1–Q7 are decided: Q2 as (b) in r2, and
Q1 and Q3–Q7 as leaned (a) (see "Design questions for the maintainer"). Codex approved r2
(`ca3014261031f8144cc70b2a31be82a1d4b4eda4`) as design review on 2026-10-24, with no P0–P2
finding; its three P3 findings are addressed in r3. Implementation proceeds in PR #105 under the
milestones below, **with a maintainer sign-off after M0** before any Java (M1).

**M0 implemented, reviewed and signed off.** M0 delivered:
- the normative spec `bulletproof-range-bls12-381-g1-v1` r1;
- registry r8, with the new entries `reserved`;
- an independent Python second implementation, with CFRG conformance (I12);
- the three-way generator reproduction (I1).

Review loop: three Claude reviewers report SPEC READY. Codex approved in round 4, after
CHANGES REQUESTED in rounds 1–3, all resolved, and the PR reviewer approved `d906c57` (M0 SPEC
READY, one P3 fixed in `daab133`). **The maintainer signed off M0 on 2026-10-25** ("Looks like M0
is approved. So continue and implement all other milestones"), in reply to a sign-off request that
listed the r5 design additions. The sign-off is recorded as accepting them:
- D7a, the proof-protocol descriptor;
- the non-empty context;
- the D4 decoding order;
- the D6 nonce, seam and entropy rules;
- `INVALID_STATEMENT`.

The redistribution terms of the copied CFRG vectors (IETF Trust, BCP 78) remain a **before-merge**
gate for the maintainer.

**M1 implemented (2026-10-25)** in PR #105 (r6): the Java SHAKE128 and transcript, the range
prover and verifier, the D7a descriptor, and their tests. Review: Codex and three Claude reviewers
report M1 READY at `316d1e5` after one round of changes (r7).

**M2 implemented (2026-10-25)** (r8):
- **The vector file** `bulletproof-range-bls12-381-g1-v1.json`, emitted by the Python second
  implementation, with `--check` (byte-identical) and `--self-test`. It has 14 positive cases at
  every width with every challenge, 114 negative cases over seven layers, and 25 prover refusals.
- **Python → Java:** the Java test-nonce prover reproduces every positive proof byte for byte,
  and every negative case gets its exact class and layer, on pure Java and on blst, with
  identical outcomes.
- **Java → Python:** `java-proofs-v1.json` holds 12 Java proofs. The Python implementation
  accepts and re-proves each of them byte for byte, and rejects 228 single-field tampers.
- **dalek check:** the group-generic Python core verifies dalek 5.0.0's published proofs at
  `n` = 8–64, and dalek accepts the core's proofs and rejects 182 tampers. The same core,
  instantiated on BLS12-381, reproduces this protocol's known-answer proof byte for byte.
- **blst parity:** fixed-nonce proofs are identical, verdicts agree on the vectors and on a fuzz
  run, and adversarial zero-coefficient proofs never throw.

Addresses [issue #96](https://github.com/bloxbean/zeroj/issues/96), phase 4 of the #93–#96 Pedersen
roadmap. It defines the first proof protocol of the commitment-profile registry
(`commitment-profiles-v1` §5): a range proof over `pedersen-bls12-381-g1-v1` commitments, the
"V4 proof" cell that registry §14 lists as "blocked (ADR-0051 D7; #96)".

**Q2 (the Fiat–Shamir transcript)** was decided on 2026-10-24: stay on the official standards.
The transcript is `draft-irtf-cfrg-fiat-shamir-03` with SHAKE128, and points and scalars use the
`draft-irtf-cfrg-sigma-protocols-03` §8.2 BLS12-381 encodings (D3, "Note on the transcript
decision").

**Risk: R3** for the proof protocol, the generator derivation (D2), the transcript (D3) and the
prover's secret handling (D6). **R2** for the proof encoding and strict decoding (D4), the Java API
(D7), the registry entry (D1), the Yano-X verifier contract (D9) and the Cardano feasibility spike
(D8).

Acceptance is design acceptance only. It certifies no implementation, test or security property,
and no AI review upgrades a maturity or security claim (AGENTS.md).

## Date

2026-10-24 (r1); 2026-10-24 (r2: Q2 decided, transcript on the CFRG drafts); 2026-10-24 (r3: review
round 1); 2026-10-24 (r4: accepted, Q1–Q7 decided); 2026-10-24 (r5: M0); 2026-10-25 (r6: M0 sign-off,
M1); 2026-10-25 (r7: M1 review); 2026-10-25 (r8: M2)

## Context

### What exists after ADR-0060

ADR-0060 (merged in PR #103, `3e6a149`) admitted three registry entries as `active` and experimental:

- the basis set `pedersen-bls12-381-g1-basis-v1`: `G` and `H` are RFC 9380 `hash_to_curve` outputs
  under `DST_B = "ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"`;
- `pedersen-bls12-381-g1-v1`: `C = [m]·G + [r]·H`, `m, r ∈ [0, q)`;
- `pedersen-bls12-381-g1-bytes-v1`.

It provides:

- strict 48-octet decoding, with the identity accepted (ADR-0060 D3);
- disclosed openings (V1) and public relations (V3) in Java;
- the same checks on-chain in `PedersenG1Lib`.

What it cannot do is show that a hidden value lies in a range. Its "does not provide" list includes
"a range on a committed value without disclosing it". So does registry §14: "Relations prove
residues, not balances: integer conservation needs a range proof per term or a circuit."

ADR-0051 D3a states the rule a range proof must serve. A point-level balance check outside a
circuit "is valid only if every term carries a range proof for its declared width from the proof
that produced it, and the verifier applies the same side-bound rule to those declared widths."

### What the registry already requires of a proof protocol

`commitment-profiles-v1` §5 requires each proof protocol to be its own registry entry stating:

1. the commitment profiles it consumes;
2. the statement;
3. the exact transcript (domain strings, absorbed items and their order, challenge derivation,
   proof encoding);
4. its binding rule.

"Changing any transcript element requires a new protocol identifier." §6.4 says that in
Fiat–Shamir proofs "the transcript absorbs the proof protocol identifier, the commitment profile
identifier, every base, every commitment and the application context. A proof verified under one
profile or context is never accepted under another."

### The open transcript question in ADR-0051 D7

ADR-0051 D7 (G1 sigma proofs) is **open and escalated**:

- `draft-irtf-cfrg-fiat-shamir-03` instantiates its duplex sponge only with SHAKE128 or
  TurboSHAKE128.
- Plutus V3 has `sha2_256`, `sha3_256`, `blake2b_224`, `blake2b_256`, `keccak_256` and
  `ripemd_160`, but no SHAKE XOF and no Keccak permutation.
- So "a CFRG-conformant proof cannot be verified on-chain natively".

D7 leans towards a ZeroJ Cardano ciphersuite built from `expand_message_xmd` with SHA-256, the
construction already on-chain in `BbsHashToScalar`, but it decides nothing. A range proof faces the
same choice (Q2). For this protocol the maintainer chose the official drafts (D3), which gives up
native on-chain verification. This ADR does not decide D7: its option (a) ("implement the CFRG
ciphersuite exactly; no on-chain verification") could reuse the transcript code built here.

### Facts this design depends on

All paths are at `3e6a149` (the merge of ADR-0060) unless stated otherwise.

**Off-chain (`zeroj-bls12381`, `zeroj-blst`).**

- `Bls12381Provider` has `g1ScalarMul`, `g1SecretScalarMul`, `g1Add`, `g1Negate`, compressed codecs,
  `g1HashToCurve` and `hashToScalar`. It has **no MSM** (`spi/Bls12381Provider.java:20-136`).
  Issue #22 proposes a provider-neutral MSM.
  - `zeroj-blst` has a native Pippenger (`BlstG1Msm`) outside the SPI.
  - The pure-Java Groth16 prover has its own MSM over `JacobianArith381`.
- Both providers re-validate their input point on every `g1ScalarMul` call with
  `Bls12381Codecs.requireValid`, an affine `[q]P` of about 4.3 ms on macOS aarch64
  (`docs/benchmarks/pedersen-g1-2026-10-22.md`). Issue #104 tracks removing that repeat for
  trusted points; #28 tracks a faster subgroup check.
- ZeroJ has its own Keccak-f[1600] permutation and SHAKE256 for the BBS SHAKE suite
  (`Bls12381Hash.java`, `KECCAK_ROUND_CONSTANTS`, `hashToScalarXofShake256`). It has no SHAKE128 (the
  same permutation at rate 168) and no duplex-sponge transcript.
- The only Fiat–Shamir transcript in `zeroj-crypto` is the snarkjs-compatible Keccak-256 PlonK
  transcript (`transcript/FiatShamirTranscript.java`), which is specific to that format.

**On-chain (JuLC `0.1.0-pre18`, PV11 cost model).**

- The parameters come from `cost-model/plutus-v3-pv11-costs-v1.params` in `julc-vm-0.1.0-pre18.jar`:
  - `bls12_381_G1_uncompress` costs 52,948,122 CPU steps (parameter 211, constant).
  - `bls12_381_G1_multiScalarMul` costs 321,837,444 + 25,087,669·k CPU steps (parameters 313–314).
    It is `LinearInX` in the length k of the scalar list, per JuLC's
    `CostModelParser.java:562` and its generic list sizing in `BuiltinCostModel.argSizes`.
  - Maximum per transaction: 10,000,000,000 steps and 16,500,000 memory units.
- ADR-0060 measured two `scalarMul` as cheaper than a two-term MSM. MSM wins only from about 8
  terms (ADR-0056).
- Plutus V3 scripts cannot contain BLS12-381 point constants (CIP-0381). Every base a validator
  uses must be decompressed (about 53M steps) or hashed to the curve at run time.

**Yano-X** (`/Users/satya/work/bloxbean/yano-x` at `4732fb1`, with the host SPI in `yano` at `f7bd7de`):

- Yano-X is a plugin ecosystem for permissioned Yano app chains. Applications implement
  `AppStateMachine`, whose `apply` runs once per finalized block on every member.
- `AppStateMachine`'s Javadoc forbids, inside `apply`: wall-clock time, randomness, I/O,
  environment reads and iteration over unordered collections ("a nondeterministic machine stalls
  its chain").
- There is no gas or CPU metering. Bounds are configuration: `DEFAULT_MAX_MESSAGE_BYTES = 65536`
  (`AppChainConfig.java:77`), plus block size and message-count limits.
- Yano-X pins `zeroj = "0.1.0-pre10"` (`gradle/libs.versions.toml:6`), from before the `org.zeroj`
  namespace (ADR-0048).
- Its `state-machines/zk` and `ledgers/eutxo-zk` modules are excluded from its build.
- Its ZK ADR (`adr/app-layer/006-…`) plans private balances with SNARKs, not Bulletproofs. It
  requires verification parameters pinned in chain configuration and a per-block proof cap.

### No standard and no BLS12-381 reference implementation

The research for this ADR (2026-10-24) found:

- **No IETF/CFRG or ZKProof document specifies Bulletproofs.** The paper is the normative source.
- **No audited, maintained Bulletproof range proof over BLS12-381 G1.**
  - `maidsafe/bls_bulletproofs` 1.1.1 (a dalek fork on blstrs, last commit 2022-12-13) is the
    only one found. It derives challenges through ChaCha20 seeded from Merlin output, and its
    vector generators use the non-uniform `encode_to_curve` with an all-zero tag. It ships no
    known-answer vectors.
  - The audited implementations (dalek/zkcrypto, Monero, Tari, secp256k1-zkp) are on Ristretto255,
    ed25519 or secp256k1.
- **Weak Fiat–Shamir has broken many Bulletproof deployments.** "Frozen Heart" (Trail of Bits,
  2022; CVE-2022-29566) traced it to the paper's original §4.4, which did not hash the statement.
  Dao, Miller, Wright and Grubbs (IEEE S&P 2023) found 14 vulnerable codebases out of 22
  Bulletproof implementations surveyed. The paper was revised on 2022-04-14 to fix §4.4.

## Threat model and trust assumptions

**Untrusted:** every proof byte; the commitment `V` the proof is about, unless the verifier's
application already authenticated it; the bit width a prover claims; on-chain, every redeemer and
datum.

**Secret (prover side):**
- the witness `v` and `γ` (the `pedersen-bls12-381-g1-v1` opening `(m, r)`);
- the bit vectors `a_L` and `a_R`;
- the blinding nonces `α`, `ρ`, `τ₁`, `τ₂` and the vectors `s_L`, `s_R`;
- the polynomials `l(X)` and `r(X)` before the challenge `x` fixes them.

Any of these lets an observer learn or narrow `v`.

**Public:** the generators, `V`, the bit width `n`, the application context and the proof.

**Trusted:**
- the verifier's configuration: the expected protocol and profile, `n`, the application context
  and the pinned generator set;
- the selected `Bls12381Provider` as code;
- for the prover, the runtime's entropy configuration: the JDK `SecureRandom` providers and
  security properties, and the operating system's entropy source. Java cannot verify it, and a
  misconfigured runtime defeats hiding;
- SHA-256 (in hash-to-curve) and SHAKE128 (in the transcript) as random oracles;
- on-chain, the node's builtins as an implementation of CIP-0381 and CIP-0133.

**Adversaries and goals:**

- **A prover who wants a valid proof for `v ≥ 2^n`**, or for a `V` it cannot open. Soundness rests
  on the discrete-log assumption in G1, the independence of every generator (D2) and a strong
  Fiat–Shamir transcript (D3).
  - The Frozen Heart attack forges a proof for an arbitrary `V` when `V` is not hashed before the
    challenges.
- **An attacker who replays or transplants a valid proof:** to another `V`, another width, another
  profile, another application context, or another protocol version. D3 binds all of them;
  application replay rules remain the application's job.
- **Malformed input:**
  - non-canonical, off-curve, non-subgroup or identity points;
  - scalars `≥ q`;
  - a proof of the wrong length;
  - inner-product vectors longer than `log₂ n`, the out-of-bounds class Monero fixed in 2026.
- **Resource exhaustion:** proofs that are too large or that select a large `n`.
- **An observer of the prover's timing, memory access or allocation.** The pure-Java prover is
  variable-time.
- **On-chain:** reliance on builtin behaviour the CIPs leave unspecified.

**Not provided:**
- authorization, replay protection, context or UTxO binding beyond what the caller passes as
  context;
- integer conservation across several commitments: the application still applies ADR-0051 D3a,
  with each term's width taken from its verified proof;
- any range on `pedersen-bls12-381-g1-bytes-v1` commitments (D1).

## Pinned normative references

1. **B. Bünz, J. Bootle, D. Boneh, A. Poelstra, P. Wuille, G. Maxwell, *Bulletproofs: Short Proofs for
   Confidential Transactions and More*.** IACR ePrint 2017/1066, revision of **2022-04-14** (the
   last of 14). IEEE S&P 2018, DOI 10.1109/SP.2018.00020.
   - **What it fixes.** The 2022 revision "fixes an earlier mistake in the Fiat-Shamir section
     (Section 4.4) reported by TrailOfBits".
   - **Sections used:**
     - §3: the inner-product argument, Protocols 1 and 2, with the fixed element `u`;
     - §4.1–§4.2: the range proof, relation (36) `V = h^γ g^v ∧ v ∈ [0, 2^n − 1]`, lines (40)–(68),
       with challenges drawn from `Z*_p`;
     - §4.3: aggregation (deferred here);
     - §4.4: Fiat–Shamir ("It is very important to include the statement st in the hash");
     - §6.2: the verifier as one multi-exponentiation of size `2n + 2 log₂ n + 7`, equations
       (95)–(105).
   - **Proof size:** `2⌈log₂ n⌉ + 4` group elements and 5 scalars.
   - **Notation.** The paper's `g` is the value base and `h` the blinding base, matching
     `pedersen-bls12-381-g1-v1`'s `G` and `H`.
2. **H. Chung, K. Han, C. Ju, M. Kim, J. H. Seo, *Bulletproofs+*.** ePrint 2020/735 (received
   2020-06-18). IEEE Access 10:42081–42096 (2022), DOI 10.1109/ACCESS.2022.3167806. The Q1
   alternative.
3. **Q. Dao, J. Miller, O. Wright, P. Grubbs, *Weak Fiat-Shamir Attacks on Modern Proof Systems*.**
   ePrint 2023/691, IEEE S&P 2023.
   - §II.E defines strong Fiat–Shamir as `c_i ← H(pp, x, a_1 … a_i)`: public parameters, statement
     and every prior prover message.
   - §IV is the Bulletproofs attack.
4. **Trail of Bits, "The Frozen Heart vulnerability in Bulletproofs"** (2022-04-15), and
   CVE-2022-29566.
5. **C. Ganesh, C. Orlandi, M. Pancholi, A. Takahashi, D. Tschudi, *Fiat-Shamir Bulletproofs are
   Non-Malleable (in the ROM)*.** ePrint 2023/147 (revision of 2025-01-06), J. Cryptology 2025.
   Non-malleability; not replay protection.
6. **RFC 9380**, *Hashing to Elliptic Curves*:
   - §3 and §3.1: domain separation;
   - §5.2 and §5.3.1: `expand_message_xmd`;
   - §8: protocols that need a random oracle "MUST NOT use a nonuniform encoding";
   - §8.8.1: the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`;
   - Appendices J.9.1 and K.1.
7. **draft-irtf-cfrg-fiat-shamir-03** (2026-08-17, expires 2027-02-18). Normative for the
   transcript (D3):
   - §3.2: the XOF duplex sponge (`Init`, `Absorb`, `Squeeze`);
   - §4.2.2–§4.2.3: `DecodeUint` and `DecodeField`, `Ns + 16` octets read little-endian;
   - §5.1: `DeriveSessionID` and the tag requirements, including the application context;
   - §5.2: the instance is absorbed first, and its encoding is prefix-free;
   - §6: serialization and deserialization (§6.2.5: validate group elements and reject the
     identity);
   - §8.5: instance encoding and CVE-2022-29566;
   - §9.1: SHAKE128;
   - Appendix B: test vectors, with a machine-readable JSON copy in the draft's repository.
8. **draft-irtf-cfrg-sigma-protocols-03** (2026-08-17). Normative for the codecs (D3, D4):
   - §8.2: the `sigma-proofs_Shake128_BLS12381` ciphersuite (`Ne = 48`, `Ns = 32`, SHAKE128);
     compressed G1, where infinity is "neither produced … nor accepted"; deserialization "MUST
     perform full point validation"; big-endian scalars in `[0, q)`;
   - Table 1: "about 120-bit" security;
   - Appendix A.3: test vectors over BLS12-381 G1, including `pedersen_commitment`.

   The protocol itself (§4, linear relations) is not used.
9. **FIPS 202** (SHA-3 standard: SHAKE128). Not fetched for r2; it will be pinned and fetched at
   M0. SHAKE128 is tested against fiat-shamir-03 Appendix B.2 and against an implementation ZeroJ
   did not write (CPython's `hashlib.shake_128`).
10. **dalek/zkcrypto `bulletproofs`** at `04bce4e66013ff857ed462fd4206210544101461` (2025-09-13),
   MIT: the notes in `docs/notes-rp.md` and `docs/notes-ipp.md`, and the transcript order in
   `src/transcript.rs` and `src/range_proof/mod.rs`.
   - This is a secondary written specification and an external oracle for the protocol's
     algebra (M2). Its vectors cannot be used for this protocol directly, because it uses
     Ristretto255 and Merlin.
   - This ADR's deviations from dalek are listed in D3 and D5.
   - *M2 note (r8):* the M2 check runs the published crate `bulletproofs` 5.0.0 (crates.io; its
     `.cargo_vcs_info.json` names commit `86eadbeeb4a96d8da41427137b45ead810d03b41`; the crate's
     SHA-256 is recorded in `dalek-check/README.md`). That commit is 9 commits before the pin
     above. The 9 commits change serde deserialization (`visit_seq`), an r1cs scalar parse, tests,
     CI, the version number and a development dependency, not the range-proof algebra or
     transcript. That was checked with
     `gh api repos/zkcrypto/bulletproofs/compare/86eadbe…04bce4e`.
11. **CIP-0381** and **CIP-0133** at `86b89208d3b2aabb5dcc5b778dfbe09096b4e114`, as pinned by ADR-0060.
12. **ZeroJ:**
    - `commitment-profiles-v1` r7 (§5, §6.2, §6.4, §7, §10, §13, §14, §15);
    - `pedersen-bls12-381-g1-v1` r2;
    - ADR-0021: the pure-Java provider is not constant-time;
    - ADR-0038: the offline/isolated rule;
    - ADR-0044: module surface;
    - ADR-0051: D3a and D7;
    - ADR-0056: on-chain cost method;
    - ADR-0059 and ADR-0060.

## Decision

Notation follows ADR-0060:

- `q = 0x73eda753…00000001` is the G1 group order;
- `G` and `H` are the `pedersen-bls12-381-g1-basis-v1` bases;
- `n` is the bit width;
- `k = log₂ n`.

### D1 — One proof protocol entry, one consumed profile (R2)

Register a proof protocol under `commitment-profiles-v1` §5:

| Field | Value |
|---|---|
| Identifier | `bulletproof-range-bls12-381-g1-v1` |
| Consumes | `pedersen-bls12-381-g1-v1` only |
| Statement | for a commitment `V` that is **not the identity**, the prover knows `(v, γ)` with `V = [v]·G + [γ]·H` and `0 ≤ v < 2^n` as integers (D4 rule 5) |
| Widths | `n ∈ {16, 32, 64}`; the verifier takes `n` from its configuration, never from the proof |
| Values per proof | one (`m = 1`); aggregation is deferred |
| Generator set | `bulletproof-bls12-381-g1-gens-v1` (D2) |
| Transcript | D3 |
| Proof encoding | D4 |
| Binding rule | D3: protocol, profile, generator set, `n`, `V` and the application context |

**Why not the bytes profile.** A `pedersen-bls12-381-g1-bytes-v1` commitment is a scalar commitment
to `s = HashBytesToScalarG1(B)`. A range on `s` says nothing useful about `B`. The verifier
configuration names `pedersen-bls12-381-g1-v1`, so a bytes commitment is never range-checked by
accident. This follows the issue's out-of-scope note: "arbitrary byte commitments cannot
meaningfully use numeric range proofs".

**Integer meaning.** Because `2^n ≤ 2^64 < q`, a verified proof establishes that the residue
committed in `V` has a representative `v ∈ [0, 2^n)`, and that representative is unique. Combining
several commitments into a balance is the application's job under ADR-0051 D3a, with each term's
width taken from its own verified proof. For example, `t` terms of width 64 stay below `q` while
`t·(2^64 − 1) < q`, which `t < 2^190` satisfies.

**Lifecycle** (as ADR-0060 D1):
- spec approval (M0) adds the entry and the generator set as `reserved`;
- admission (M6) makes them `active` only after every prerequisite is checked;
- if anything is missing, they stay `reserved`.

### D2 — Generator set `bulletproof-bls12-381-g1-gens-v1` (R3)

The range proof needs the vectors `g⃗ = (G_0 … G_{n−1})` and `h⃗ = (H_0 … H_{n−1})`, and the
inner-product element `u` (paper §3). Every one must have an unknown discrete log relative to every
other and to `G` and `H`.

```
DST_BP = "ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"   (ASCII, 70 octets)
G_i    = hash_to_curve("G" ‖ I2OSP(i, 4), DST_BP)      for i = 0 … 63
H_i    = hash_to_curve("H" ‖ I2OSP(i, 4), DST_BP)      for i = 0 … 63
U      = hash_to_curve("U", DST_BP)
```

**Construction:**
- 129 new points under RFC 9380's random-oracle suite. The uniform `hash_to_curve` is required;
  `encode_to_curve` is not allowed (RFC 9380 §8).
- The tag is distinct from `DST_B`, so no generator collides with `G` or `H` by construction.
- A proof of width `n < 64` uses the prefixes `G_0 … G_{n−1}` and `H_0 … H_{n−1}`, so one set
  serves every width.

**Rules:**
- **Checks at derivation.** The deriver MUST check that none of the 131 points
  (`G_i`, `H_i`, `U`, `G`, `H`) is the identity, and that no two are equal or negatives of each
  other. On failure the set is invalid and a new version is required.
- **What the spec pins:**
  - all 129 compressed encodings;
  - their SHA-256 digest `D_gens`, over the concatenation `G_0 … G_63 ‖ H_0 … H_63 ‖ U`;
  - the derivation.
  Implementations use the pinned constants, and a test recomputes them.
- **Independent reproductions:** Java `hashToG1` (M0) and the stand-alone Python reference
  (M0). On-chain `bls12_381_G1_hashToGroup` (M4) is a third reproduction if the feasibility spike
  runs, but it is not an admission prerequisite, since this ADR publishes no on-chain library.
- **Deviation from dalek.** dalek replaces `u` with `Q = w·B`, where `w` is a transcript
  challenge. This ADR follows the paper's fixed `u` (`U` above). The change is listed so that the
  dalek notes are not misread as this protocol.

### D3 — Transcript and challenges (R3; Q2 decided: the CFRG drafts)

**Construction.** The non-interactive argument uses the duplex-sponge Fiat–Shamir transformation of
`draft-irtf-cfrg-fiat-shamir-03`, instantiated with **SHAKE128** (§3.2, §9.1). It uses the codecs of
the `sigma-proofs_Shake128_BLS12381` ciphersuite of `draft-irtf-cfrg-sigma-protocols-03` §8.2:

| Item | Rule |
|---|---|
| Group elements (`Ne = 48`) | compressed G1 (pairing-friendly-curves Appendix C; M0 confirms it is the ADR-0060 Zcash form); the point at infinity is "neither produced … nor accepted"; full point validation on input |
| Scalars (`Ns = 32`) | big-endian `I2OSP`; deserialization fails unless the value is in `[0, q)` |
| Challenges | `DecodeField(Squeeze(Ns + 16), q, 1)`: 48 squeezed octets read **little-endian** (`LE2IP`) and reduced mod `q`; bias at most 2^−128 (fiat-shamir-03 §4.2.2–§4.2.3; sigma-03 §8) |

In the XOF duplex sponge (§3.2), each challenge is SHAKE128 over everything so far: the session
identifier padded to the 168-octet rate, the encoded instance, and the encoded prover messages up
to that round. Consecutive squeezes in one round (`y`, then `z`) continue one output stream.

Only the transcript and the codecs come from the drafts. The interactive protocol is the paper's
range proof. No draft specifies Bulletproofs, so the order of absorbs and squeezes below is this
ADR's, written in the drafts' framework.

**Session identifier** (fiat-shamir-03 §5.1). `session_id = DeriveSessionID(tag)`. The tag is
US-ASCII, built from fixed fields with an unambiguous delimiter, and identifies:
- the argument and its version: `bulletproof-range-bls12-381-g1-v1`;
- the codec and hash suite: `sigma-proofs_Shake128_BLS12381` and `fiat-shamir-03`;
- the round structure and the bit width `n` (which fixes the number of rounds, so §5.1
  requirement 2 puts it in the tag; it is also absorbed in the instance as part of the statement);
- the **application context** `ctx`, as §5.1 requirement 3 asks.

`ctx` is caller-supplied, **1 to 1,024 octets** (r5: non-empty, and unique to the application),
encoded so the tag stays unambiguous (spec §5.1). r1–r4 allowed an empty context; M0 found that an
empty one identifies only the protocol, so two applications that both used it could accept each
other's proofs. The verifier supplies `ctx` from its own
configuration and state (on Yano-X, for example, a chain identifier and message domain), never
from the proof.

**Instance** (fiat-shamir-03 §5.2). The instance is absorbed first, before any prover message, with
a prefix-free encoding of:
- the consumed profile identifier `pedersen-bls12-381-g1-v1`;
- the bases `G` and `H`;
- the generator-set identifier and `D_gens` (D2);
- `n` as `SerializeUint`;
- the commitment `V`.

This makes every challenge depend on the public parameters and the statement. That is the strong
Fiat–Shamir of Dao et al., and the fix for Frozen Heart.

**Rounds** (each prover message is absorbed through the codec before the next squeeze):

1. Absorb `A`, `S`; squeeze `y`, then `z`.
2. Absorb `T₁`, `T₂`; squeeze `x`.
3. Absorb `t̂`, `τ_x`, `μ`; squeeze `x_u`, the inner-product argument's Protocol 1 challenge for
   `u`.
4. For `j = 1 … k`: absorb `L_j`, `R_j`; squeeze `x_j`.

**Zero challenges.** If any challenge is `0`, the verifier rejects, and the prover restarts with
fresh nonces. The paper draws challenges from `Z*_q`; the BP+ audit (ZenGo X 2021, §5.2) and Tari
enforce this check; dalek does not.

**Security level.** sigma-03 Table 1 rates the BLS12-381 G1 suite at "about 120-bit"
pre-quantum. That is the curve's level, not a property of this protocol.

**Changing the transcript.** Changing any item above, the codec, or the draft version needs a new
protocol identifier (registry §5). The identifier pins `-03`. A later draft revision that changes
bytes is a new protocol version, not an update.

**Note on the transcript decision (maintainer, 2026-10-24).** The r1 lean was a ZeroJ SHA-256
chain on `expand_message_xmd`, which Plutus can recompute. It was dropped because **no official
test vector exists for such a chain.** Only its parts have one: RFC 9380 Appendix K.1 for
`expand_message_xmd`, and the BBS vectors for `hash_to_scalar`. The chaining, labels and absorb
order would be checked only by implementations ZeroJ writes itself.

The CFRG drafts publish official vectors for exactly the layer this ADR depends on:
- fiat-shamir-03 Appendix B: the codecs, the SHAKE128 sponge and an example protocol's transcript;
- sigma-03 Appendix A.3: complete proofs in `sigma-proofs_Shake128_BLS12381`, over BLS12-381 G1,
  including `pedersen_commitment` relations.

The maintainer's decision is to **stay on the official standards for the transcript and the
encodings.** The consequences:
- native Plutus verification of this protocol is ruled out, because Plutus has no SHAKE128
  (D8);
- if Cardano verification is wanted later, a SHA-256 transcript becomes a separate protocol
  identifier under its own ADR, and is reviewed as a ZeroJ-specific construction.

Merlin (dalek, Tari) was not chosen either. It has no published vectors, and Plutus cannot
recompute it.

### D4 — Proof encoding and strict decoding (R2)

The proof is a fixed sequence:

```
A ‖ S ‖ T₁ ‖ T₂ ‖ t̂ ‖ τ_x ‖ μ ‖ L_1 ‖ R_1 ‖ … ‖ L_k ‖ R_k ‖ a ‖ b
```

- **Points:** 48-octet compressed G1, decoded with the ADR-0060 D3 strict decoder (steps 1–7), which is the sigma-03 §8.2 full validation. M0 confirms that sigma-03's reference encoding (pairing-friendly-curves Appendix C) is byte-identical to the ADR-0060 encoding on the A.3 vectors.
- **Scalars:** 32-octet big-endian, canonical: check 1, `[0, q)`; never reduced (sigma-03 §8.2.2).
- **Length:** exactly `48·(4 + 2k) + 32·5` octets.

| `n` | `k` | Proof length |
|---:|---:|---:|
| 16 | 4 | 736 octets |
| 32 | 5 | 832 octets |
| 64 | 6 | 928 octets |

**Decoding rules, in order:**

1. `n` comes from the verifier's configuration and must be in `{16, 32, 64}`. Otherwise:
   configuration error.
2. The proof length must equal the length for that `n`, **before anything is decoded or indexed**.
   This rules out the Monero 2026 out-of-bounds class.
3. The proof's fields are decoded **in proof order** (`A`, `S`, `T₁`, `T₂`, `t̂`, `τ_x`, `μ`, `L_1`,
   `R_1`, …, `a`, `b`), as fiat-shamir-03 §6.2 reads a NARG string, and the first failure is
   reported. (r1–r4 decoded all points, then all scalars; M0 aligned the order with the draft in
   r5.)
   - Every point decodes strictly. **The identity is rejected for every proof point** (`A`, `S`,
     `T₁`, `T₂`, `L_j`, `R_j`), as sigma-03 §8.2 requires (dalek does the same). An honest prover
     produces the identity with negligible probability, and if it does, it restarts.
   - Every scalar passes check 1 (`t̂`, `τ_x`, `μ`, `a` and `b`).
4. `V` is decoded with the profile's own decoder (ADR-0060 D3). The decoder accepts the
   identity, but this protocol then **rejects an identity `V`**, because the sigma-03 §8.2 codec
   neither produces nor accepts infinity. The profile itself is unchanged: the identity remains a
   valid `pedersen-bls12-381-g1-v1` commitment for openings and relations. It just cannot carry a
   range proof. An honest committer with a uniform `γ` produces it with negligible probability.
   An API that accepts `V` already decoded MUST accept only a validated subgroup element (the
   `G1PedersenCommitment` type), never raw coordinates.

Outcomes (spec §8.1, §9):
- step 1 is `INVALID_CONFIGURATION`;
- steps 2–4 raise the registry format classes (`MALFORMED_ENCODING`, `NOT_IN_SUBGROUP`,
  `NON_CANONICAL_SCALAR`);
- an identity `V` makes verification return `false`;
- the error carries no secret and no partial verification state.

### D5 — Verification (R2)

The verifier follows paper §6.2, equations (95)–(105), with the challenges of D3. It checks **two
equations separately** (Q3):

1. **The `t̂` check (paper (65)):** `[t̂]·G + [τ_x]·H = [z²]·V + [δ(y, z)]·G + [x]·T₁ + [x²]·T₂`.
   This is a 5-term multi-scalar multiplication.
2. **The inner-product check:** the IPA equation from paper (105), with the challenge products
   `s_i` of §6.2. This is a multi-scalar multiplication of `2n + 2k + 4` terms over `g⃗`, `h⃗`,
   `L_j`, `R_j`, `A`, `S`, `H` and `U`.

**Why two equations, not one.** The paper and dalek merge the two equations into one MSM with a
random weight `c`. A random `c` makes the verdict depend on randomness, which a Yano-X `apply`
forbids. A transcript-derived `c` is not specified by any pinned reference. Checking the two
equations separately is deterministic. It costs one extra MSM intercept and one extra term, because
`H` appears in both checks: `2n + 2k + 9` terms in total, against `2n + 2k + 8` for the union of the
same bases, so 149 against 148 at `n = 64`. The paper's smaller count, `2n + 2 log₂ n + 7`, also
reuses the value base as the inner-product element. This design uses the independent `U` (D2).

**Arithmetic and resources:**
- All scalar arithmetic is mod `q` on canonical values.
- No loop depends on proof contents beyond the fixed `n` from configuration.
- A provider MSM is used when one exists (issue #22). Otherwise the checks are evaluated term by
  term with `g1ScalarMul`, with the same verdict.

### D6 — Proving and secrets (R3)

**Prover input** is a `G1PedersenOpening` `(m, r)` and the width `n`. The prover refuses
deterministically, in this order (spec §7.1):
- **before any curve work**, an invalid configuration (`n` or `ctx`) and `m ≥ 2^n`;
- then, after computing `V = [m]·G + [r]·H` with the secret entry point and **before any proof
  work**, an opening whose commitment is the identity. The prover checks the commitment itself, not just
  the pair. The opening `(0, 0)` is the known case. Any other opening of the identity would reveal
  `log_H(G)`, so finding one is as hard as breaking binding.

The refusal is a fixed error. The prover never re-blinds the caller's commitment, and never retries
nonces for this case: no nonce choice can make an identity `V` acceptable under D4. An opening
`(0, r)` with `r ≠ 0` is valid and proves `v = 0`. The prover never produces a proof it would
itself reject.

**Randomness.**
- Nonces (`α`, `ρ`, `τ₁`, `τ₂`, `s_L`, `s_R`) are fresh per proof.
- Each is 64 octets from `SecureRandom`, reduced mod `q`, the sampler of
  `G1Pedersen.randomBlinding`.
- **Reusing nonces across two proofs leaks the witness.** No API accepts caller-chosen nonces.
- **The prover owns its `SecureRandom`** (spec §7.3):
  - it is created at run time and never accepted from a caller;
  - it is never created in a static initialiser that a native-image build could run at build
    time;
  - the runtime's entropy configuration (JDK providers and security properties, the OS entropy
    source) is **trusted deployment configuration**, because Java cannot verify entropy quality;
  - an algorithm allowlist (`NativePRNG`, `NativePRNGNonBlocking`, `DRBG`, `Windows-PRNG`) is a
    sanity check that rejects an obviously wrong source, not proof of entropy (Codex M0 F8).

  Restarts are bounded at 8 attempts. Exhausting them raises `IllegalStateException`, and no
  proof is emitted.
- **The deterministic nonce source for vectors is fenced as ADR-0046 fences its seeded prover**
  (spec §7.5):
  - the seed → nonce expansion lives only in the unpublished `testFixtures` source set of
    `zeroj-bls12381`, guarded by its module-metadata check;
  - production code has at most package-private test seams, each bounded (spec §7.5): a hook that
    accepts a nonce-source object, never a seed; a path that skips the range refusal so a test can
    force an out-of-range value through the prover (I6); and a challenge tap that can only force
    zero (I4);
  - an API-surface reflection test asserts that no public or protected member of
    `org.zeroj.bls12381.bulletproofs` accepts a seed, a nonce, a nonce source or a
    `SecureRandom`.

  The M0 security review showed why this matters: three same-seed proofs of one opening reveal
  `γ`, and from it `v`.
- *Alternative:* hedged nonces, which mix the witness and the transcript into the random source
  as Merlin's `TranscriptRng` does. Recorded, not chosen: it adds a construction that needs its own
  review.

**Secret operations.**
- Secret-dependent curve operations use only `g1SecretScalarMul`, as ADR-0060 D6 requires:
  `A = [α]·H + ⟨a_L, g⃗⟩ + ⟨a_R, h⃗⟩`, plus `S`, `T₁` and `T₂`.
- Secret-dependent scalar arithmetic (`l(x)`, `r(x)`, `t(x)`, `τ_x`, `μ`) uses `BigInteger` and is
  variable-time.
- **The ADR-0038 offline/isolated restriction applies to proving on both providers.** No
  constant-time claim is made for either.
- `A` depends on the bits of `v` through which generators it adds, so its schedule leaks `v` to a
  timing observer unless it is computed as a full MSM over all `2n` generators, with scalars 0 or 1 on `g⃗` and 0 or −1 on `h⃗`.
  M1 computes it that way, and documents that this is a schedule property, not a constant-time
  guarantee.
- Temporary arrays are wiped in `finally`, best-effort.

**Inner-product rounds.** After challenge `x`, the vectors `l` and `r` are blinded by `s_L` and
`s_R`, and the unoptimised protocol of paper §4.1 sends them in the clear. The inner-product rounds run on them with the public `g1ScalarMul`.

### D7 — Java API and placement (R2)

**Placement.** A new package, `org.zeroj.bls12381.bulletproofs`, in `zeroj-bls12381`, next to
`org.zeroj.bls12381.pedersen`. It needs the strict decoder and the bases. A new module would add a
default project for one package (ADR-0044); a separate package keeps the surface reviewable.

*Implementation note (r6, M1).* The pedersen package keeps its strict decoder and bases
package-private, and a Java package cannot see another's package-private members. So the new
package does not reach into them, and the pedersen package's API is unchanged (I9):
- `G` and `H` are pinned again in `BulletproofGenerators`, and `BulletproofBasesTest` checks
  that they equal the profile's commitments to `(1, 0)` and `(0, 1)`;
- proof points use the package's own strict decoder, on the public `Bls12381Codecs`, in the
  order of `pedersen-bls12-381-g1-v1.md` §4, then reject the identity (spec §3);
- a commitment given as octets is decoded with the public `G1PedersenCommitment.decode`, the
  profile's own strict decoder;
- a `G1PedersenCommitment` is a validated subgroup element by construction (spec §8.1 step 4),
  so its encoding is decompressed without repeating the subgroup check.

SHAKE128 is a new public class, `org.zeroj.bls12381.Shake128`, because `Bls12381Hash`'s
Keccak-f[1600] is package-private to `org.zeroj.bls12381`.

**Public types:**
- `G1RangeProof`: an opaque, immutable proof, with `toBytes()` and `decode(byte[], int bits)`.
- `G1RangeProver`: `prove(G1PedersenOpening, int bits, byte[] context)`. It uses `pureJava()` or
  `withProvider(Bls12381Provider)`, and probes support for secret operations as ADR-0060's
  `supportsGeneration` does.
- `G1RangeVerifier`: `verify(G1PedersenCommitment, G1RangeProof, int bits, byte[] context)`,
  returning a verdict. `bits` and `context` are verifier configuration. An overload takes raw
  proof bytes and decodes them with D4.

**Rules:**
- There is no API that verifies without a context argument, and an empty context is
  `INVALID_CONFIGURATION` (r5).
- No API accepts nonces, generators or a transcript from the caller.
- Native-image `reflect-config.json` entries are added for the public types.

### D7a — Proof-protocol descriptor in `zeroj-api` (R2; added in r5, accepted at the M0 sign-off on 2026-10-25)

**The gap.** `commitment-profiles-v1` §2.4 item 5 admits a proof protocol only with "a descriptor
type fixed when the first protocol is admitted, holding an identifier validated by §2.1". This is
the first protocol, and r1–r4 did not define that type. M0 found the gap.

**Decision:**
- **The type.** `zeroj-api` gains a final descriptor type for proof protocols in
  `org.zeroj.api.commitment`, `ProofProtocol` (the name M1 fixed in registry §12.1). It
  holds:
  - the identifier, validated by the registry §2.1 grammar;
  - the consumed `CommitmentProfile` descriptor;
  - the generator-set identifier.
- **Built-in only.** The descriptor for `bulletproof-range-bls12-381-g1-v1` is created and
  registered in `zeroj-api`'s own static initialisation, as ADR-0060 D8 does for
  `CommitmentProfile`. There is **no public `define` for proof protocols** in v1.
- **Where the identifiers are reserved.** The shared registry set is seeded **in
  `CommitmentProfile`'s own static initialisation**, before any caller can reach `define`. The set
  holds the built-in profile identifiers, the basis-set identifiers, the proof-protocol identifier,
  the generator-set identifier `bulletproof-bls12-381-g1-gens-v1`, and the reserved document names
  of registry §2.2. `CommitmentProfile.define` rejects every one of them with
  `INVALID_CONFIGURATION`.
  - Seeding the set from the proof-protocol class instead would leave a hole. A fresh JVM could
    call `CommitmentProfile.define(protocolId)` first, creating a profile named after the
    protocol, and the protocol class would then fail to initialise.
  - Before M1, `define` checked only profile identifiers. Rejecting basis-set identifiers and
    document names closes that older §2.2 gap.
- **A constant for a reserved protocol is not admission** (registry §2.3), as for profiles.
- **Constants.** It is exposed from a constants class beside `CommitmentProfiles`,
  `ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1`. `G1RangeProof` re-exports it as
  `PROTOCOL`.
- **Acceptance mapping.** `CommitmentAcceptance` lets a `CommitmentFormatException` with
  `INVALID_STATEMENT` propagate unchanged from any step, and never turns it into a
  `CommitmentCheck` (registry §12.1). M1 adds callback regressions for this.
- **Error class.** `CommitmentError` gains `INVALID_STATEMENT`, which registry r8 §11 adds, for
  the prover's identity-commitment refusal. It is **appended** after `PROVENANCE_MISMATCH`, so no
  existing ordinal shifts, and is carried by `CommitmentFormatException` like the other prover
  refusals. `isFormatClass` becomes an explicit set instead of an ordinal comparison, and the test
  that pins ordinals is updated to that set. `INVALID_STATEMENT` never appears in a
  `CommitmentCheck`.
- **Tests (M1):**
  - every field of the descriptor;
  - `define` of the protocol identifier, the generator-set identifier, each basis-set identifier
    and a reserved document name is rejected;
  - a forked-JVM pre-emption regression whose **first** action is `CommitmentProfile.define` of
    the protocol and generator-set identifiers, after which `ProofProtocols` and the range-proof
    classes still load and work;
  - the seeded reserved set equals the registry §2.3 table plus the §2.2 reserved names, so later
    reservations cannot drift;
  - the API-surface tests.

**Alternative rejected.** Reusing `CommitmentProfile` for protocols. A proof protocol is not a
commitment profile: it has no kind, group encoding or opening.

### D8 — Cardano L1: no verifier for this protocol; a measured cost study (R2)

**Why no verifier.** A Plutus V3 validator cannot verify `bulletproof-range-bls12-381-g1-v1`. Its
challenges are SHAKE128 outputs (D3), and Plutus V3 has no SHAKE128 builtin. A validator that took
the challenges from its redeemer would not be a verifier, because the challenges must be computed,
not supplied. So this ADR publishes **no on-chain library**, and registry §14 records the L1 cell
for this protocol as "not native (SHAKE128 transcript)".

**What the cost study measures.** Issue #96 asks for a measured Cardano feasibility report. The
algebra (decompression and both MSMs) is the same under any transcript, so measuring it tells a
future ADR whether a separate, Cardano-specific protocol is worth specifying. Such a protocol would
need a SHA-256 transcript of its own, a new identifier, and its own review (D3 note).

**Estimate before measurement.** A Plutus V3 verifier would have to decompress:
- every generator it uses (`2n`, plus `G`, `H` and `U`);
- `V`;
- every proof point.

It would then run two MSMs. From the PV11 parameters above:

| `n` | Points decompressed | MSM terms | Estimated CPU steps (decompression + MSM only) |
|---:|---:|---:|---:|
| 16 | 48 | 5 + 44 | ≈ 2.54e9 + 1.87e9 ≈ **4.4e9** (44%) |
| 32 | 82 | 5 + 78 | ≈ 4.34e9 + 2.73e9 ≈ **7.1e9** (71%) |
| 64 | 148 | 5 + 144 | ≈ 7.84e9 + 4.38e9 ≈ **12.2e9** (over the 10e9 limit) |

These are **estimates**. They exclude:
- the transcript hashes;
- the `s_i` products (about `2n` modular multiplications);
- script overhead;
- the 16.5M memory budget, which may bind first.

By this estimate a 64-bit proof would not fit one transaction, and a 32-bit proof is uncertain.

**M4 measures** the algebra for `n = 16, 32, 64` in the JuLC VM under PV11, in test sources only:
- CPU, memory and script size;
- cost against the transaction limits.

The measured script takes the challenges as inputs and is labelled **not a verifier**. It is never
published or admitted. The report states feasible or infeasible per width, and nothing more.

### D9 — Yano-X: a deterministic verifier contract, not a plugin (R2)

Issue #96 asks for "a Yano-X adapter verifying proofs deterministically in a confidential-accounting
state machine". Yano-X today pins ZeroJ `0.1.0-pre10` under the old namespace, and its ZK modules are
outside its build. A ZeroJ module that depends on Yano's SPI would invert the dependency.

This ADR therefore delivers, in ZeroJ:

1. **The verifier contract** a Yano-X `apply` relies on, stated in the spec and tested:
   - no randomness, clock, I/O or unordered iteration;
   - a verdict that is a pure function of `(V, proof bytes, n, ctx)` and the pinned constants;
   - the same verdict on every provider;
   - work bounded by `n`;
   - proof length known before decoding;
   - measured verification time per width, with p50/p95 recorded, so a chain can set
     `zk.max-proofs-per-block`.
2. **A reference confidential-accounting state machine in ZeroJ test sources**, with no Yano
   dependency. It shows:
   - authorization (a signed message, simulated);
   - replay protection (a per-sender sequence);
   - the ADR-0051 D3a balance rule;
   - a range proof per output;
   - deterministic rejection;
   - resource limits.
3. **A handoff note for a Yano-X ADR.** The plugin itself lives in `yano-x`, after Yano-X moves to
   an `org.zeroj` release.

Q4 asks whether the maintainer wants the plugin in this ADR instead.

## Alternatives considered

- **Bulletproofs+ instead of Bulletproofs (Q1).**
  - For: three elements smaller (624 / 720 / 816 octets for `n` = 16 / 32 / 64 on BLS12-381),
    deployed in Monero since August 2022, audited twice.
  - Against: the same missing-oracle problem, a weighted inner product with less written
    secondary specification, and two BP+ audit findings (missing infinity and zero-challenge
    checks) that show the edge cases are easy to miss.
  - Kept as a v2 candidate.
- **Bulletproofs++.** Smaller still. The Cypher Stack review (2024) found an incorrect lemma and
  unclear extraction validity, and there is no production deployment. Rejected for v1.
- **Sharp (relaxed range proofs).** It proves the committed value is a fraction, and its authors
  state it is not a drop-in replacement where commitments are added. Rejected.
- **Groth16 range circuit over the G1 commitment.** It needs non-native arithmetic, because G1
  coordinates live in the 381-bit base field, plus a trusted setup per circuit. Rejected.
  Applications that can use **Jubjub** commitments already have in-circuit range checks
  (ADR-0051), and that remains the recommended on-chain path today.
- **Bit-decomposition sigma proofs** (`n` OR-proofs of a bit). Linear size, and OR-composition is
  outside sigma-03. Useful only as a small-`n` test oracle.
- **Aggregated proofs (`m > 1`) in v1.** They save space for multi-output transactions but add
  generator-set growth and the `m`-bound class Monero just fixed. Deferred to a later version.
- **One merged verification equation with a transcript-derived weight.** Rejected for v1 (D5).
- **A ZeroJ SHA-256 transcript on `expand_message_xmd` (r1 lean).** Plutus can recompute it, but
  there is no official vector for the composed transcript; only its parts have one. Rejected by
  the maintainer for this protocol (D3 note). A Cardano-specific variant would be a separate
  protocol under its own ADR.
- **Merlin (STROBE-128).** Used by dalek and Tari. It has no published vectors, needs a Java STROBE
  port, and Plutus cannot recompute it. Rejected.

## Exact invariants

| # | Invariant | Decisions | Evidence required |
|---|---|---|---|
| I1 | The generator set is reproduced independently twice (Java, Python), matches `D_gens`, and passes the D2 distinctness checks | D2 | M0 |
| I2 | Strong Fiat–Shamir: changing any item of D3 (the session-tag fields, including `n` and `ctx`; the instance items profile id, `G`, `H`, `D_gens` and `V`; or any prover message) changes every later challenge; the Frozen Heart forgery recipe is rejected | D3 | M1 tests; M2 vectors with intermediate challenges |
| I3 | Strict decoding: `n` only from configuration; the exact length is checked before any decoding; every proof point is strict and not the identity; every scalar is canonical | D4 | M1 negatives; M2 vector negatives |
| I4 | A zero challenge is rejected by the verifier and never emitted by the prover | D3 | M1 test seam |
| I5 | Completeness, for commitments that are not the identity: honest proofs verify for `v ∈ {0, 1, 2^n − 1}` (with `γ ≠ 0`) and random values at each `n`. The prover refuses `v ≥ 2^n` before any curve work, and an opening whose commitment is the identity (`(0, 0)`) after computing `V` and before any proof work. Both refusals are tested, and `(0, γ ≠ 0)` is accepted | D1, D4, D6 | M1 |
| I6 | Rejection of every single-byte or single-element tamper; of a proof checked under another `n`, `ctx`, `V` or protocol; and of an out-of-range value forced through a test-only prover | D3–D5 | M1, M2 |
| I7 | Determinism: the verdict is a pure function of its inputs; no randomness or unordered iteration on the verification path; identical verdicts on pure Java and blst and across runs | D5, D9 | M1, M2, M3 |
| I8 | Secret handling: proving only through `g1SecretScalarMul` for secret scalars; fresh nonces; no nonce API; best-effort wiping; no constant-time claim | D6 | M1 schedule test with a counting provider stub |
| I9 | No change to the G1 Pedersen profiles, their vectors or `PedersenG1Lib` | — | Byte-identical vectors; unchanged tests |
| I10 | Resource bounds: verification work is a fixed function of `n ≤ 64`; inputs are rejected before work | D4, D5 | M1 tests; M3 measurements |
| I11 | Measurements are records, never security evidence | D8, D9 | — |
| I12 | Transcript conformance on the vector sets listed under "Conformance vector scope" (Verification strategy): the fiat-shamir-03 codec and SHAKE128 vectors; the sigma-03 A.3.1 valid proofs for `discrete_logarithm` and `pedersen_commitment`, where the session identifier and challenges are reproduced and the proof verifies; and every A.3.2 adversarial vector, as rejections, or acceptances for the four non-reject `F` controls. SHAKE128 also agrees with CPython's `hashlib.shake_128` | D3, D4 | M0 (Python), M1 (Java) |
| I13 | The proof-protocol descriptor (D7a) is built-in, registered before any external `define`, and its identifier cannot be pre-empted | D7a | M1 tests, including a forked-JVM regression |

## Compatibility

- **Additive, with two intentional tightenings.** A new package in `zeroj-bls12381`, a new spec,
  a new vector file and a registry revision (r8) that adds `reserved` entries at M0 and makes them
  `active` at M6. No existing profile, cryptographic encoding or vector changes. Two existing
  behaviours do change, at M1:
  - `CommitmentProfile.define` rejects identifiers it used to accept: basis-set and
    proof-protocol identifiers, and the reserved document names (D7a, registry §2.2);
  - `CommitmentError` gains an appended member, and `CommitmentAcceptance` lets
    `INVALID_STATEMENT` propagate (registry §12.1).

  Callers that defined such identifiers get `INVALID_CONFIGURATION`.
- **Transcript versioning.** Any change to D2, D3 or D4 after admission needs a new protocol
  identifier, and proofs under the old identifier stay verifiable under it.
- **Yano-X.** Using the verifier needs a Yano-X dependency upgrade to an `org.zeroj` release (D9).

## Implementation milestones (after acceptance)

| Milestone | Entry gate | Deliverables | Exit |
|---|---|---|---|
| **M0** spec and second implementation | ADR accepted; Q1 and Q3–Q7 decided | `docs/specs/bulletproof-range-bls12-381-g1-v1.md`: generators, session tag and instance bytes, encoding, verifier equations, error classes, test seams. Registry r8 adds the entries as `reserved`. FIPS 202 pinned. A stand-alone Python implementation (stdlib only, using `hashlib.shake_128` for SHAKE128, on the ADR-0060 M0 BLS12-381 code), written from the paper and the specs without reading Java: XOF duplex sponge and codecs, prover, verifier, generator derivation, and output of intermediate challenges | Python passes the I12 vector scope; Java `hashToG1` and Python agree on `D_gens`; Python round-trips its own proofs; review loop reports SPEC READY; **maintainer sign-off** |
| **M1** Java | M0 signed off | SHAKE128 (rate 168 on the existing Keccak-f[1600]) and the XOF duplex sponge and codecs, tested on the I12 scope: the fiat-shamir-03 codec and SHAKE128 vectors; a test-only sigma harness for the A.3.1 `discrete_logarithm` and `pedersen_commitment` proofs and all A.3.2 adversarial vectors; the seven A.3.2 codec-layer rejections also run directly against the D4 decoders; and `hashlib.shake_128` outputs. Package `org.zeroj.bls12381.bulletproofs`, all D4–D7 rules, the D7a descriptor, the shared reserved set and `INVALID_STATEMENT` in `zeroj-api`, the test-only nonce source in `zeroj-bls12381` `testFixtures` (metadata guard re-run), an API-surface reflection test (scoped to `org.zeroj.bls12381.bulletproofs`) that no public member accepts a seed, nonce, nonce source or `SecureRandom`, the `SecureRandom` algorithm allowlist (a sanity-check test only; entropy configuration is trusted), unit and negative tests (I2–I8, I10, I12, I13), API surface test, seeded faults (below) | Module suites green; I12 vectors pass; seeded faults killed |
| **M2** vectors and cross-implementation | M1 | `bulletproof-range-bls12-381-g1-v1.json` with fixed-nonce proofs, every intermediate challenge, and negatives. Generator with `--check` and `--self-test`. Java verifies Python proofs and Python verifies Java proofs. A reviewer recomputes the verifier side with separate code (for example on py_ecc). **External algebra check against dalek:** the Python protocol code is parameterised by group and transcript, run on ristretto255 (RFC 9496, fetched and pinned at M2, with its vectors) with Merlin and dalek's deviations (D2, D5), and must verify dalek's published test proofs (`tests/range_proof.rs`, `n` = 8–64) and produce proofs dalek 5.0.0 verifies. blst parity | Byte-identical regeneration; both directions pass; independent recomputation matches; the dalek check passes in both directions |
| **M3** performance and determinism | M2 | Benchmark harness (`commitment-profiles-v1` §15 method): prove and verify p50/p95 per `n`, allocation, 1 and 8 threads, pure Java and blst. Uses the #22 MSM if merged, otherwise records the term-by-term cost. Determinism test (repeated runs, both providers) | Measurements recorded; no check removed for speed |
| **M4** Cardano cost study | M2 | JuLC VM probes in test sources for `n` = 16, 32, 64: generator decompression, both checks, challenges supplied as inputs, labelled "not a verifier" (D8). PV11 CPU, memory and script size. On-chain `hashToGroup` reproduction of the generators | Measurements and a feasible/infeasible verdict per `n` recorded in a benchmark doc; no library published |
| **M5** Yano-X contract | M3 | Verifier contract in the spec (D9). Reference confidential-accounting state machine in `zeroj-integration-tests` test sources with authorization, replay, the D3a rule and limits, plus a negative suite. Handoff note for a Yano-X ADR | Tests green |
| **M6** docs and admission | M1–M5 | Registry r8 makes the entries `active` (experimental) if every prerequisite holds: accepted ADR, spec, I1, I12, M2 vectors with independent recomputation and the dalek check, M3 measurements. The §14 V4 cell is updated. Module README, support matrix, docsite page, ADR implementation-evidence section | Admission recorded; otherwise entries stay `reserved` with the gap stated |

**Seeded faults M1 must kill:**
- drop `V`, `n`, `ctx` or `D_gens` from the transcript;
- reuse `y` for `z`;
- accept an identity proof point;
- skip check 1 on `a` or `b`;
- accept a longer `L`/`R` list;
- swap `G` and `H`;
- swap `g⃗` and `h⃗`;
- compute `δ(y, z)` with the wrong sign;
- accept a zero challenge;
- let the prover accept `v = 2^n`.

## Verification and test strategy

**Where the evidence comes from.** Each layer has a different source, and only some of them are
outside ZeroJ:

| Layer | Official or external evidence | Written by ZeroJ |
|---|---|---|
| SHAKE128 | fiat-shamir-03 Appendix B.2; CPython `hashlib.shake_128` | Java SHAKE128 |
| Duplex sponge and codecs | fiat-shamir-03 Appendix B | Java and Python implementations |
| Transcript over BLS12-381 G1 | sigma-03 Appendix A.3 (`sigma-proofs_Shake128_BLS12381`) | the test-only A.3 harness |
| Generators (hash-to-curve) | RFC 9380 J.9.1 and K.1 (already in the tests) | the D2 derivation |
| Bulletproof algebra | dalek 5.0.0 test proofs and verifier, through the group-generic Python code (M2); the paper | Java, and the Python second implementation |
| The protocol's own vectors | none exist: no standard, no BLS12-381 implementation | the M2 vector file |

**The Python implementation is ZeroJ's own.** It is not an official or third-party reference. It
is independent in a narrower sense:
- it is written by a separate author (an agent instructed not to read the Java), in another
  language, from the paper and the specifications only;
- it uses `hashlib` for SHA-256 and SHAKE128 and the ADR-0060 M0 curve code, whose correctness is
  anchored on the RFC 9380 vectors and a reviewer's py_ecc recomputation.

Agreement between Java and Python shows that two implementations read the specification the same
way. It does not show that the specification is right. That is why the dalek check and external
review matter.

**Conformance vector scope (I12).** The scope covers the vectors for the functions this protocol
uses, not every vector in the two appendices.

| Source | In scope | Out of scope, and why |
|---|---|---|
| fiat-shamir-03 B.1 (codec) | B.1.1, B.1.2, B.1.4–B.1.8, B.1.10, B.1.11: variable-length strings, unsigned integers, `DecodeUint`, big-endian prime-field serialization, and their rejections | B.1.3 and B.1.9 (degree-2 extension fields, unused); B.1.12 and B.1.13 (the Appendix A sumcheck example over Mersenne31, unused) |
| fiat-shamir-03 B.2 (SHAKE128) | B.2.1–B.2.11: sponge behaviour, `DeriveSessionID`, `DecodeUint` | B.2.12 and B.2.13 (sumcheck example) |
| fiat-shamir-03 B.3 (TurboSHAKE128) | none | this design selects SHAKE128 |
| sigma-03 A.3.1 (14 valid proofs) | `discrete_logarithm` and `pedersen_commitment`, batchable and compact (4). Checks: the session identifier is reproduced, every challenge is reproduced, and the proof verifies | `dleq`, `pedersen_commitment_dleq`, `bbs_blind_commitment_computation`, `elgamal_decryption` and `dleq_derived_element` (10): they need general linear-relation machinery beyond the transcript layer this ADR uses |
| sigma-03 A.3.2 (32 adversarial vectors under the `discrete_logarithm` base identifier; F2 and F2b carry a `dleq` instance, and E1–E3 are synthetic instances rejected by sigma-03 §3.5 instance validation) | All 32, through the harness. 28 must be rejected; the four non-reject controls (`batchable/F1`, `compact/F1`, `batchable/F2`, `compact/F2`) must be accepted. A1, A3–A6 (points) and B1, B2 (scalars) must fail **at deserialization, before any challenge is derived**, and also run directly against the D4 point and scalar decoders. C1 and C2 are length failures; D, E, F and H are verification-layer failures | — |

Valid-proof checks assert reproduced challenges. Rejection checks assert only the rejection and the
layer it happens at; a vector that fails during decoding has no challenge to compare.

**Rules:**
- No values are derived from the code under test. Fixed nonces come from a documented test-only
  expansion, so the vectors are reproducible.
- **Cross-implementation:** Java↔Python proofs in both directions. A reviewer recomputes the
  verifier with separate code (py_ecc), as for ADR-0060.
- **Bulletproof vectors:** none are published for BLS12-381. dalek's Ristretto vectors are used
  only through the group-generic Python code (M2), never as vectors for this protocol.
- **Adversarial cases:**
  - the Frozen Heart recipe;
  - transcript-item omission (each item in turn);
  - identity and non-subgroup points;
  - scalars `≥ q`;
  - wrong lengths;
  - wrong `n`;
  - a zero-challenge seam;
  - `v = 2^n` and `v = q − 1` refused by the prover;
  - a test-only prover forcing an out-of-range value, which must fail verification;
  - MSM edge cases: zero scalars and repeated bases.
- **Property tests:** random values and widths verify; random single-bit flips fail.
- **Provider parity:** pure Java and blst give identical proofs (with fixed nonces) and identical
  verdicts on every vector.

## Consequences

- ZeroJ gets its first setup-free proof over a commitment, and its first registered proof protocol.
- Applications can check that hidden G1-committed amounts are non-negative and bounded. Off-chain
  balance arguments then become sound under ADR-0051 D3a.
- The CFRG duplex-sponge transcript (SHAKE128) enters the codebase, beside the PlonK transcript. It
  is reusable for ADR-0051 D7 option (a). The protocol identifier pins draft `-03`, so a later
  draft revision means a new protocol version.
- Verification cost depends on MSM support (#22) and on trusted-point handling (#104). Without
  them, a 64-bit verification would spend about 150 × 4.3 ms ≈ 0.65 s on input re-validation alone
  (an estimate from the ADR-0060 measurement). M3 records the real figure.
- No native on-chain verification for this protocol (D8). On-chain range checks today are better
  served by Jubjub commitments in a Groth16 circuit (ADR-0051). A Cardano-specific variant would
  need its own transcript and ADR.

## Risks and production/audit gates

- **Novel composition.** There is no Bulletproofs standard and no BLS12-381 reference
  implementation. The transcript and codecs follow the CFRG drafts, but placing the paper's rounds
  in them (D3) is this ADR's own composition.
  - **External cryptographic review of the spec (generators, transcript, encoding and verifier)
    is required before any value-bearing use.**
  - Q7 asks whether it must also come before admission as `active` (experimental).
- **Weak Fiat–Shamir regressions.** I2 tests and the seeded faults guard the transcript; review of
  any transcript change is mandatory.
- **Side channels in proving.** Proving is offline/isolated only (ADR-0038). There is no
  constant-time claim.
- **Draft drift.** fiat-shamir-03 and sigma-03 are Internet-Drafts and expire on 2027-02-18. A
  later revision can change bytes. The identifier pins `-03`; proofs under it stay verifiable, and a
  new revision means a new protocol version.
- **Performance.** Without #22 and #104, verification may be too slow for per-block use on
  Yano-X. M3 measures before any recommendation is made.
- **Maturity.** Experimental. Test counts, vectors, AI review and on-chain execution are not
  security evidence (AGENTS.md).

## Related findings (out of scope)

- **#22 (provider MSM) and #104 (re-validation of trusted points)** decide verification speed. They
  are shared R3 primitives with their own designs.
- **ADR-0051 D7** (G1 sigma proofs) stays open. Its option (a) ("implement the CFRG ciphersuite
  exactly") could reuse the SHAKE128 transcript built here; this ADR does not decide D7.
- **Aggregated range proofs and multi-proof batching** are a later version.
- **A Jubjub ↔ G1 bridge** proving two commitments hold the same value (ADR-0051 D8).

## Design questions for the maintainer

All seven were decided by maintainer Satya on 2026-10-24. D7a (r5) is a later design addition that awaits the maintainer's acceptance at the M0 sign-off. The other options are kept for the record.

| # | Question | Options | Decision |
|---|---|---|---|
| Q1 | Protocol variant | (a) Bulletproofs (ePrint 2017/1066, 2022-04-14), one value per proof; (b) Bulletproofs+ | **Decided (a)**: most independent review and written specification; BP+ saves 112 octets at `n = 64` |
| Q2 | Fiat–Shamir construction (D3) | (a) ZeroJ SHA-256 chain on `expand_message_xmd`, recomputable on Plutus; (b) CFRG fiat-shamir-03 with SHAKE128 and sigma-03 BLS12-381 codecs; (c) Merlin | **Decided (b)** by maintainer Satya, 2026-10-24: stay on the official standards. The composed transcript in (a) would have no official vectors (D3 note) |
| Q3 | Verifier combination (D5) | (a) two separate checks, deterministic; (b) one MSM with a transcript-derived weight; (c) one MSM with a random weight | **Decided (a)**: deterministic and specified; the cost is one extra MSM intercept |
| Q4 | Yano-X deliverable (D9) | (a) verifier contract plus a reference state machine in ZeroJ test sources, with the plugin in `yano-x` under its own ADR; (b) the Yano-X plugin in this ADR | **Decided (a)**: avoids a ZeroJ → Yano dependency; Yano-X first needs an `org.zeroj` upgrade |
| Q5 | Cardano scope (D8) | (a) a JuLC VM cost study of the algebra, labelled "not a verifier"; (b) no on-chain work beyond the estimate | **Decided (a)**: the issue asks for a measured feasibility report, and the result tells a future ADR whether a Cardano-specific variant is worth specifying |
| Q6 | Widths | (a) `{16, 32, 64}`; (b) add 8 | **Decided (a)**: the issue's set; 8 adds little |
| Q7 | When external review is required | (a) before value-bearing use, with admission as `active` (experimental) allowed after M6; (b) before admission | **Decided (a)**: matches how ADR-0060 admitted its entries as experimental |

## Revision history

- **r1 (2026-10-24):** initial proposal.
- **r2 (2026-10-24; maintainer decision before the first review of `7b96210`):** Q2 decided as (b).
  The maintainer stays on the official standards because the r1 lean (a ZeroJ SHA-256 chain) has
  no official vectors.
  - **D3:** rewritten on fiat-shamir-03 (XOF duplex, SHAKE128, `DeriveSessionID` with the context
    in the tag, the instance absorbed first) and the sigma-03 §8.2 codecs (challenges are 48
    octets, little-endian, mod `q`), with a note on the decision.
  - **D4:** an identity `V` is now rejected (the sigma-03 codec); M0 confirms the encodings are
    byte-identical.
  - **D8:** no on-chain verifier for this protocol (Plutus has no SHAKE128); M4 becomes a cost
    study labelled "not a verifier"; Q5 reworded.
  - **Evidence:** I12 added (fiat-shamir-03 Appendix B, sigma-03 A.3, `hashlib.shake_128`); M0, M1
    and M2 updated; the dalek algebra check moved from optional to M2.
  - **Verification strategy:** now has a table of which layers are checked externally, and states
    plainly that the Python implementation is ZeroJ's own.
  - **References:** fiat-shamir-03 and sigma-03 split and made normative; FIPS 202 added (pinned at
    M0).
  - Alternatives, consequences, risks and related findings updated.
- **r3 (2026-10-24; responds to the review of `ca30142`, Verdict APPROVED with three P3 findings):**
  - **F1:** a "Conformance vector scope" table lists the in-scope fiat-shamir-03 B.1 and B.2
    vectors. B.3 (TurboSHAKE128), the extension-field vectors and the sumcheck vectors are out of
    scope. In sigma-03, the scope is the four A.3.1 valid proofs and all 32 A.3.2 adversarial
    vectors, separating challenge checks from rejection checks and the layer each rejection
    happens at. I12, M0 and M1 are aligned to it.
  - **F2:** the D1 statement now excludes the identity `V`. The D6 prover refuses any opening whose
    commitment is the identity (`(0, 0)` is the known case) deterministically, with no re-blinding
    and no nonce retry. I5 is qualified,
    with tests for `(0, 0)` refused and `(0, γ ≠ 0)` accepted. The stale "pending Q2" in D1 is
    removed.
  - **F3:** D5 now gives the separate-check cost as one extra intercept and one extra term
    (`2n + 2k + 9` against `2n + 2k + 8`), and notes that the paper's count reuses the value base
    where this design uses an independent `U`.
- **r4 (2026-10-24):** accepted (design) by maintainer Satya. Q1 and Q3–Q7 are decided as leaned
  (a); Q2 was already decided (b) in r2. Codex's APPROVED review of `ca30142` is recorded. A
  maintainer sign-off follows M0.
- **r5 (2026-10-24, M0):** new **D7a**: a built-in proof-protocol descriptor in `zeroj-api` with
  no public `define`, plus `CommitmentError.INVALID_STATEMENT`. Registry §2.4 item 5 requires a
  descriptor type for the first proof protocol, and r1–r4 did not define one. D7a awaits the
  maintainer's acceptance at the M0 sign-off. I13 is added.
  - **D3/D7 amendment (same sign-off):** the application context must now be non-empty (1 to
    1,024 octets). M0's second implementation found that an empty context lets proofs move
    between applications that both use it.
  - **Security review (reviewer (b)), same sign-off:**
    - D6 states the refusal order exactly, the nonce-source rules and restart bound, and fences
      the test seam as ADR-0046 does;
    - D7a pins where identifiers are reserved, extends the `define` rejection to every registry
      type and the reserved names, and fixes how `INVALID_STATEMENT` enters the enum;
    - the CFRG vector licence must be confirmed before merge.
  - **Codex M0 round 3 (F8):** the runtime's entropy configuration is now a stated trust
    assumption, and the `SecureRandom` algorithm allowlist is kept as a sanity check only.
  - **Codex M0 round 2:**
    - the `INVALID_STATEMENT` propagation rule in `CommitmentAcceptance`;
    - I5 refusal timing;
    - compatibility now names the two intentional tightenings;
    - registry §2.4 covers the generator set's vectors through the protocol file.
  - **D4 amendment (same sign-off; Codex M0 F2):** proof fields are decoded in proof order, as
    fiat-shamir-03 §6.2 reads a NARG string, instead of all points before all scalars. `V` is
    decoded after the proof's format checks, so the length is still checked before anything is
    decoded (I3). The outcomes are the spec's registry classes, and a decoded `V` must be a
    validated subgroup element (Codex M0 F1). The A.3.2 scope row now describes those vectors
    accurately.
- **r6 (2026-10-25, M0 sign-off and M1):**
  - **Sign-off:** the maintainer signed off M0 and, with it, the r5 additions (Status). D7a is no
    longer pending; its type names are fixed as `ProofProtocol` and `ProofProtocols`.
  - **D7 implementation note:** how the new package gets the bases and the strict decoders
    without opening the pedersen package, and the new public `Shake128` class.
  - **M1 implemented:** see Status. The CFRG vector licence stays a before-merge gate.
- **r7 (2026-10-25, M1 review round 1 of `fb5d2ac`):** Codex F1–F2, reviewer (b) F1–F5 and
  reviewer (c) F1–F9, all accepted.
  - **Resource bounds (I10):** the proof length and the context length are checked on the caller's
    array before anything is copied.
  - **D6:** the three package-private test seams are listed (spec §7.5); the challenge tap can force
    only zero, and the range-skipping path still checks the configuration. The native-image
    entries register public members only.
  - **Evidence added at M1:**
    - context tags with every octet class, pinned by the CFRG PoC code;
    - nonce sampling (64 octets, big-endian, mod `q`, buffer wiped);
    - a fixed multiplication count for every proof that reaches the checks, and none for a
      rejected input;
    - every point position against four malformed encodings;
    - final-scalar `+ q` malleability;
    - the context snapshot during proving;
    - sigma-03 check 10 in the harness.
  - **Seeded faults (M1 exit criterion):** all 14 of the M1 list were applied one at a time to a
    copy of `fb5d2ac`, each confirmed to compile, and each made the bulletproofs tests fail
    (14/14 killed). Reviewer (a) independently killed the same list plus three faults of its own.
    Reviewer (c) ran 18 more mutants; 8 survived, and the evidence added in this revision targets
    each of them. The rerun on the revised code also includes "skip check 1 on `a`" (Codex F2)
    and those survivors.
  - **Round 2 (`316d1e5`):** Codex, reviewer (a), reviewer (b) and reviewer (c) all report M1
    READY with no P0–P2 open. The two P3s that remained (Codex r2 F3, reviewer (c) F11: the nonce
    sample was palindromic, so the byte order was untested) are fixed with a non-palindromic
    sample whose residues were computed in Python.
  - **Recorded gaps:** pinned proofs at `n = 32` and `n = 64` come with the M2 vector file.
- **r8 (2026-10-25, M2):** the evidence listed under Status, and the dalek crate note (reference
  10).
  - **Spec §11:** the vector file must have a positive case at each width (reviewer (c) M1 F10).
    Positive cases at 32 and 64 bits kill the n-dependent fault that the 16-bit known-answer
    test missed (reviewer (c) M1 MU15). The
    allowlist is tested through `SystemNonceSource.checked`, not through a JVM whose default
    `SecureRandom` is not allowlisted.
