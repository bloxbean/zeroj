# ADR-0061: Bulletproof range proofs for BLS12-381 G1 Pedersen commitments

## Status

**Proposed** (design only; no implementation in this PR).

Addresses [issue #96](https://github.com/bloxbean/zeroj/issues/96), phase 4 of the #93–#96 Pedersen
roadmap. It defines the first proof protocol of the commitment-profile registry
(`commitment-profiles-v1` §5): a range proof over `pedersen-bls12-381-g1-v1` commitments, the
"V4 proof" cell that registry §14 lists as "blocked (ADR-0051 D7; #96)".

Seven questions need a maintainer decision before acceptance (see "Design questions for the
maintainer"). The two that matter most are the protocol variant (Q1) and the Fiat–Shamir transcript
(Q2). This ADR records a lean on each and decides neither.

**Risk: R3** for the proof protocol, the generator derivation (D2), the transcript (D3) and the
prover's secret handling (D6). **R2** for the proof encoding and strict decoding (D4), the Java API
(D7), the registry entry (D1), the Yano-X verifier contract (D9) and the Cardano feasibility spike
(D8).

Accepting this ADR would be design acceptance only. It would certify no implementation, test or
security property, and no AI review upgrades a maturity or security claim (AGENTS.md).

## Date

2026-10-24 (r1)

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
same choice (Q2). This ADR does not decide D7 either; Q2's answer can be reused there.

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
- ZeroJ implements SHAKE256 for the BBS SHAKE suite (`Bls12381Hash.hashToScalarXofShake256`). It has
  no SHAKE128 and no duplex-sponge transcript.
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
- SHA-256 (and SHAKE128 if Q2 picks it) as a random oracle;
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
7. **draft-irtf-cfrg-fiat-shamir-03** (2026-08-17) and **draft-irtf-cfrg-sigma-protocols-03**
   (2026-08-17). These are Q2 option (b), and the encoding profile this ADR follows in any case:
   - sigma-03 §8.2: BLS12-381 G1 points are 48-octet compressed, and infinity is "neither produced
     … nor accepted"; scalars are 32-octet big-endian in `[0, q)`;
   - fiat-shamir-03 §5.1–§5.2: the session identifier, and the instance absorbed first;
   - fiat-shamir-03 §4.2.3: scalars are derived from `Ns + 16` octets.
8. **dalek/zkcrypto `bulletproofs`** at `04bce4e66013ff857ed462fd4206210544101461` (2025-09-13),
   MIT: the notes in `docs/notes-rp.md` and `docs/notes-ipp.md`, and the transcript order in
   `src/transcript.rs` and `src/range_proof/mod.rs`.
   - This is a secondary written specification and a cross-check of the algebra. It is not a
     vector source, because it uses Ristretto255 and Merlin.
   - This ADR's deviations from dalek are listed in D3 and D5.
9. **CIP-0381** and **CIP-0133** at `86b89208d3b2aabb5dcc5b778dfbe09096b4e114`, as pinned by ADR-0060.
10. **ZeroJ:**
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
| Statement | the prover knows `(v, γ)` with `V = [v]·G + [γ]·H` and `0 ≤ v < 2^n` as integers |
| Widths | `n ∈ {16, 32, 64}`; the verifier takes `n` from its configuration, never from the proof |
| Values per proof | one (`m = 1`); aggregation is deferred |
| Generator set | `bulletproof-bls12-381-g1-gens-v1` (D2) |
| Transcript | D3 (pending Q2) |
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

### D3 — Transcript and challenges (R3; the construction is Q2)

**Required content, whichever construction Q2 picks.** The transcript is strong Fiat–Shamir in the
sense of Dao et al. Every challenge is a function of everything before it:

1. **Session identifier:** the protocol identifier `bulletproof-range-bls12-381-g1-v1` and the
   transcript-construction version.
2. **Public parameters:** the consumed profile identifier `pedersen-bls12-381-g1-v1`; the basis set
   identifier and the compressed `G`, `H`; the generator set identifier and `D_gens`.
3. **Instance:** `n` (as `I2OSP(n, 4)`), the application context `ctx`, and the compressed `V`.
4. **First round:** `A`, `S`, then challenges `y` and `z`.
5. **Second round:** `T₁`, `T₂`, then challenge `x`.
6. **Third round:** `t̂`, `τ_x`, `μ`, then challenge `x_u` (the inner-product argument's
   Protocol 1 challenge for `u`).
7. **Inner-product rounds:** for `j = 1 … k`, `L_j` and `R_j`, then challenge `x_j`.

**Encoding rules:**
- **Labels.** Every absorbed item carries a distinct label and an explicit length. No label is a
  prefix of another, and the encoding is prefix-free (fiat-shamir-03 §5.2).
- **Context.** `ctx` is caller-supplied octets of at most 1,024 octets, absorbed with its length.
  An empty context is allowed but discouraged. The verifier supplies `ctx` from its own
  configuration and state (on Yano-X, for example, a chain identifier and message domain), never
  from the proof.
- **Scalar challenges** are derived from at least 48 uniform octets, reduced mod `q`. The bias is
  at most 2^−128 (fiat-shamir-03 §4.2.3; BBS `hash_to_scalar`).
- **Zero challenges.** If any challenge is `0`, the verifier rejects. The prover restarts with fresh
  nonces. The paper draws challenges from `Z*_q`; the BP+ audit (ZenGo X 2021, §5.2) and Tari
  enforce this check; dalek does not.

**Q2: the construction.** There are three options, and the ADR does not decide:

- **(a) A ZeroJ SHA-256 chain on RFC 9380 `expand_message_xmd`.**
  - Each absorb updates a chained state, `h_i = SHA-256(h_{i−1} ‖ label ‖ I2OSP(len, 4) ‖ data)`.
  - Each challenge is `OS2IP(expand_message_xmd(h_i ‖ label, DST_C, 48)) mod q`, the same
    expansion as BBS `hash_to_scalar` and `BbsHashToScalar` on-chain.
  - This sketch is illustrative; M0 pins the exact bytes.
  - It can be recomputed on Plutus, but no outside implementation exists.
- **(b) `draft-irtf-cfrg-fiat-shamir-03` with SHAKE128**, and sigma-03 §8.2 encodings.
  - It is on the standards track and has test vectors (Appendix B).
  - The draft can still change. ZeroJ has no SHAKE128 or duplex sponge yet, and Plutus cannot
    recompute it, so L1 verification is ruled out.
- **(c) Merlin (STROBE-128)**, as in dalek and Tari.
  - It is the most-used transcript for Bulletproofs.
  - It has no published vectors (merlin.cool lists them as "TBD") and needs a Java STROBE port.
    Plutus cannot recompute it, since CIP-0101 exposes only the `keccak_256` hash, not the
    permutation.
  - dalek's labels do not absorb the generators, so this ADR would add them.

**Changing the construction.** Changing any of these items, or the construction, needs a new
protocol identifier (registry §5).

### D4 — Proof encoding and strict decoding (R2)

The proof is a fixed sequence:

```
A ‖ S ‖ T₁ ‖ T₂ ‖ t̂ ‖ τ_x ‖ μ ‖ L_1 ‖ R_1 ‖ … ‖ L_k ‖ R_k ‖ a ‖ b
```

- **Points:** 48-octet compressed G1, decoded with the ADR-0060 D3 strict decoder (steps 1–7).
- **Scalars:** 32-octet big-endian, canonical: check 1, `[0, q)`; never reduced.
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
3. Every point decodes strictly. **The identity is rejected for every proof point** (`A`, `S`, `T₁`,
   `T₂`, `L_j`, `R_j`), as sigma-03 §8.2 and dalek do. An honest prover produces the identity with
   negligible probability, and if it does, it restarts.
4. Every scalar passes check 1 (`t̂`, `τ_x`, `μ`, `a` and `b`).
5. `V` is decoded with the profile's own decoder, which accepts the identity (ADR-0060 D3). A
   commitment to `v = 0, γ = 0` is valid, and a verifier that refuses it does so as policy.

The verdict is a single "invalid proof" outcome for steps 2–5, plus a distinct
"invalid configuration" outcome for step 1. The error carries no secret and no partial
verification state.

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
equations separately is deterministic and costs one extra MSM intercept (5 more terms off-chain).

**Arithmetic and resources:**
- All scalar arithmetic is mod `q` on canonical values.
- No loop depends on proof contents beyond the fixed `n` from configuration.
- A provider MSM is used when one exists (issue #22). Otherwise the checks are evaluated term by
  term with `g1ScalarMul`, with the same verdict.

### D6 — Proving and secrets (R3)

**Prover input** is a `G1PedersenOpening` `(m, r)` and the width `n`. The prover refuses
`m ≥ 2^n` before any curve work. It never produces a proof it would itself reject.

**Randomness.**
- Nonces (`α`, `ρ`, `τ₁`, `τ₂`, `s_L`, `s_R`) are fresh per proof.
- Each is 64 octets from `SecureRandom`, reduced mod `q`, the sampler of
  `G1Pedersen.randomBlinding`.
- **Reusing nonces across two proofs leaks the witness.** No API accepts caller-chosen nonces.
- A deterministic nonce source exists only as a package-private test seam, for vector
  generation.
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
`org.zeroj.bls12381.pedersen`. It needs the strict decoder and the bases, which are package-private
there. A new module would add a default project for one package (ADR-0044); a separate package
keeps the surface reviewable.

**Public types:**
- `G1RangeProof`: an opaque, immutable proof, with `toBytes()` and `decode(byte[], int bits)`.
- `G1RangeProver`: `prove(G1PedersenOpening, int bits, byte[] context)`. It uses `pureJava()` or
  `withProvider(Bls12381Provider)`, and probes support for secret operations as ADR-0060's
  `supportsGeneration` does.
- `G1RangeVerifier`: `verify(G1PedersenCommitment, G1RangeProof, int bits, byte[] context)`,
  returning a verdict. `bits` and `context` are verifier configuration. An overload takes raw
  proof bytes and decodes them with D4.

**Rules:**
- There is no API that verifies without a context argument; callers pass an empty array
  explicitly.
- No API accepts nonces, generators or a transcript from the caller.
- Native-image `reflect-config.json` entries are added for the public types.

### D8 — Cardano L1: a measured feasibility spike only (R2)

This ADR publishes **no on-chain library**. Registry §14 keeps the L1 cell at "feasibility (#96)"
until a later ADR revision admits one with measurements.

**Estimate before measurement.** A Plutus V3 verifier must decompress:
- every generator it uses (`2n`, plus `G`, `H` and `U`);
- `V`;
- every proof point.

It then runs two MSMs. From the PV11 parameters above:

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

By this estimate a 64-bit proof does not fit one transaction, and a 32-bit proof is uncertain.

**M4 measures** `n = 16, 32, 64` in the JuLC VM under PV11:
- CPU, memory and script size;
- cost against the transaction limits;
- whether option (a) of Q2 recomputes the challenges.

Per Q5, it may also include a DevKit run. The spike code stays in test sources.

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

## Exact invariants

| # | Invariant | Decisions | Evidence required |
|---|---|---|---|
| I1 | The generator set is reproduced independently twice (Java, Python), matches `D_gens`, and passes the D2 distinctness checks | D2 | M0 |
| I2 | Strong Fiat–Shamir: changing any item of D3 (protocol id, profile id, `G`, `H`, `D_gens`, `n`, `ctx`, `V`, or any prover message) changes every later challenge; the Frozen Heart forgery recipe is rejected | D3 | M1 tests; M2 vectors with intermediate challenges |
| I3 | Strict decoding: `n` only from configuration; the exact length is checked before any decoding; every proof point is strict and not the identity; every scalar is canonical | D4 | M1 negatives; M2 vector negatives |
| I4 | A zero challenge is rejected by the verifier and never emitted by the prover | D3 | M1 test seam |
| I5 | Completeness: honest proofs verify for `v ∈ {0, 1, 2^n − 1}` and random values at each `n`; the prover refuses `v ≥ 2^n` before curve work | D6 | M1 |
| I6 | Rejection of every single-byte or single-element tamper; of a proof checked under another `n`, `ctx`, `V` or protocol; and of an out-of-range value forced through a test-only prover | D3–D5 | M1, M2 |
| I7 | Determinism: the verdict is a pure function of its inputs; no randomness or unordered iteration on the verification path; identical verdicts on pure Java and blst and across runs | D5, D9 | M1, M2, M3 |
| I8 | Secret handling: proving only through `g1SecretScalarMul` for secret scalars; fresh nonces; no nonce API; best-effort wiping; no constant-time claim | D6 | M1 schedule test with a counting provider stub |
| I9 | No change to the G1 Pedersen profiles, their vectors or `PedersenG1Lib` | — | Byte-identical vectors; unchanged tests |
| I10 | Resource bounds: verification work is a fixed function of `n ≤ 64`; inputs are rejected before work | D4, D5 | M1 tests; M3 measurements |
| I11 | Measurements are records, never security evidence | D8, D9 | — |

## Compatibility

- **Additive.** A new package in `zeroj-bls12381`, a new spec, a new vector file and a registry
  revision (r8) that adds `reserved` entries at M0 and makes them `active` at M6. No existing
  profile, encoding or API changes.
- **Transcript versioning.** Any change to D2, D3 or D4 after admission needs a new protocol
  identifier, and proofs under the old identifier stay verifiable under it.
- **Yano-X.** Using the verifier needs a Yano-X dependency upgrade to an `org.zeroj` release (D9).

## Implementation milestones (after acceptance)

| Milestone | Entry gate | Deliverables | Exit |
|---|---|---|---|
| **M0** spec and independent reference | ADR accepted; Q1–Q7 decided | `docs/specs/bulletproof-range-bls12-381-g1-v1.md`: generators, transcript bytes, encoding, verifier equations, error classes, test seams. Registry r8 adds the entries as `reserved`. A stand-alone Python reference (stdlib only, on the ADR-0060 M0 BLS12-381 reference), written from the paper and the spec without reading Java: prover, verifier and generator derivation, printing intermediate challenges | Java `hashToG1` and Python agree on `D_gens`; Python round-trips its own proofs; review loop reports SPEC READY; **maintainer sign-off** |
| **M1** Java | M0 signed off | Package `org.zeroj.bls12381.bulletproofs`, all D4–D7 rules, unit and negative tests (I2–I8, I10), API surface test, seeded faults (below) | Module suites green; seeded faults killed |
| **M2** vectors and cross-implementation | M1 | `bulletproof-range-bls12-381-g1-v1.json` with fixed-nonce proofs, every intermediate challenge, and negatives. Generator with `--check` and `--self-test`. Java verifies Python proofs and Python verifies Java proofs. A reviewer recomputes the verifier side independently (for example on py_ecc). blst parity | Byte-identical regeneration; both directions pass; independent recomputation matches |
| **M3** performance and determinism | M2 | Benchmark harness (`commitment-profiles-v1` §15 method): prove and verify p50/p95 per `n`, allocation, 1 and 8 threads, pure Java and blst. Uses the #22 MSM if merged, otherwise records the term-by-term cost. Determinism test (repeated runs, both providers) | Measurements recorded; no check removed for speed |
| **M4** Cardano feasibility spike | M2 | JuLC VM probes in test sources for `n` = 16, 32, 64 (generators, transcript recomputation if Q2 = (a), both checks). PV11 CPU, memory and script size. On-chain `hashToGroup` reproduction of the generators | Measurements and a feasible/infeasible verdict per `n` recorded in a benchmark doc; no library published |
| **M5** Yano-X contract | M3 | Verifier contract in the spec (D9). Reference confidential-accounting state machine in `zeroj-integration-tests` test sources with authorization, replay, the D3a rule and limits, plus a negative suite. Handoff note for a Yano-X ADR | Tests green |
| **M6** docs and admission | M1–M5 | Registry r8 makes the entries `active` (experimental) if every prerequisite holds: accepted ADR, spec, I1, M2 vectors with independent recomputation, M3 measurements. The §14 V4 cell is updated. Module README, support matrix, docsite page, ADR implementation-evidence section | Admission recorded; otherwise entries stay `reserved` with the gap stated |

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

- **Independent implementation.** The M0 Python reference is written from the paper and the spec
  only, by an author who does not read the Java, on the independent ADR-0060 M0 curve code. It is
  the vector source.
  - No values are derived from the code under test.
  - Fixed nonces come from a documented test-only expansion, so the vectors are reproducible.
- **Cross-implementation.** Java↔Python proofs in both directions. A reviewer recomputes the
  verifier with separate code (py_ecc), as for ADR-0060.
- **Published vectors.** RFC 9380 J.9.1 and K.1 cover the hash-to-curve layer, and are already in
  the tests. If Q2 = (b), fiat-shamir-03 Appendix B covers the transcript.
  - No published Bulletproof vectors exist for BLS12-381.
  - dalek's Ristretto vectors cannot be reused. A group-generic cross-check against dalek is
    recorded as optional extra scope, not planned.
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
- A second Fiat–Shamir construction enters the codebase, beside the PlonK transcript. Q2 decides
  whether it is ZeroJ-specific or a CFRG draft. Either way it is a long-lived compatibility
  commitment.
- Verification cost depends on MSM support (#22) and on trusted-point handling (#104). Without
  them, a 64-bit verification would spend about 150 × 4.3 ms ≈ 0.65 s on input re-validation alone
  (an estimate from the ADR-0060 measurement). M3 records the real figure.
- On-chain verification is probably limited to narrow widths (D8). On-chain range checks today are
  better served by Jubjub commitments in a Groth16 circuit.

## Risks and production/audit gates

- **Novel composition.** There is no BLS12-381 reference and no standard. If Q2 = (a), the
  transcript is ZeroJ-specific.
  - **External cryptographic review of the spec (generators, transcript, encoding and verifier)
    is required before any value-bearing use.**
  - Q7 asks whether it must also come before admission as `active` (experimental).
- **Weak Fiat–Shamir regressions.** I2 tests and the seeded faults guard the transcript; review of
  any transcript change is mandatory.
- **Side channels in proving.** Proving is offline/isolated only (ADR-0038). There is no
  constant-time claim.
- **Draft drift (Q2 = (b)).** A future fiat-shamir draft can change the bytes. The identifier
  pins `-03`.
- **Performance.** Without #22 and #104, verification may be too slow for per-block use on
  Yano-X. M3 measures before any recommendation is made.
- **Maturity.** Experimental. Test counts, vectors, AI review and on-chain execution are not
  security evidence (AGENTS.md).

## Related findings (out of scope)

- **#22 (provider MSM) and #104 (re-validation of trusted points)** decide verification speed. They
  are shared R3 primitives with their own designs.
- **ADR-0051 D7** (G1 sigma proofs) stays open. If Q2 picks (a), D7's option (b) can reuse that
  construction, but this ADR does not decide D7.
- **Aggregated range proofs and multi-proof batching** are a later version.
- **A Jubjub ↔ G1 bridge** proving two commitments hold the same value (ADR-0051 D8).

## Design questions for the maintainer

| # | Question | Options | Lean |
|---|---|---|---|
| Q1 | Protocol variant | (a) Bulletproofs (ePrint 2017/1066, 2022-04-14), one value per proof; (b) Bulletproofs+ | **(a)**: most independent review and written specification; BP+ saves 112 octets at `n = 64` |
| Q2 | Fiat–Shamir construction (D3) | (a) ZeroJ SHA-256 chain on `expand_message_xmd`, recomputable on Plutus; (b) CFRG fiat-shamir-03 with SHAKE128, standards-track but Java-only; (c) Merlin | **(a)**, with mandatory external review: it keeps L1 possible for narrow widths and is the same lean as ADR-0051 D7. Choose (b) if standards alignment matters more than L1 |
| Q3 | Verifier combination (D5) | (a) two separate checks, deterministic; (b) one MSM with a transcript-derived weight; (c) one MSM with a random weight | **(a)**: deterministic and specified; the cost is one extra MSM intercept |
| Q4 | Yano-X deliverable (D9) | (a) verifier contract plus a reference state machine in ZeroJ test sources, with the plugin in `yano-x` under its own ADR; (b) the Yano-X plugin in this ADR | **(a)**: avoids a ZeroJ → Yano dependency; Yano-X first needs an `org.zeroj` upgrade |
| Q5 | Cardano scope (D8) | (a) JuLC VM spike only; (b) spike plus a DevKit run; (c) publish an on-chain library | **(a)**, with (b) if M4 finds a width that fits |
| Q6 | Widths | (a) `{16, 32, 64}`; (b) add 8 | **(a)**: the issue's set; 8 adds little |
| Q7 | When external review is required | (a) before value-bearing use, with admission as `active` (experimental) allowed after M6; (b) before admission | **(a)**: matches how ADR-0060 admitted its entries as experimental |

## Revision history

- **r1 (2026-10-24):** initial proposal.
