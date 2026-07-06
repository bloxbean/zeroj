# ADR-0027: In-Circuit Real-World Crypto Gadgets — SHA-512, HMAC-SHA512, Blake2b, and Non-Native Ed25519 for BLS12-381

## Status
Proposed

## Date
2026-07-06

## Context

ADR-0015 shipped standards-compatible **Poseidon** over the BLS12-381 scalar field;
ADR-0016 added the embedded **Jubjub** curve (EdDSA, Pedersen). Together they cover
*ZK-friendly* primitives: hashes and a signature curve whose base field **is** BLS12-381's
scalar field. Every ZeroJ usecase to date is built on them — and every one of them abstracts
real-world cryptography as a Poseidon commitment (`Poseidon(secret, …)`) or a Jubjub
signature. `identity-kyc` signs credentials with EdDSA-**Jubjub**; `nft-ownership` models a
wallet key as an opaque field element `secretKey`. None of them reproduces a **real**
cryptographic artifact from an external system.

**The gap.** To prove statements about the cryptography that real wallets, chains, and
identity standards actually use, the circuit must compute the *standard* primitives:

- **Cardano wallet keys** — CIP-1852 / **BIP32-Ed25519** derivation: **HMAC-SHA512** chains,
  **Ed25519** scalar multiplication over edwards25519, and **Blake2b-224** for the payment
  key hash. (See the driving usecase, `zeroj-usecases/account-ownership-recovery/DESIGN.md`.)
- **OIDC / zkLogin** — RS256 JWTs (**SHA-256**), already partially covered by the host-side
  SHA-256 in `Bls12381Hash`, but not in-circuit.
- **Bitcoin / Ethereum ownership** — **SHA-256**, **Keccak-256**, **secp256k1** (a second
  non-native curve, out of scope here but enabled by the same foreign-field layer).

None of SHA-512, HMAC, Blake2b, or Ed25519 exists as an in-circuit gadget today. The
codebase records the gap explicitly: `EdDSAJubjub.java:39` — *"RFC 8032 uses SHA-512 …; this
implementation uses Poseidon so the verify equation avoids a SHA-512-in-a-SNARK."* That
substitution was the right call for issuer-signed credentials, but it does not help when the
signature/derivation we must verify is fixed by an external system we do not control.

### Strategic rationale — real-world scenarios, not toy abstractions

This gadget suite is a deliberate step-change in ZeroJ's positioning: **from "ZK over
ZK-friendly abstractions" to "ZK over real-world cryptographic facts."** A single, reusable
core-library investment unlocks a *family* of high-value use cases that all share these
primitives:

- **Wallet ownership / account recovery** (the SecondFi-class problem) — prove control of a
  Cardano address from a derivation ancestor without revealing the seed.
- **zkLogin / OIDC** — prove "I hold a Google/Apple-signed token for subject X" without
  revealing the token.
- **Cross-chain proof of ownership** — prove control of a BTC/ETH/ADA address in ZK.
- **Proof of solvency / reserves over real signatures**, **KYC over real X.509/JWT
  credentials**, **selective disclosure of government-issued credentials**.

These are the scenarios where ZK carries real economic weight. They are also, not
coincidentally, large circuits — so this ADR treats **prover performance at scale** as a
first-class workstream, not an afterthought.

### Why this is fundamentally harder than ADR-0016 (the honest cost)

ADR-0016's Jubjub scalar-mul costs ~2,500 constraints because Jubjub is an **embedded**
curve: its base field *is* the BLS12-381 scalar field (`r = 0x73eda753…00000001`), so each
curve-arithmetic field op is one native `api.mul`. **Ed25519 is a foreign curve** — its base
field is `2²⁵⁵ − 19 ≠ r`. We cannot choose the curve; the real-world artifact (the address,
the derivation, the signature) dictates it. Emulating `GF(2²⁵⁵−19)` inside a BLS12-381 SNARK
means representing each field element as multiple limbs and doing schoolbook
multiply-with-reduction — **~500× more expensive per scalar-mul (~1.2M vs ~2,500)**.
Similarly, SHA-512/Blake2b are bit-oriented, not field-algebraic like Poseidon.

Concretely (measured against equivalent circom implementations; ZeroJ figures to be
confirmed in M1–M6):

| Primitive | Reference cost | ZeroJ model note |
|-----------|----------------|------------------|
| SHA-512, per 1024-bit block | ~66k–77k R1CS (circom) | **MEASURED in ZeroJ M1: 129,723/block** (correct, JCA-validated). ~77.8k is bitwise (Σ/σ/Ch/Maj XOR/AND, 1 mul/bit; rotates/shifts free), ~25.7k is the 64-bit modular-add carry decompositions, rest overhead. ~1.7× circom — a fused-adder / Xor3 optimization pass (target ~77k) is **deferred pending the M7 proving-scale verdict** (it changes the full circuit from ~10M to ~8M constraints, not the go/no-go). |
| HMAC-SHA512 (≤128B data) | ~4 SHA-512 blocks | wrapper over SHA-512 |
| Blake2b, per 128B block | ~77k R1CS | same free-rotate advantage |
| Ed25519 scalar-mul (foreign field) | ~1.2M R1CS | ZeroJ can implement a **fixed-base windowed** gadget (the derivation case `A = kL·B`), which the reference circom lib **lacks** — a genuine cost-reduction lever. |

### What ZeroJ already provides for gadget authors (verified)

- **CircuitAPI** (`zeroj-circuit-dsl`): `add` (free), `mul` (1 constraint, full ~255-bit
  field multiply — usable directly for schoolbook limb products where each limb ≤ ~127 bits),
  `toBinary(x, nBits)` (bit-decompose + range-check; `MAX_SAFE_BITS = 253`), `xor/and/or/not`,
  `assertInRange`, `isEqual`, `lessThan`, `select`.
- **`Binary` / `SignalBinary`** (`zeroj-circuit-lib`): `bitXor/bitAnd/bitOr` over `Variable[]`,
  and **free** `rotateLeft(bits, n)` / `shiftRight(api, bits, n)`. This is the exact
  XOR/AND/rotate/shift toolkit SHA-512 and Blake2b need.
- **Gadget template**: `InCircuitJubjub` (`record Point`, `final` class, `static` methods
  taking `CircuitAPI` first, double-and-add scalar-mul, fixed- and variable-base) is the
  structural model for the Ed25519 point gadget.
- **Annotation integration**: custom gadgets are callable from an `@ZKCircuit`/`@Prove`
  method via `zk.builder().api()`; expose ergonomic wrappers as `Zk*` adapters in
  `zeroj-circuit-lib/.../lib/zk/` (pattern: `ZkPoseidon`). **No annotation-processor change
  is required.**

### What is missing and must be built

- 64-bit modular-add-with-carry driver; SHA-512 message schedule + round function; padding.
- HMAC ipad/opad framing.
- Blake2b compression (G-function) + `-224`/`-256` output.
- **A non-native / foreign-field arithmetic layer** for `GF(2²⁵⁵−19)` — none exists
  (`grep nonnative|foreignfield|emulated|limb` finds only host-side Montgomery field code,
  never an in-circuit gadget). This is the delicate, audit-critical piece.
- Ed25519 point arithmetic over the emulated field; fixed-/variable-base scalar-mul.
- BIP32-Ed25519 hardened/soft child-derivation composition.
- **A validated large-circuit proving path** — no ZeroJ test has ever *proven* a circuit
  above ~4k constraints (the ~9–10k `InCircuitEdDSAJubjub` is only witness-checked, never run
  through setup/prove). This ADR must close that.

## Decision

Build four gadget families in `zeroj-circuit-lib` at the CircuitAPI level (plus `Zk*`
annotation adapters), **targeting BLS12-381 exclusively**, and stand up a benchmarked
large-circuit proving path.

### 1. SHA-512 gadget (`lib/hash/Sha512`)
- Operate on `Variable[]` 64-bit words. Reuse `Binary.rotateLeft/shiftRight` (free) and
  `Binary.bitXor/bitAnd` for `Σ/σ/Ch/Maj`.
- Build a **64-bit modular-add-with-carry** helper: sum the (free) linear combination, then
  `api.toBinary(sum, 64 + ceil(log2(#addends)))` to split value + carry with a single
  range-decomposition. This is the dominant per-round cost.
- Message schedule (80 words) + 80-round compression + FIPS 180-4 padding (padding computed
  in the witness where lengths are public; length-bits asserted in-circuit).
- Host oracle: JCA `MessageDigest.getInstance("SHA-512")`.

### 2. HMAC-SHA512 gadget (`lib/hash/HmacSha512`)
- Standard `H((K'⊕opad) ‖ H((K'⊕ipad) ‖ m))` framing over the SHA-512 gadget, keys ≤ 128 B
  (one block), as used by BIP32-Ed25519.
- Host oracle: JCA `Mac.getInstance("HmacSHA512")`.
- **PBKDF2 is explicitly out of scope** — Cardano Icarus master-key derivation is
  4096 iterations ≈ 1.26 **billion** constraints, infeasible in any SNARK (see usecase §7.2).
  Circuits anchor at the root/intermediate extended key, never the mnemonic.

### 3. Blake2b gadget (`lib/hash/Blake2b`)
- Blake2b compression with the free-rotate advantage; parameterize output length to support
  **blake2b-224** (Cardano payment/stake key hash) and blake2b-256.
- Host oracle: cardano-client-lib `Blake2bUtil` (already a transitive dep in Cardano-facing
  modules).

### 4. Non-native field layer + Ed25519 gadget (`lib/field/NonNativeField`, `lib/ed25519/`)
- **`NonNativeField`**: a general emulated-field module parameterized by modulus, limb count,
  and limb bit-width. Represent an element as `k` limbs (e.g. 5×51-bit or 3×85-bit — chosen so
  limb products stay `< r`, i.e. ≤ ~127 bits, captured exactly by one `api.mul`). Multiply via
  schoolbook `api.mul` + `api.add`; reduce via a **witnessed quotient** asserted with
  `assertEqual(a·b, q·p + r)` and range-checked with `api.toBinary`. Add/sub with borrow.
  Built to be **reusable for secp256k1** later.
- **`Ed25519Point`** (`record` in extended twisted-Edwards coords over `NonNativeField`),
  following the `InCircuitJubjub` template: `add`, `doubled`, `select`, `conditionalAdd`.
- **Scalar multiplication**: a **fixed-base windowed** gadget for `A = kL·B` (the derivation
  and public-key case — precompute `[2^i]·B` off-circuit; this is the optimization the
  reference circom lib omits), plus a variable-base double-and-add for the general case.
- **BIP32-Ed25519 derivation helpers** (`lib/ed25519/Bip32Ed25519`): hardened step
  (`Z = HMAC-SHA512(cc, 0x00‖kL‖kR‖LE32(i))`, no EC op) and soft step
  (`Z = HMAC-SHA512(cc, 0x02‖A‖LE32(i))`, one fixed-base scalar-mul), with the
  `kL_child = 8·Z_L[0:28] + kL` / `kR_child = Z_R + kR mod 2²⁵⁶` big-int arithmetic.
- Host oracles: RFC 8032 test vectors; cardano-client-lib HD derivation (`HdKeyPair`,
  `DerivationPath`) for BIP32-Ed25519.
- **Optional** full RFC 8032 verify (with the ADR-0016 malleability + subgroup discipline) —
  deferred unless a usecase needs in-circuit Ed25519 *signature* verification.

### 5. Curve: BLS12-381 only — no BN254 path

Per **ADR-0016's established doctrine**: BabyJubJub/BN254 "inside a Cardano-verifiable SNARK
means either (a) proving over BN254 (no Plutus builtin; unverifiable on Cardano) or (b)
emulating…". A BN254 proof is a dead end — it can never be promoted on-chain, and it forks
the pipeline into two circuits, two trusted setups, and two verification keys. All gadgets
here are authored for the BLS12-381 scalar field so that **a single proof verifies both
off-chain (`Groth16BLS12381Verifier`, pure Java) and on-chain (Julc `Groth16BLS12381Verifier`,
Plutus V3)**. This also means the ADR-0016 "port the BN254 circom gadget" risk **does not
apply** here — we author natively for BLS12-381 from the first line.

### 6. Large-circuit proving path (benchmark + optimize)

- Benchmark ZeroJ's Groth16 setup+prover (`Groth16SetupBLS381`, `Groth16ProverBLS381`,
  `FieldFFTBLS381` — `MAX_LOG_DOMAIN = 32`, `PowersOfTauBLS381` power ∈ [4,32]) at
  **2²¹, 2²², 2²³** constraints. Record wall-clock, peak memory, proving-key size.
- The **pure-Java prover is the correctness baseline**; the **`zeroj-blst` native module is
  the performance path** — the setup/prover cost is dominated by `O(numWires)` / `O(domainSize)`
  arrays of curve-point scalar-mults and Pippenger MSMs, which blst accelerates. Decide, from
  the M7 benchmark, whether pure-Java is acceptable or blst-backed MSM/FFT is required before
  the full derivation circuit (M8) is worthwhile.
- Production requires an **MPC trusted-setup ceremony** at the chosen power (ties to ADR-0013,
  ADR-0025); dev uses the flag-gated `generateForTesting` setup.

### 6.1 M7 measured results (pure-Java, BLS12-381, this machine)

Synthetic modular-squaring chain (exactly N constraints); `Groth16SetupBLS381` +
`Groth16ProverBLS381`, no blst. Reproduce with `./gradlew :zeroj-crypto:benchmark`.

| log₂N | constraints | setup (s) | prove (s) | peak heap (MB) |
|------:|------------:|----------:|----------:|---------------:|
| 12 | 4,096 | 14.1 | 2.3 | 635 |
| 14 | 16,384 | 56.4 | 6.7 | 669 |
| 16 | 65,536 | 223.5 | 23.0 | 779 |
| 18 | 262,144 | 894.8 | 68.6 | 1,349 |

Per-constraint at 2¹⁸: setup ≈ 3.4 ms, prove ≈ 262 µs, heap ≈ 5.3 KB. Linear extrapolation
(a **lower bound** — FFT is superlinear):

| target | setup | prove | peak heap |
|-------:|------:|------:|----------:|
| 2²¹ (~2.1M) | ~2.0 h | **~9 min** | ~10.5 GB |
| 2²² (~4.2M) | ~4.0 h | ~18 min | ~21 GB |
| 2²³ (~8.4M) | ~8.0 h | ~37 min | ~42 GB |

**Verdict — GO, with a defined operating envelope:**
1. **Proving is tractable server-side.** ~9 min at 2²¹ (the role-anchor recovery target) is
   fine for a recovery portal; per-proof cost is not the blocker.
2. **Memory is the binding ceiling**, not time. 2²¹ fits a 16 GB box; 2²³ needs ~48 GB+.
   This — not wall-clock — caps how deep an anchor we can prove on commodity hardware.
3. **Setup is a one-time cost.** The ~2 h pure-Java setup at 2²¹ is a dev-loop annoyance, not
   a production cost: production uses a pinned MPC-ceremony `.ptau` (`PtauImporterBLS381`), not
   `Groth16SetupBLS381`. Dev iteration should use the smallest anchor/circuit that exercises
   the logic.
4. **blst MSM wiring is the highest-value optimization**, but is **not on the critical path
   for a role-anchor PoC** — pure-Java already clears it. Prioritize it before the root-anchor
   (2²³) target, alongside the SHA-512 constraint reduction (§7 cost table), since both memory
   and the ~130k/block SHA-512 cost push the derivation circuit toward the 2²²–2²³ band.

Consequence for the usecase: **target the role-anchor (~2²¹–2²²) circuit first**; treat
root-anchor (2²³) as gated on the blst + memory-optimization follow-up.

## Milestones

| # | Scope | Tests / oracles | Est. effort |
|---|-------|-----------------|-------------|
| **M1** | SHA-512 gadget + 64-bit mod-add driver + padding | ✅ **DONE** — `lib/hash/Sha512.java` + `Sha512Test`; JCA-validated across padding boundaries + multi-block on BN254 **and** BLS12-381; `rotr`/`shr` cross-checked vs `Long`; negative test. **Measured 129,723 constraints/block** (correct-first; optimization deferred, see cost table). | 1 wk |
| **M2** | HMAC-SHA512 wrapper | ✅ **DONE** — `lib/hash/HmacSha512.java` + `HmacSha512Test`; JCA-validated across key regimes (short / 32B chain-code / exact-128 / >128-hashed) + empty/multi-block msg + RFC 4231 case 1 fixed vector + negative; BN254 & BLS12-381. **535,685 constraints** at the BIP32 shape. | 3 days |
| **M3** | Blake2b (-224 / -256) | cardano-client-lib `Blake2bUtil`; RFC 7693 vectors | 4 days |
| **M4** | `NonNativeField` foreign-field layer (`GF(2²⁵⁵−19)`) | random-input cross-check vs `BigInteger` mod-p; carry/reduction edge cases; negative (under-constraint) tests | 1.5 wk |
| **M5** | `Ed25519Point` ops + fixed-base scalar-mul `A = kL·B` | RFC 8032 pubkey vectors; cross-check vs host Ed25519 | 1.5 wk |
| **M6** | BIP32-Ed25519 one soft + one hardened derivation step, composed | cardano-client-lib HD derivation vectors; CIP-1852 path | 1 wk |
| **M7** | **Prover-scale benchmark** (2²¹–2²³) + blst-MSM decision | ✅ **DONE** — `Groth16ScaleBenchmark` + `:zeroj-crypto:benchmark` task; measured 2¹²–2¹⁸, extrapolated to targets (see §6.1). **Verdict: GO (server-side, role-anchor).** | 1 wk |
| **M8** | Full CIP-1852 derivation circuit; integrate into `account-ownership-recovery` usecase | end-to-end prove (snark) + verify off-chain **and** on Yaci DevKit | 2 wk |

Each `Zk*` annotation adapter (`ZkSha512`, `ZkHmacSha512`, `ZkBlake2b`, `ZkEd25519`) ships
with its gadget. Four-agent review (ADR conformance + crypto correctness + Java quality +
Codex second opinion) after each milestone, matching the ADR-0015/0016 pattern.

**Acceptance-benchmark form** (per gadget): compiles to ≤ N constraints via
`circuit.compileR1CS(CurveId.BLS12_381).numConstraints()`, **and** its witness matches the
host reference oracle on the published vectors, **and** tampered inputs fail
(`assertThrows` on `calculateWitness`).

## Consequences

### Easier
- **Real-world-crypto usecases become possible**: wallet ownership/recovery, zkLogin/OIDC,
  cross-chain proof-of-ownership, KYC over real credentials — a whole product surface.
- The `NonNativeField` layer is reusable: **secp256k1** (Bitcoin/Ethereum) is a follow-on ADR
  with most of the machinery already built.
- **No on-chain changes**: `Groth16BLS12381Verifier` accepts these proofs unmodified; on-chain
  verification cost is **independent of circuit size** (only public-input count matters).

### Harder
- **Circuit sizes explode** from ~1k–10k to **~2M–7M** constraints. Compile, witness-gen, and
  especially **proving** become heavy (minutes, tens of GB) — proving performance is now a
  primary engineering concern (M7).
- **Audit surface grows sharply.** Foreign-field reduction and SHA/Blake bit-plumbing are the
  two most under-constraint-prone categories of ZK code. Independent audit is mandatory before
  any value depends on these gadgets.
- **Trusted setup at 2²³** requires an MPC ceremony (no public BLS12-381 ptau is readily
  importable to snarkjs; a solo setup is not trustless).

### Neutral
- Additive to Poseidon/Jubjub — no breaking changes to existing gadgets or usecases.
- The lightweight Poseidon-commitment path stays the right tool for *proactive* enrollment
  circuits (usecase §14); these heavy gadgets are for *retroactive* proofs over existing
  artifacts.

## Risks

1. **Prover does not scale in pure Java.** Millions of constraints ⇒ millions of curve-point
   scalar-mults at setup and MSMs at prove time. *Mitigation:* M7 benchmarks **before** M8;
   `zeroj-blst` native MSM/FFT as the performance path; accept server-side (not browser)
   proving. This is the single biggest risk and gates the full circuit.
2. **Non-native field under-constraint.** A missing range-check on a limb or quotient makes
   proofs forgeable. *Mitigation:* cross-check every op against `BigInteger` host arithmetic
   over thousands of random inputs; explicit negative tests; external audit; keep limb
   products < r (≤ ~127-bit limbs) so no silent wraparound.
3. **255-bit field / `MAX_SAFE_BITS = 253` edge cases.** Carries and reductions must respect
   the 253-bit decomposition ceiling. *Mitigation:* size limbs and carry widths conservatively;
   unit-test the boundary.
4. **SHA-512 / Blake2b padding & endianness.** Classic byte-order bugs. *Mitigation:*
   byte-exact vectors from JCA / cardano-client-lib and NIST/RFC.
5. **No trustless BLS12-381 ptau at scale.** *Mitigation:* MPC ceremony (ADR-0013/0025);
   self-gen for dev only, clearly flagged insecure.
6. **Ed25519 signature-verify malleability/subgroup** (only if the optional verify gadget is
   built). *Mitigation:* reuse ADR-0016's strict `S < l` + subgroup discipline.

## Open questions

- **Limb parameterization** for `NonNativeField` (5×51 vs 3×85 vs 4×64) — decide in M4 from a
  constraint-count bake-off; the choice trades multiply cost against reduction cost.
- **Fixed-base window size** for Ed25519 `A = kL·B` — tune in M5 (3-bit vs 4-bit windows).
- **Where padding is enforced** — witness-computed with in-circuit length assertion vs fully
  in-circuit; default to the former where message length is public.

## References

- ADR-0010 — Java Circuit DSL (CircuitAPI, gate model)
- ADR-0012 — Pure-Java Groth16/PlonK provers (prover this ADR must scale)
- ADR-0013 / ADR-0025 — Trusted-setup ceremony tooling / audit readiness
- ADR-0015 — Standards-compatible Poseidon for BLS12-381
- ADR-0016 — Jubjub-in-Circuit (curve doctrine + gadget template this ADR mirrors)
- `zeroj-usecases/account-ownership-recovery/DESIGN.md` — the driving usecase
- FIPS 180-4 (SHA-512), RFC 4231 (HMAC-SHA512 vectors), RFC 7693 (BLAKE2)
- RFC 8032 (Ed25519), BIP32-Ed25519 (Khovratovich–Law), CIP-1852 / CIP-3 (Cardano derivation)
- Electron-Labs ed25519-circom / sha512 — external constraint-count reference
