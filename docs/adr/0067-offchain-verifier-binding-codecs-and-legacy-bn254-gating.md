# ADR-0067: Off-Chain Verifier Envelope Binding, Canonical Codecs, and Legacy BN254 Gating

## Status

Proposed

## Date

2026-11-21

## Risk Classification

**R2** — Security-sensitive validation, serialization/deserialization trust boundaries, cross-backend verifier consistency, and legacy curve isolation.

## Context

Four off-chain trust-boundary gaps existed across ZeroJ's verification orchestration, backend verifiers, envelope codecs, and legacy BN254 surface:

1. **Divergent envelope-to-material binding across off-chain backends:** `PlonkBLS12381Verifier` validated that `envelope.proofSystem()`, `envelope.curve()`, `envelope.circuitId()`, `material.vkHash()`, and `envelope.vkRef()` (`ByHash`) matched `VerificationMaterial` before verifying cryptography, returning `VK_MISMATCH` on any mismatch. However, `VerifierOrchestrator`, `Groth16BLS12381Verifier`, `Groth16BLS12381PureJavaVerifier`, and `BbsZkVerifier` did not enforce these checks. An attacker could supply a valid proof for `circuit-a` inside an envelope claiming `circuit-b` (or referencing a different `ByHash` VK digest) and receive `proofValid = true` from `VerifierOrchestrator` or the Groth16/BBS verifiers. In addition:
   - `InMemoryVerificationKeyRegistry.register` indexed `material.vkHash()` without checking that it equaled `SHA-256(material.vkBytes())`.
   - `VerifierRegistry` stored backends in an unsynchronized `ArrayList`.
   - Groth16 verifiers decoded proof/VK bytes with the platform default charset instead of UTF-8, did not check parsed JSON `protocol`/`curve`, and mapped `CodecException` to `INTERNAL_ERROR` instead of `MALFORMED_ENVELOPE`.
   - `BbsZkVerifier` mapped malformed CBOR/public-key `BbsException` failures to `INTERNAL_ERROR` instead of `MALFORMED_ENVELOPE`.
2. **Broken `SnarkjsJsonCodec.toEnvelope` serialization & unchecked PlonK VK JSON:** `SnarkjsJsonCodec.toEnvelope(SnarkjsProof, SnarkjsVerificationKey, ...)` serialized Java record field names (`piA`, `vkAlpha1`, numeric JSON numbers) rather than snarkjs JSON (`pi_a`, `vk_alpha_1`, canonical decimal strings), producing envelopes that failed `SnarkjsJsonCodec.parseProof` and computed `vkRef` hashes over non-snarkjs JSON. Meanwhile `SnarkjsPlonkCodec.toEnvelopeFromJson` never parsed or cross-checked `vkJson` (`protocol`, `curve`, `nPublic`).
3. **Lossy and non-canonical `CborEnvelopeCodec`:** `CborEnvelopeCodec` documented optional keys `8` (`domainTag`), `9` (`metadata`), and `10` (`proofFormat`) but dropped them on encode/decode — stripping `proofFormat` needed by format-sensitive verifiers (e.g., Cardano PlonK profiles and BBS). On decode it used default `CborDecoder.decode(cbor)` without duplicate-key rejection, preallocation bounds, unknown-key rejection, version bounds, minimal `BigInteger` checks, or canonical re-encoding verification.
4. **Incomplete legacy BN254 gating:** `ZkeyImporter.importWtns` lacked both `LegacyCurvePolicy.requireLegacyBn254Enabled()` and binary framing/prime/bounds validation. Legacy BN254 verifiers (`Groth16BN254Verifier`, `PlonkBN254Verifier`) also returned `isAvailable() == true` even when BN254 was disabled, and `LegacyCurvePolicy` did not explicitly warn that legacy BN254 verifiers are unsound against adversarial input.

## Threat Model & Trust Assumptions

- **Untrusted inputs:** `ZkProofEnvelope` (including `version`, `proofSystem`, `curve`, `circuitId`, `proofBytes`, `publicInputs`, `vkRef`, `proofFormat`, `domainTag`, `metadata`), CBOR envelope bytes, snarkjs proof/VK/public JSON strings, and `.wtns` streams.
- **Trusted boundary:** `VerificationMaterial` registered in a trusted `VerificationKeyRegistry` (or passed directly by the caller after binding it to the intended statement/circuit) represents the expected statement and verification key bytes.
- **Threats addressed:**
  - Cross-circuit or cross-VK substitution via mismatched `circuitId`, `proofSystem`, `curve`, `ByHash` VK digest, or spoofed `material.vkHash()`.
  - Silent cross-backend divergence where PlonK rejects a substituted envelope while Groth16 or BBS accepts it.
  - CBOR malleability, duplicate-key smuggling, unknown-key injection, preallocation DoS, and silent stripping of `proofFormat`/`domainTag`/`metadata` on round-trip.
  - Accidental exposure or unbounded parsing of legacy BN254 `.wtns` files or BN254 verifiers via `ServiceLoader` or `VerifierRegistry`.
- **Non-goals:** Cryptographic proof validity still does not confer application authorization, replay protection, or `ScriptContext` binding.

## Normative References

- **RFC 8949 §4.2** — Deterministic Encoding for CBOR (shortest-form integers, definite lengths, no duplicate keys, canonical map key ordering).
- **snarkjs 0.7.6** — Groth16 and PlonK JSON proof / verification key / public input schemas (`pi_a`, `pi_b`, `pi_c`, `vk_alpha_1`, `vk_beta_2`, `vk_gamma_2`, `vk_delta_2`, `vk_alphabeta_12`, `IC`, decimal strings) and binary `.wtns` section format (`magic = "wtns"`, section 1 header + section 2 witness).
- **CFRG BBS draft-10 (`draft-irtf-cfrg-bbs-signatures-10`)** — ZeroJ's `BbsPresentationCodec` strict canonical CBOR model and dual-suite (`SHA-256` / `SHAKE-256`) `BbsZkVerifier` adapter.
- **ADR-0044** — Module surface isolation (`zeroj-backend-spi`, opt-in backends, no BN254 in default `ServiceLoader` surface).
- **ADR-0062** — BLS12-381 Groth16 pure-Java / `blst` verifier parity and canonical point encoding (`z = 1`).

## Security Invariants

1. **I1 — Uniform envelope/material binding:** `VerifierOrchestrator.verify(envelope, material)` AND each BLS12-381 verifier (`Groth16BLS12381Verifier`, `Groth16BLS12381PureJavaVerifier`, `PlonkBLS12381Verifier`, `BbsZkVerifier`) enforce:
   - `envelope != null` (else `MALFORMED_ENVELOPE`), `material != null` (else `VK_MISMATCH`);
   - `1 <= envelope.version() <= ZkProofEnvelope.currentVersion()` (else `MALFORMED_ENVELOPE`);
   - `material.proofSystemId() == envelope.proofSystem()`, `material.curveId() == envelope.curve()`, and `material.circuitId().equals(envelope.circuitId())` (else `VK_MISMATCH`);
   - `actualVkHash = SHA-256(material.vkBytes())`: if `material.vkHash()` is present it must equal `actualVkHash`, and if `envelope.vkRef()` is `ByHash` it must equal `actualVkHash` (else `VK_MISMATCH`).
   - Binding MUST NOT assume Groth16 JSON structure for `material.vkBytes()` (BBS uses raw 96-byte G2 public keys) and MUST NOT reject empty `publicInputs` (valid for BBS and 0-public-input circuits).
2. **I2 — Registry integrity & thread safety:** `InMemoryVerificationKeyRegistry.register(material)` rejects any `material` whose declared `vkHash` disagrees with `SHA-256(material.vkBytes())`. `VerifierRegistry` uses thread-safe `CopyOnWriteArrayList` storage and returns an immutable snapshot from `all()`.
3. **I3 — Backend metadata validation & error classification:** Both BLS12-381 Groth16 verifiers decode JSON explicitly as UTF-8, validate optional `proofFormat` (`"snarkjs-json"` if present), validate parsed JSON `protocol == "groth16"`, `curve == "bls12-381"`, and `IC.size() == nPublic + 1`, and map `CodecException` to `MALFORMED_ENVELOPE` (preserving pure-Java / `blst` `ReasonCode` parity). `BbsZkVerifier` maps malformed CBOR/key `BbsException` errors to `MALFORMED_ENVELOPE` rather than `INTERNAL_ERROR`.
4. **I4 — Verifiable snarkjs JSON round-trip:** `SnarkjsJsonCodec.serializeProofToBytes` and `serializeVkToBytes` (exposed via `toVerificationKeyBytes`) emit canonical snarkjs JSON (`pi_a`, `pi_b`, `pi_c`, `vk_alpha_1`, ..., `IC`, canonical decimal strings) that round-trips through `parseProof` / `parseVerificationKey` and verifies against BLS12-381 Groth16 verifiers. `SnarkjsPlonkCodec.toEnvelopeFromJson` parses and cross-checks `vkJson` (`protocol == "plonk"`, `vk.curve() == proof.curve()`, `vk.nPublic() == inputs.size()`).
5. **I5 — Strict canonical CBOR envelope wire format (v1):** `CborEnvelopeCodec` carries required keys `1..7` and optional keys `8` (`domainTag`, omitted when empty), `9` (`metadata`, omitted when empty, keys sorted in RFC 8949 canonical byte-length-then-unsigned-lexicographical UTF-8 order), and `10` (`proofFormat`, omitted when absent). Envelopes with none of keys `8..10` populated emit the exact existing 7-key v1 bytes. Decoding enforces:
   - `MAX_CBOR_BYTES` bound, `setRejectDuplicateKeys(true)`, `setMaxPreallocationSize(MAX_CBOR_BYTES)`;
   - single definite-length CBOR map with keys restricted to `{1..10}`;
   - `1 <= version <= ZkProofEnvelope.currentVersion()`;
   - minimal non-negative `BigInteger.toByteArray()` encodings in `publicInputs`;
   - strict omission of empty optional keys (`domainTag == ""`, `metadata == {}`, blank `proofFormat`);
   - byte-for-byte canonical round-trip equality (`Arrays.equals(cbor, encode(decoded))`).
   Local non-wire fields (`proofUri`, `proofHash`, `createdAt`, `producerId`) are explicitly documented as not serialized in CBOR.
6. **I6 — Legacy BN254 fail-closed isolation:** `ZkeyImporter.importWtns` enforces `LegacyCurvePolicy.requireLegacyBn254Enabled()` plus bounded section framing, exact BN254 scalar prime `FR`, and canonical scalar range `< FR`. `Groth16BN254Verifier` and `PlonkBN254Verifier` report `isAvailable() == LegacyCurvePolicy.legacyBn254Enabled()`, carry explicit Javadoc/policy warnings that they are unsound against adversarial input, and remain absent from all `META-INF/services/org.zeroj.backend.spi.ZkVerifier` files.

## Decision & Alternatives Considered

- **Shared `EnvelopeBinding` helper in `zeroj-backend-spi`:** Placing the shared binding logic in `org.zeroj.backend.spi.EnvelopeBinding` avoids duplicating hash/binding checks across `VerifierOrchestrator`, Groth16, PlonK, and BBS while keeping `zeroj-backend-spi` free of `zeroj-codec` dependencies.
  - *Alternative rejected:* Wiring `EnvelopeValidator` centrally. `EnvelopeValidator` currently rejects empty `publicInputs`, which would break BBS presentations and 0-public-input circuits.
- **Keep CBOR envelope version = 1 with optional keys 8–10:** Existing 7-key envelopes (where `domainTag` is empty, `metadata` is empty, and `proofFormat` is absent) remain 100% byte-compatible with v1, while envelopes carrying `domainTag`/`metadata`/`proofFormat` now round-trip losslessly using the exact key numbers already documented in `CborEnvelopeCodec`.
  - *Alternative rejected:* Bumping to version 2 or stripping keys 8–10 from Javadoc. Bumping version unnecessarily breaks existing v1 7-key fixtures, while dropping `proofFormat` breaks Cardano PlonK and BBS envelope round-trips.
- **Fix `SnarkjsJsonCodec.toEnvelope` rather than deleting it:** Emitting true snarkjs JSON fixes the broken API in place while keeping binary/source compatibility for callers; `toVerificationKeyBytes(SnarkjsVerificationKey)` lets callers materialize matching `VerificationMaterial` cleanly, while raw-file callers continue to prefer `toEnvelopeFromJson`.

## Compatibility

- **Breaking for callers passing mismatched envelopes/materials:** Callers that previously constructed Groth16 or BBS envelopes with dummy/mismatched `ByHash(new byte[32])` or mismatched `circuitId` now receive `VK_MISMATCH` instead of `proofValid = true` (matching `PlonkBLS12381Verifier`).
- **Breaking for non-canonical CBOR inputs:** `CborEnvelopeCodec.decode` now rejects non-canonical CBOR (non-minimal ints, indefinite lengths, duplicate/unknown/out-of-order keys, padded `BigInteger` bytes) and `encode` now emits keys `8..10` when populated.
- **Breaking for ungated `ZkeyImporter.importWtns`:** Callers of `ZkeyImporter.importWtns` (BN254) must now opt in via `-Dzeroj.allowLegacyBn254=true` or `ZEROJ_ALLOW_LEGACY_BN254=true`, matching `ZkeyImporter.importZkey`.

## Implementation Milestones

- **M1:** Add `EnvelopeBinding` in `zeroj-backend-spi`; harden `VerifierOrchestrator`, `InMemoryVerificationKeyRegistry`, `VerifierRegistry`, `Groth16BLS12381Verifier`, `Groth16BLS12381PureJavaVerifier`, `PlonkBLS12381Verifier` (reuse `EnvelopeBinding`), and `BbsZkVerifier`.
- **M2:** Fix `SnarkjsJsonCodec.toEnvelope` / `serializeProofToBytes` / `serializeVkToBytes` + `toVerificationKeyBytes` and `SnarkjsPlonkCodec.toEnvelopeFromJson` VK validation.
- **M3:** Implement keys 8–10 and strict canonical CBOR validation in `CborEnvelopeCodec`.
- **M4:** Gate and harden `ZkeyImporter.importWtns`, override `isAvailable()` and add unsoundness warnings on `LegacyCurvePolicy` / `Groth16BN254Verifier` / `PlonkBN254Verifier`, add ServiceLoader isolation tests, and update `www/src/content/docs/guides/verifying/off-chain.md`.

## Verification & Test Strategy

- **Positive + negative binding tests** across `VerifierOrchestrator`, `InMemoryVerificationKeyRegistry`, `Groth16BLS12381Verifier` & `Groth16BLS12381PureJavaVerifier` (with exact blst/pure-Java `ReasonCode` parity), and `BbsZkVerifier` (including `ById`, `ByHash`, dual SHA-256/SHAKE-256 suites, malformed CBOR -> `MALFORMED_ENVELOPE`).
- **Round-trip + verification test** proving `SnarkjsJsonCodec.toEnvelope(...)` produces a proof verifiable by BLS12-381 Groth16 verifiers, plus negative `SnarkjsPlonkCodec.toEnvelopeFromJson` VK mismatch tests.
- **Adversarial CBOR tests** rejecting indefinite lengths, non-minimal ints, duplicate keys, unknown keys, out-of-order keys, padded `BigInteger`, bad versions, and empty optional keys, plus round-trip tests preserving `domainTag`, `metadata`, and `proofFormat`.
- **Legacy BN254 tests** confirming `ZkeyImporter.importWtns` rejects disabled policy, wrong prime, bad framing, and non-canonical witness scalars; confirming `Groth16BN254Verifier` / `PlonkBN254Verifier` report `isAvailable() == false` by default and never appear in `META-INF/services/org.zeroj.backend.spi.ZkVerifier`.

## Remaining Production & Audit Gates

- Independent external cryptographic review of all verifier backends, codecs, and on-chain/off-chain integration boundaries remains required prior to production or value-bearing promotion.
- Application-level authorization, replay protection, nullifier tracking, and `ScriptContext` binding remain the application's responsibility outside the generic verifier SPI.
