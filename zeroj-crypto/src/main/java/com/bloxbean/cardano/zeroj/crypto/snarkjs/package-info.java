/**
 * snarkjs-compatible JSON export of ZeroJ BLS12-381 Groth16 and PlonK artifacts (ADR-0047).
 *
 * <p>The classes here consume proofs and keys; none of them produces a proof, so they are outside
 * the ADR-0046 proof-producer allowlist by construction. Parsing of snarkjs JSON lives in
 * {@code zeroj-codec} ({@code SnarkjsJsonCodec}, {@code SnarkjsPlonkCodec}); this package is the
 * inverse direction and deliberately has no dependency on that module.</p>
 */
package com.bloxbean.cardano.zeroj.crypto.snarkjs;
