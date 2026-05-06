package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Off-circuit EdDSA signature scheme over Jubjub, with Poseidon as the
 * challenge hash. Used by {@link InCircuitEdDSAJubjub} as the in-circuit
 * verifier's cryptographic oracle and by application code for issuing /
 * signing / off-chain verification.
 *
 * <h2>Scheme</h2>
 *
 * <h3>Key generation</h3>
 * {@code sk ∈ [1, l); pk = [sk]·G} where G is {@link JubjubPoint#SUBGROUP_GENERATOR}
 * and {@code l = } {@link JubjubCurve#SUBGROUP_ORDER}.
 *
 * <h3>Sign (sk, msg)</h3>
 * <ol>
 *   <li>{@code r = Poseidon(sk, msg) mod l} — deterministic nonce (no RNG).</li>
 *   <li>{@code R = [r]·G}.</li>
 *   <li>{@code k = Poseidon(R.u, R.v, msg) mod l} — challenge.</li>
 *   <li>{@code S = (r + k·sk) mod l}.</li>
 *   <li>Signature = {@code (R, S)}.</li>
 * </ol>
 *
 * <h3>Verify (pk, msg, R, S)</h3>
 * <ol>
 *   <li>Reject if {@code R ∉ subgroup} or {@code pk ∉ subgroup}.</li>
 *   <li>Reject if {@code S ≥ l} (malleability prevention).</li>
 *   <li>{@code k = Poseidon(R.u, R.v, msg) mod l}.</li>
 *   <li>Check {@code [S]·G == R + [k]·pk}.</li>
 * </ol>
 *
 * <h2>Deviation from RFC 8032</h2>
 * RFC 8032 uses SHA-512 for both the nonce derivation and challenge hash,
 * and the public key is the output of a hash-to-curve rather than a plain
 * scalar-mul. This implementation uses Poseidon so the verify equation can
 * be emitted as a small number of constraints inside a BLS12-381 SNARK. The
 * resulting scheme is <b>not interoperable</b> with Ed25519 or
 * Sapling-EdDSA signatures; it is intended for in-SNARK credential
 * verification on Cardano.
 */
public final class EdDSAJubjub {

    private EdDSAJubjub() {}

    /** A keypair: private scalar {@code sk} and public point {@code pk = [sk]·G}. */
    public record Keypair(BigInteger sk, JubjubPoint pk) {
        public Keypair {
            Objects.requireNonNull(sk, "sk");
            Objects.requireNonNull(pk, "pk");
        }
    }

    /**
     * A signature: curve point {@code R} and scalar {@code S}. Both are
     * required to be canonical forms ({@code R} in the prime-order subgroup,
     * {@code S ∈ [0, l)}) for verification to succeed.
     */
    public record Signature(JubjubPoint r, BigInteger s) {
        public Signature {
            Objects.requireNonNull(r, "r");
            Objects.requireNonNull(s, "s");
        }
    }

    /**
     * Derives a keypair from a given secret scalar.
     *
     * @param sk secret key scalar; must satisfy {@code 0 < sk < l}
     */
    public static Keypair keypairFromSecret(BigInteger sk) {
        Objects.requireNonNull(sk, "sk");
        if (sk.signum() <= 0 || sk.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException(
                    "Secret key must satisfy 0 < sk < l (= Jubjub subgroup order)");
        }
        JubjubPoint pk = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sk);
        return new Keypair(sk, pk);
    }

    /**
     * Signs a message digest {@code msg} with secret key {@code sk}.
     *
     * <p>The {@code msg} argument is expected to be a pre-hashed field
     * element (BLS12-381 scalar field). For byte-oriented messages, hash them
     * to a field element via Poseidon or another field-friendly hash
     * before calling.
     */
    public static Signature sign(BigInteger sk, BigInteger msg) {
        Objects.requireNonNull(sk, "sk");
        Objects.requireNonNull(msg, "msg");
        BigInteger l = JubjubCurve.SUBGROUP_ORDER;
        JubjubPoint pk = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sk);
        // r = Poseidon(sk, msg) mod l (deterministic; no secure RNG required).
        // Note: mod-l over a 255-bit Poseidon output has ~2^-3 bias (p/l ≈ 8).
        // For signers that issue many thousands of credentials under one key,
        // this bias enables biased-nonce attacks (Bleichenbacher / HNP). For
        // single-issuer credential systems with bounded signing volume, the
        // bias is practically negligible. If volume grows: widen the hash.
        BigInteger r = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, sk, msg).mod(l);
        JubjubPoint rPoint = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(r);
        // Challenge binds (R, pk, msg) — including pk defends against key-
        // substitution / duplicate-signature attacks (standard Ed25519 / Schnorr).
        BigInteger k = computeChallenge(rPoint, pk, msg);
        // S = (r + k·sk) mod l
        BigInteger s = r.add(k.multiply(sk)).mod(l);
        return new Signature(rPoint, s);
    }

    /**
     * Verifies a signature. Returns {@code false} (does not throw) for
     * malformed or invalid signatures.
     *
     * @param pk  public key (must be in the Jubjub prime-order subgroup)
     * @param msg message field element
     * @param sig signature to verify
     */
    public static boolean verify(JubjubPoint pk, BigInteger msg, Signature sig) {
        Objects.requireNonNull(pk, "pk");
        Objects.requireNonNull(msg, "msg");
        Objects.requireNonNull(sig, "sig");
        BigInteger l = JubjubCurve.SUBGROUP_ORDER;
        // 1. Subgroup checks (malleability / small-subgroup defenses).
        if (!pk.isInSubgroup()) return false;
        if (!sig.r.isInSubgroup()) return false;
        // 2. S ∈ [0, l).
        if (sig.s.signum() < 0 || sig.s.compareTo(l) >= 0) return false;
        // 3. Challenge k = Poseidon(R.u, R.v, pk.u, pk.v, msg) mod l.
        BigInteger k = computeChallenge(sig.r, pk, msg);
        // 4. [S]·G == R + [k]·pk?
        JubjubPoint lhs = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sig.s);
        JubjubPoint rhs = sig.r.add(pk.scalarMul(k));
        return lhs.projectiveEquals(rhs);
    }

    /**
     * Computes the challenge scalar
     * {@code k = Poseidon(R.u, R.v, pk.u, pk.v, msg) mod l}.
     *
     * <p>Including {@code pk} in the challenge is a standard defense against
     * key-substitution attacks (a malicious actor cannot claim a valid
     * signature pair transfers to a different issuer key).
     *
     * <p>Exposed for in-circuit gadgets that need to compute {@code k} the
     * same way sign/verify do.
     */
    public static BigInteger computeChallenge(JubjubPoint r, JubjubPoint pk, BigInteger msg) {
        return PoseidonHash.hashN(PoseidonParamsBLS12_381T3.INSTANCE,
                r.affineU(), r.affineV(), pk.affineU(), pk.affineV(), msg)
                .mod(JubjubCurve.SUBGROUP_ORDER);
    }
}
