package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Off-circuit Pedersen commitment over Jubjub:
 * {@code C(v, r) = [v]·G + [r]·H}
 *
 * <p>G is {@link JubjubPoint#SUBGROUP_GENERATOR}. H is the first Jubjub
 * subgroup point derived deterministically from a domain-separated Poseidon
 * hash (see {@link #H} below). Because H is produced by a random oracle
 * output with no known discrete-log relation to G, Pedersen commitments
 * using (G, H) are <b>binding</b>. Hiding comes from the uniformly random
 * blinding scalar {@code r}.
 *
 * <h2>Domain separation</h2>
 * H is derived from the UTF-8 byte string {@code "zeroj.pedersen.v1.H"}
 * hashed via Poseidon over BLS12-381 (ADR-0015 preset). The derivation is
 * try-and-increment: hash the domain tag, reduce to a field element, check
 * whether that value is a valid v-coordinate on Jubjub; if not, increment
 * a counter and rehash. The first successful hit is taken, cofactor-cleared,
 * and cached.
 *
 * <h2>Caveats</h2>
 * <ul>
 *   <li>This implementation is deterministic — any two correct runs produce
 *       the same H.</li>
 *   <li>The domain tag {@code "zeroj.pedersen.v1.H"} is a protocol version.
 *       Changing it invalidates all commitments produced under the previous
 *       H; treat as a breaking change.</li>
 *   <li>H has <b>no known discrete log</b> w.r.t. G. If a future
 *       implementation hard-codes {@code H = [h]·G} for known h, binding is
 *       broken. The derivation recipe above avoids this trap by construction.</li>
 * </ul>
 */
public final class PedersenCommitment {

    private PedersenCommitment() {}

    /** Domain tag for the second base derivation. Must not change. */
    public static final String H_DOMAIN_TAG = "zeroj.pedersen.v1.H";

    /**
     * Second Pedersen base, derived from {@link #H_DOMAIN_TAG} via a
     * deterministic Poseidon-based try-and-increment. The discrete log of
     * H w.r.t. {@link JubjubPoint#SUBGROUP_GENERATOR} is unknown.
     */
    public static final JubjubPoint H = deriveSecondBase();

    /**
     * Commits to {@code v} with blinding {@code r}:
     * {@code C(v, r) = [v]·G + [r]·H}.
     *
     * @param value    committed value (typically small; must be reducible
     *                 mod {@link JubjubCurve#SUBGROUP_ORDER})
     * @param blinding uniformly random blinding scalar (required for hiding)
     * @return a Jubjub point representing the commitment
     */
    public static JubjubPoint commit(BigInteger value, BigInteger blinding) {
        JubjubPoint vG = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(value);
        JubjubPoint rH = H.scalarMul(blinding);
        return vG.add(rH);
    }

    /**
     * Verifies an opening: returns {@code true} iff {@code C == [v]·G + [r]·H}.
     */
    public static boolean verify(JubjubPoint commitment, BigInteger value, BigInteger blinding) {
        return commit(value, blinding).projectiveEquals(commitment);
    }

    private static JubjubPoint deriveSecondBase() {
        BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
        // Hash the domain tag bytes into the field via Poseidon.
        byte[] domainBytes = H_DOMAIN_TAG.getBytes(StandardCharsets.UTF_8);
        BigInteger a = new BigInteger(1, domainBytes).mod(p);
        for (int counter = 0; counter < 1_000_000; counter++) {
            BigInteger b = BigInteger.valueOf(counter);
            BigInteger seed = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
            BigInteger vCandidate = seed.mod(p);
            // Try to solve -u^2 + v^2 = 1 + d·u^2·v^2 for u.
            // u^2 = (v^2 - 1) / (d·v^2 + 1).
            BigInteger vv = vCandidate.multiply(vCandidate).mod(p);
            BigInteger num = vv.subtract(BigInteger.ONE).mod(p);
            BigInteger den = JubjubCurve.D.multiply(vv).add(BigInteger.ONE).mod(p);
            if (den.signum() == 0) continue;
            BigInteger uSquared = num.multiply(den.modInverse(p)).mod(p);
            BigInteger u = modSqrtOrNull(uSquared, p);
            if (u == null) continue;
            // Deterministic sign choice: take the lexicographically-smaller root.
            BigInteger altU = p.subtract(u);
            if (altU.compareTo(u) < 0) u = altU;
            // Cofactor-clear to ensure H is in the prime-order subgroup.
            JubjubPoint candidate = JubjubPoint.fromAffine(u, vCandidate).mulByCofactor();
            if (candidate.isIdentity()) continue; // extremely unlikely, but safe
            return candidate;
        }
        throw new IllegalStateException(
                "PedersenCommitment second-base derivation did not converge after 1M tries — "
                        + "this should be cryptographically impossible; check Poseidon/Jubjub wiring");
    }

    private static BigInteger modSqrtOrNull(BigInteger a, BigInteger p) {
        if (a.signum() == 0) return BigInteger.ZERO;
        // Euler criterion: a is a QR iff a^((p-1)/2) == 1.
        BigInteger exp = p.subtract(BigInteger.ONE).shiftRight(1);
        if (!a.modPow(exp, p).equals(BigInteger.ONE)) return null;
        // Tonelli-Shanks
        BigInteger s = p.subtract(BigInteger.ONE);
        int e = 0;
        while (!s.testBit(0)) { s = s.shiftRight(1); e++; }
        BigInteger n = BigInteger.TWO;
        while (!n.modPow(exp, p).equals(p.subtract(BigInteger.ONE))) {
            n = n.add(BigInteger.ONE);
        }
        BigInteger x = a.modPow(s.add(BigInteger.ONE).shiftRight(1), p);
        BigInteger b = a.modPow(s, p);
        BigInteger g = n.modPow(s, p);
        int r = e;
        while (true) {
            BigInteger tmp = b;
            int m = 0;
            while (!tmp.equals(BigInteger.ONE)) {
                tmp = tmp.multiply(tmp).mod(p);
                m++;
                if (m == r) return null;
            }
            if (m == 0) return x;
            BigInteger gs = g.modPow(BigInteger.TWO.pow(r - m - 1), p);
            g = gs.multiply(gs).mod(p);
            x = x.multiply(gs).mod(p);
            b = b.multiply(g).mod(p);
            r = m;
        }
    }
}
