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
 *   <li><b>Commitment generation is not constant-time — generate offline or in an isolated
 *       process.</b> See the section below; this is a restriction on execution, not on the
 *       scheme.</li>
 * </ul>
 *
 * <h2>Side-channel restriction on generation (ADR-0038)</h2>
 * {@link #commit(BigInteger, BigInteger)} runs both secret scalars through a fixed
 * 316-iteration, multiple-of-l-blinded schedule. The historical loop-bound, zero early-return,
 * Hamming-weight operation-count and raw trailing-zero/identity-duration channels are therefore
 * removed or blinded at the call site.
 *
 * <p>This is still <b>not constant-time</b>. The blinding reduction, secret branch and all
 * coordinate arithmetic use variable-time {@link BigInteger}; JVM/JIT/GC behaviour is outside
 * the implementation's control. Generation must remain offline or inside a reviewed isolated
 * boundary that performs the complete operation.
 *
 * <p><b>Hiding and binding of the commitment itself are unaffected.</b> Perfect hiding is an
 * information-theoretic property of the commitment string; a timing channel during generation
 * sits outside that model and does not weaken it. Nor does this expose the Schnorr/Hidden
 * Number Problem relation that makes the analogous leak in {@link EdDSAJubjub#sign} a
 * key-recovery concern — there is no published practical value-recovery attack here.
 *
 * <p>The in-circuit gadgets ({@code InCircuitPedersen}, {@code ZkPedersen}) are unaffected:
 * they emit constraints and perform no secret-dependent host arithmetic.
 *
 * <p><b>Do not expose secret-bearing commitment generation to an untrusted timing observer or a
 * co-resident adversary.</b> {@link #verify(JubjubPoint, BigInteger, BigInteger)} is different:
 * an opening supplied for verification is public to that verifier, so it deliberately uses the
 * faster variable-length public-scalar path.
 *
 * @see <a href="../../../../../../../../../docs/adr/0038-jubjub-dsl-remediation-plan.md">ADR-0038</a>
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
     * <p><b>Binding is to the residue {@code value mod l}, not to the integer.</b> {@code G}
     * has order {@code l}, so {@code [v]·G} depends only on {@code v mod l} and
     * {@code commit(v, r)} equals {@code commit(v + l, r)}. Both inputs are canonicalised here
     * for that reason. An application that needs commitments to distinguish integers beyond
     * that range must range-bound them itself.
     *
     * <p><b>Hiding requires a uniformly random blinding scalar</b> drawn from {@code [0, l)}.
     * A predictable, reused, or low-entropy {@code r} forfeits it.
     *
     * <p><b>Best-effort, not constant-time.</b> Both legs use a freshly multiple-of-l-blinded
     * scalar and a fixed 316-iteration add/double schedule. Residual channels remain: the
     * {@code mod} reductions, branch selection and all {@link BigInteger} arithmetic are
     * variable-time. Generate offline or in an isolated process. The commitment's hiding and
     * binding are unaffected either way — the restriction is on execution.
     *
     * @param value    committed value (typically small; bound as {@code value mod l})
     * @param blinding uniformly random blinding scalar (required for hiding)
     * @return a Jubjub point representing the commitment
     */
    public static JubjubPoint commit(BigInteger value, BigInteger blinding) {
        BigInteger[] scalars = canonicalScalars(value, blinding);
        BigInteger v = scalars[0];
        BigInteger r = scalars[1];
        JubjubPoint vG = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(v);
        JubjubPoint rH = H.scalarMulSecretBlindedBestEffort(r);
        return vG.add(rH).normalized();
    }

    /**
     * Verifies an opening: returns {@code true} iff {@code C == [v]·G + [r]·H}.
     *
     * <p>The opening is disclosed to the verifier, so this uses the faster public-scalar path.
     * It shares canonicalisation with {@link #commit(BigInteger, BigInteger)}, preserving the
     * exact residue-mod-l semantics without paying the secret-scalar schedule.
     */
    public static boolean verify(JubjubPoint commitment, BigInteger value, BigInteger blinding) {
        return commitPublic(value, blinding).projectiveEquals(commitment);
    }

    private static JubjubPoint commitPublic(BigInteger value, BigInteger blinding) {
        BigInteger[] scalars = canonicalScalars(value, blinding);
        return JubjubPoint.SUBGROUP_GENERATOR.scalarMul(scalars[0])
                .add(H.scalarMul(scalars[1]));
    }

    private static BigInteger[] canonicalScalars(BigInteger value, BigInteger blinding) {
        java.util.Objects.requireNonNull(value, "value");
        java.util.Objects.requireNonNull(blinding, "blinding");
        // Binding is to residues mod l. Canonicalisation also establishes the range required by
        // the fixed secret schedule used by commit().
        return new BigInteger[]{
                value.mod(JubjubCurve.SUBGROUP_ORDER),
                blinding.mod(JubjubCurve.SUBGROUP_ORDER)
        };
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
