package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;

/**
 * Jubjub curve constants — twisted Edwards elliptic curve embedded in the
 * BLS12-381 scalar field. Pinned to the Zcash / zkcrypto Jubjub parameters
 * (see <a href="https://github.com/zkcrypto/jubjub">zkcrypto/jubjub</a>).
 *
 * <h2>Naming convention</h2>
 * <ul>
 *   <li>{@code Fq} — Jubjub base field (where point coordinates live) =
 *       BLS12-381 scalar field (prime {@link #BASE_FIELD_PRIME}).</li>
 *   <li>{@code Fr} — Jubjub scalar field (where scalar multipliers live) =
 *       prime-order subgroup modulus {@link #SUBGROUP_ORDER}.</li>
 * </ul>
 *
 * <h2>Curve equation</h2>
 * Twisted Edwards form: {@code -u² + v² = 1 + d·u²·v²}, with {@code a = -1}.
 * Both {@code a = -1} (which is a square in {@code Fq}) and {@code d}
 * (which is a non-square) are chosen so the unified addition formula
 * (Hisil-Wong-Carter-Dawson 2008) is complete — no exceptional inputs.
 *
 * <h2>Full group vs prime-order subgroup</h2>
 * The full Jubjub curve has order {@code 8 · l}. For cryptographic use
 * (signatures, commitments, ZK circuits), points must live in the
 * prime-order subgroup of order {@code l}. A point is in the subgroup iff
 * {@code [l] · P == 0}. {@link #SUBGROUP_GENERATOR} is a fixed generator
 * of that subgroup; it equals {@code [8] · FULL_GENERATOR}.
 */
public final class JubjubCurve {

    private JubjubCurve() {}

    /**
     * Jubjub base field prime = BLS12-381 scalar field prime.
     * {@code 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001}
     */
    public static final BigInteger BASE_FIELD_PRIME = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /**
     * Jubjub {@code a} parameter: {@code -1} (mod {@link #BASE_FIELD_PRIME}).
     */
    public static final BigInteger A = BASE_FIELD_PRIME.subtract(BigInteger.ONE);

    /**
     * Jubjub {@code d} parameter (Zcash/zkcrypto canonical value).
     * {@code 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1}
     */
    public static final BigInteger D = new BigInteger(
            "2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1", 16);

    /** {@code 2 · d} — pre-computed because the unified Edwards formula uses it. */
    public static final BigInteger TWO_D = D.shiftLeft(1).mod(BASE_FIELD_PRIME);

    /**
     * Prime order of the Jubjub subgroup (= Jubjub {@code Fr} modulus,
     * 252 bits). Matches zkcrypto/jubjub {@code FR_MODULUS_BYTES} byte
     * for byte.
     * {@code 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7}
     */
    public static final BigInteger SUBGROUP_ORDER = new BigInteger(
            "0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7", 16);

    /** Cofactor: {@code |E(Fq)| = 8 · SUBGROUP_ORDER}. */
    public static final int COFACTOR = 8;

    /**
     * {@code FULL_GENERATOR} — a generator of the full curve group (order
     * {@code 8 · l}). Not safe for cryptographic use without first
     * cofactor-clearing (i.e. multiply by 8). Exposed for
     * {@link #SUBGROUP_GENERATOR} derivation and for interop with zkcrypto
     * test vectors.
     */
    public static final BigInteger FULL_GENERATOR_U = new BigInteger(
            "62edcbb8bf3787c88b0f03ddd60a8187caf55d1b29bf81afe4b3d35df1a7adfe", 16);

    /** {@code FULL_GENERATOR}'s v-coordinate ({@code 11}). */
    public static final BigInteger FULL_GENERATOR_V = BigInteger.valueOf(11);

    // The subgroup generator itself (as a JubjubPoint) lives on JubjubPoint to
    // avoid a class-init ordering issue (computing [8] · FULL_GENERATOR needs
    // JubjubPoint's methods). Access via {@link JubjubPoint#SUBGROUP_GENERATOR}.

    /**
     * Compressed-point encoding length: 32 bytes (256 bits).
     * Layout: little-endian {@code v}-coordinate in the low 255 bits;
     * top bit encodes the sign of {@code u} (1 iff {@code u} is odd when
     * represented as the least non-negative residue).
     */
    public static final int COMPRESSED_POINT_BYTES = 32;
}
