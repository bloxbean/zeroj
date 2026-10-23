package org.zeroj.onchain.julc.pedersen.lib;

import org.julclang.core.types.JulcG1;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;
import org.zeroj.onchain.julc.bbs.lib.BbsHashToScalar;

import java.math.BigInteger;

/**
 * On-chain verification of the BLS12-381 G1 Pedersen profiles {@code pedersen-bls12-381-g1-v1} and
 * {@code pedersen-bls12-381-g1-bytes-v1} with the CIP-0381 builtins
 * ({@code docs/specs/pedersen-bls12-381-g1-v1.md} §9, ADR-0060 D9). Experimental.
 *
 * <p>The library's own guards run before every builtin that could misbehave on an input the CIPs
 * leave unspecified:
 * <ul>
 *   <li>{@link #decodeCommitment} checks the 48-octet length before {@code bls12_381_G1_uncompress},
 *       and {@code compress(point) == bytes} after it, so only the canonical encoding of a point is
 *       accepted. Curve and subgroup validity come from CIP-0381's element contract ("can only be
 *       generated with byte arrays that represent a point which is part of the prime order
 *       subgroup"): {@code uncompress} fails the script otherwise. The identity {@code 0xC0 ‖ 0^47}
 *       is accepted, as off-chain.</li>
 *   <li>Every scalar passed to {@code bls12_381_G1_scalarMul} has passed check 1 ({@code [0, q)}) or
 *       the delta rule; a negative or out-of-range integer never reaches it.</li>
 * </ul>
 * Every failed check fails the script ({@code error}); an opening that is well formed but does not
 * match returns {@code false}.
 *
 * <p>Every commitment argument must come from {@link #decodeCommitment} or from this library's own
 * arithmetic; only {@code decodeCommitment} enforces the canonical encoding of a received point.
 *
 * <p><b>The profile comes from the validator's configuration.</b> A decoded point does not say
 * which profile it was issued under. {@link #verifyScalarOpening}, {@link #verifyScalarOpeningBounded},
 * {@link #applyPublicDelta}, {@link #add}, {@link #subtract} and {@link #negate} are for
 * {@code pedersen-bls12-381-g1-v1} commitments only; the bytes profile has no arithmetic, and a
 * scalar opening {@code (s, r)} of a byte commitment authenticates only {@code s}, never a payload
 * (spec §3.2, §6.4). {@link #verifyBytesOpening} is for {@code pedersen-bls12-381-g1-bytes-v1}.
 *
 * <p>The bases are the pinned compressed constants of spec §2.2 ({@link #baseGEncoding},
 * {@link #baseHEncoding}), decompressed in the script only by the operations that use them.
 * {@code bls12_381_G1_hashToGroup} reproduces them in the tests only.
 *
 * <p><b>What this library does not provide:</b> authorization, replay protection, UTxO and
 * context binding, or non-negative balances (results are residues mod {@code q}). An opened value
 * is public forever. Validators must add these themselves.
 */
@OnchainLibrary
public final class PedersenG1Lib {

    private PedersenG1Lib() {}

    /**
     * Strictly decodes a received commitment (spec §9 steps 1–3): exactly 48 octets, then
     * {@code uncompress} (curve and subgroup validity by the CIP-0381 contract), then canonical
     * re-encoding. Any violation fails the script.
     */
    public static JulcG1 decodeCommitment(byte[] encoded) {
        if (Builtins.lengthOfByteString(encoded) != 48L) {
            Builtins.error();
        }
        JulcG1 point = Builtins.bls12_381_G1_uncompress(encoded);
        if (!Builtins.equalsByteString(Builtins.bls12_381_G1_compress(point), encoded)) {
            Builtins.error();
        }
        return point;
    }

    /** The 48-octet canonical encoding of {@code point}. */
    public static byte[] encodeCommitment(JulcG1 point) {
        return Builtins.bls12_381_G1_compress(point);
    }

    /**
     * Disclosed scalar opening (V1): {@code true} iff {@code commitment == [m]·G + [r]·H}. Check 1 on
     * {@code m}, then {@code r}, fails the script before any multiplication.
     */
    public static boolean verifyScalarOpening(JulcG1 commitment, BigInteger m, BigInteger r) {
        if (!canonical(m) || !canonical(r)) {
            Builtins.error();
        }
        return Builtins.bls12_381_G1_equal(commit(m, r), commitment);
    }

    /**
     * {@link #verifyScalarOpening} with check 2: {@code amountBits ∈ [1, 254]} and
     * {@code m < 2^amountBits}, both checked (after check 1) before any multiplication.
     */
    public static boolean verifyScalarOpeningBounded(JulcG1 commitment, BigInteger m, BigInteger r,
                                                     BigInteger amountBits) {
        if (!validBits(amountBits) || !canonical(m) || !canonical(r)) {
            Builtins.error();
        }
        if (m.compareTo(pow2(amountBits)) >= 0) {
            Builtins.error();
        }
        return Builtins.bls12_381_G1_equal(commit(m, r), commitment);
    }

    /**
     * Disclosed byte opening (V1): {@code true} iff
     * {@code commitment == [HashBytesToScalarG1(payload)]·G + [r]·H}. Check 1 on {@code r} fails the
     * script before any hashing or multiplication; {@code s} is recomputed from the payload.
     */
    public static boolean verifyBytesOpening(JulcG1 commitment, byte[] payload, BigInteger r) {
        if (!canonical(r)) {
            Builtins.error();
        }
        return Builtins.bls12_381_G1_equal(commit(hashBytesToScalar(payload), r), commitment);
    }

    /**
     * {@code HashBytesToScalarG1(payload)} (spec §5): {@code expand_message_xmd}/SHA-256 to 48 octets
     * over {@code payload ‖ I2OSP(n, 8)} under {@code DST_S}, reduced mod {@code q}. The framed input
     * is built in memory, which spec §5.2 permits on-chain; its size is bounded by the transaction.
     */
    public static BigInteger hashBytesToScalar(byte[] payload) {
        byte[] framed = Builtins.appendByteString(payload,
                Builtins.integerToByteString(true, 8L, Builtins.lengthOfByteString(payload)));
        return BbsHashToScalar.hashToScalar(framed, dstS());
    }

    /**
     * {@code commitment + [δ]·G} for a public signed delta (spec §6.4): {@code deltaBits ∈ [1, 253]}
     * and {@code |δ| < 2^deltaBits}, else the script fails; {@code [|δ|]·G} is computed with the
     * canonical scalar {@code |δ|} and negated when {@code δ < 0}.
     */
    public static JulcG1 applyPublicDelta(JulcG1 commitment, BigInteger delta, BigInteger deltaBits) {
        if (!validDeltaBits(deltaBits)) {
            Builtins.error();
        }
        BigInteger magnitude = delta.signum() < 0 ? delta.negate() : delta;
        if (magnitude.compareTo(pow2(deltaBits)) >= 0) {
            Builtins.error();
        }
        JulcG1 step = Builtins.bls12_381_G1_scalarMul(magnitude, base(baseGEncoding()));
        JulcG1 signedStep = delta.signum() < 0 ? Builtins.bls12_381_G1_neg(step) : step;
        return Builtins.bls12_381_G1_add(commitment, signedStep);
    }

    /** {@code a + b}: opens to the sums of the messages and blindings, mod {@code q}. */
    public static JulcG1 add(JulcG1 a, JulcG1 b) {
        return Builtins.bls12_381_G1_add(a, b);
    }

    /** {@code a − b}: opens to the differences of the messages and blindings, mod {@code q}. */
    public static JulcG1 subtract(JulcG1 a, JulcG1 b) {
        return Builtins.bls12_381_G1_add(a, Builtins.bls12_381_G1_neg(b));
    }

    /** {@code −a}. */
    public static JulcG1 negate(JulcG1 a) {
        return Builtins.bls12_381_G1_neg(a);
    }

    /** The pinned compressed encoding of {@code G} (spec §2.2). */
    public static byte[] baseGEncoding() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        BigInteger g = BigInteger.valueOf(19742636L)
                .multiply(base).add(BigInteger.valueOf(487342436617912845L))
                .multiply(base).add(BigInteger.valueOf(786236033613326307L))
                .multiply(base).add(BigInteger.valueOf(95595993200291546L))
                .multiply(base).add(BigInteger.valueOf(846243343301113780L))
                .multiply(base).add(BigInteger.valueOf(62929437528291396L))
                .multiply(base).add(BigInteger.valueOf(349299720068017982L));
        return Builtins.integerToByteString(true, 48L, g);
    }

    /** The pinned compressed encoding of {@code H} (spec §2.2). */
    public static byte[] baseHEncoding() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        BigInteger h = BigInteger.valueOf(22606316L)
                .multiply(base).add(BigInteger.valueOf(7913454726302611L))
                .multiply(base).add(BigInteger.valueOf(913866733164788119L))
                .multiply(base).add(BigInteger.valueOf(950482235740235285L))
                .multiply(base).add(BigInteger.valueOf(752892572404685644L))
                .multiply(base).add(BigInteger.valueOf(56728579045353354L))
                .multiply(base).add(BigInteger.valueOf(860155921606552421L));
        return Builtins.integerToByteString(true, 48L, h);
    }

    /** {@code DST_S}, the 52 ASCII octets {@code "ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256"}. */
    public static byte[] dstS() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        BigInteger dst = BigInteger.valueOf(59756998721997636L)
                .multiply(base).add(BigInteger.valueOf(643135487068496496L))
                .multiply(base).add(BigInteger.valueOf(818463019036061754L))
                .multiply(base).add(BigInteger.valueOf(590487657251946928L))
                .multiply(base).add(BigInteger.valueOf(736826917741907428L))
                .multiply(base).add(BigInteger.valueOf(557272537583912376L))
                .multiply(base).add(BigInteger.valueOf(765847953315345718L));
        return Builtins.integerToByteString(true, 52L, dst);
    }

    /** {@code q}, the order of G1 (built from limbs: Julc cannot parse a 77-digit literal). */
    public static BigInteger groupOrder() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }

    /** {@code [x]·G + [r]·H} for canonical {@code x, r}. */
    private static JulcG1 commit(BigInteger x, BigInteger r) {
        return Builtins.bls12_381_G1_add(
                Builtins.bls12_381_G1_scalarMul(x, base(baseGEncoding())),
                Builtins.bls12_381_G1_scalarMul(r, base(baseHEncoding())));
    }

    /**
     * A pinned base, decompressed where it is used. Julc evaluates zero-argument library methods once
     * at script start, so a zero-argument accessor would make every script that links this library
     * decompress both bases, used or not; a method with an argument is evaluated only when called.
     */
    private static JulcG1 base(byte[] pinnedEncoding) {
        return Builtins.bls12_381_G1_uncompress(pinnedEncoding);
    }

    /** Check 1: {@code 0 ≤ x < q}. */
    private static boolean canonical(BigInteger x) {
        return x.signum() >= 0 && x.compareTo(groupOrder()) < 0;
    }

    /** An amount-bound width in {@code [1, 254]}. */
    private static boolean validBits(BigInteger bits) {
        return bits.compareTo(BigInteger.ONE) >= 0 && bits.compareTo(BigInteger.valueOf(254L)) <= 0;
    }

    /**
     * A delta-bound width in {@code [1, 253]}: only then is a bounded signed delta unique mod {@code q}
     * (spec §6.4), so no {@code δ − q} alias passes the bound.
     */
    private static boolean validDeltaBits(BigInteger bits) {
        return bits.compareTo(BigInteger.ONE) >= 0 && bits.compareTo(BigInteger.valueOf(253L)) <= 0;
    }

    /** {@code 2^k} for {@code k ≥ 0}, by square and multiply. */
    private static BigInteger pow2(BigInteger k) {
        if (k.signum() == 0) {
            return BigInteger.ONE;
        }
        BigInteger half = pow2(k.divide(BigInteger.valueOf(2L)));
        BigInteger square = half.multiply(half);
        return k.remainder(BigInteger.valueOf(2L)).signum() == 0 ? square : square.add(square);
    }
}
