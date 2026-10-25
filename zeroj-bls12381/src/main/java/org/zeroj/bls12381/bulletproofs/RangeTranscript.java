package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.ProofProtocols;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/**
 * The transcript of spec {@code bulletproof-range-bls12-381-g1-v1} §5: the session tag, the
 * instance, and the absorb/squeeze rounds on the fiat-shamir-03 SHAKE128 duplex sponge. The prover
 * and the verifier drive the same object in the same order, so their challenges agree by
 * construction; the Python second implementation and the CFRG proof-of-concept sponge check the
 * bytes independently.
 *
 * <p>Each challenge is {@code DecodeField(Squeeze(48), q, 1) = LE2IP(·) mod q} (§3). A zero
 * challenge is reported to the caller, who rejects (verifier) or restarts (prover).
 */
final class RangeTranscript {

    /** Octets squeezed per challenge: {@code Ns + 16} for the 32-octet scalar field. */
    static final int CHALLENGE_BYTES = PointCodec.SCALAR_BYTES + 16;

    /** Minimum and maximum application-context length in octets (spec §5.1). */
    static final int MIN_CONTEXT_BYTES = 1;
    static final int MAX_CONTEXT_BYTES = 1024;

    private static final String TAG_PREFIX = "ZeroJ:bulletproof-range-bls12-381-g1-v1"
            + "/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381";
    private static final BigInteger TWO_POW_32 = BigInteger.ONE.shiftLeft(32);

    private final DuplexSponge sponge;
    private final byte[] sessionId;
    private final byte[] instance;

    private RangeTranscript(byte[] sessionId, byte[] instance) {
        this.sessionId = sessionId;
        this.instance = instance;
        this.sponge = DuplexSponge.init(sessionId);
        sponge.absorb(instance);
    }

    /** Starts the transcript for width {@code bits}, context {@code ctx} and commitment {@code v}. */
    static RangeTranscript start(int bits, byte[] ctx, G1Point v) {
        return new RangeTranscript(DuplexSponge.deriveSessionId(tag(bits, ctx)), instance(bits, v));
    }

    /**
     * Configuration check of spec §7.1 and §8.1 step 1: {@code n ∈ {16, 32, 64}} and
     * {@code len(ctx) ∈ [1, 1024]}, else {@code INVALID_CONFIGURATION}.
     */
    static void requireConfiguration(int bits, byte[] ctx) {
        Objects.requireNonNull(ctx, "context");
        G1RangeProof.requireBits(bits);
        if (ctx.length < MIN_CONTEXT_BYTES || ctx.length > MAX_CONTEXT_BYTES) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "context must be 1 to 1024 octets");
        }
    }

    /** {@code k = log₂ n} for a configured width. */
    static int rounds(int bits) {
        return Integer.numberOfTrailingZeros(bits);
    }

    /** The session tag of spec §5.1, for a configured width and context. */
    static byte[] tag(int bits, byte[] ctx) {
        String tag = TAG_PREFIX
                + "/N" + String.format(Locale.ROOT, "%03d", bits)
                + "/A96S96.A96S48.A96S48.(A96S48)x" + rounds(bits)
                + "/CTX" + String.format(Locale.ROOT, "%04d", ctx.length) + ":" + HexFormat.of().formatHex(ctx);
        return tag.getBytes(StandardCharsets.US_ASCII);
    }

    /** The instance encoding of spec §5.2. */
    static byte[] instance(int bits, G1Point v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(FsCodec.serializeVarLenString(G1PedersenCommitment.PROFILE.id().toAsciiBytes()));
        out.writeBytes(PointCodec.encode(BulletproofGenerators.g()));
        out.writeBytes(PointCodec.encode(BulletproofGenerators.h()));
        out.writeBytes(FsCodec.serializeVarLenString(
                ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1.generatorSetId().toAsciiBytes()));
        out.writeBytes(BulletproofGenerators.digest());
        out.writeBytes(FsCodec.serializeUint(BigInteger.valueOf(bits), TWO_POW_32));
        out.writeBytes(PointCodec.encode(v));
        return out.toByteArray();
    }

    /** The 32-octet session identifier (a copy). */
    byte[] sessionId() {
        return sessionId.clone();
    }

    /** The encoded instance (a copy). */
    byte[] instanceBytes() {
        return instance.clone();
    }

    /** Absorbs two points, then squeezes one challenge. */
    BigInteger absorbPointsSqueeze(G1Point first, G1Point second) {
        absorbPoints(first, second);
        return challenge();
    }

    /** Absorbs {@code ser(first) ‖ ser(second)}: 96 octets. */
    void absorbPoints(G1Point first, G1Point second) {
        byte[] buf = new byte[2 * PointCodec.POINT_BYTES];
        System.arraycopy(PointCodec.encode(first), 0, buf, 0, PointCodec.POINT_BYTES);
        System.arraycopy(PointCodec.encode(second), 0, buf, PointCodec.POINT_BYTES, PointCodec.POINT_BYTES);
        sponge.absorb(buf);
    }

    /** Absorbs {@code ser(a) ‖ ser(b) ‖ ser(c)}: 96 octets. */
    void absorbScalars(BigInteger a, BigInteger b, BigInteger c) {
        byte[] buf = new byte[3 * PointCodec.SCALAR_BYTES];
        PointCodec.writeScalar(a, buf, 0);
        PointCodec.writeScalar(b, buf, PointCodec.SCALAR_BYTES);
        PointCodec.writeScalar(c, buf, 2 * PointCodec.SCALAR_BYTES);
        sponge.absorb(buf);
    }

    /** {@code DecodeField(Squeeze(48), q, 1)}: the next challenge, possibly zero. */
    BigInteger challenge() {
        return FsCodec.decodeUint(sponge.squeeze(CHALLENGE_BYTES), PointCodec.Q);
    }
}
