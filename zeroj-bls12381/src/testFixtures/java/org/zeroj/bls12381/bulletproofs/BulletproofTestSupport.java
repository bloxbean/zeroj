package org.zeroj.bls12381.bulletproofs;

import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * TEST-ONLY access to public values of {@code bulletproof-range-bls12-381-g1-v1} for other modules'
 * tests (the ADR-0061 M4 cost study in {@code zeroj-onchain-julc}, the M5 reference state machine):
 * the pinned generator encodings and the transcript challenges of a proof. Nothing secret passes
 * through here. Unpublished test fixture.
 */
public final class BulletproofTestSupport {

    private BulletproofTestSupport() {
    }

    /** The challenges of spec §5.3 for a proof, recomputed by the verifier's transcript. */
    public record Challenges(byte[] sessionId, BigInteger y, BigInteger z, BigInteger x, BigInteger xu,
                             List<BigInteger> xj) {
    }

    /** Compressed {@code G} and {@code H} (pedersen-bls12-381-g1-v1 §2.2). */
    public static List<String> pedersenBasesHex() {
        return List.of(BulletproofGenerators.G_HEX, BulletproofGenerators.H_HEX);
    }

    /** Compressed {@code G_0 … G_{n−1}}, {@code H_0 … H_{n−1}}, then {@code U}, for width {@code bits}. */
    public static List<String> generatorsHex(int bits) {
        G1RangeProof.requireBits(bits);
        List<String> out = new ArrayList<>(BulletproofGenerators.G_VEC_HEX.subList(0, bits));
        out.addAll(BulletproofGenerators.H_VEC_HEX.subList(0, bits));
        out.add(BulletproofGenerators.U_HEX);
        return out;
    }

    /** The transcript challenges of a well-formed proof for a commitment (spec §5.3). */
    public static Challenges challenges(byte[] commitment, byte[] proof, int bits, byte[] ctx) {
        G1RangeProof decoded = G1RangeProof.decode(proof, bits);
        G1RangeVerifier.Challenges c = G1RangeVerifier.Challenges.derive(
                PointCodec.point(G1PedersenCommitment.decode(commitment)), decoded, RangeTranscript.configuredContext(bits, ctx));
        return new Challenges(c.sessionId(), c.y(), c.z(), c.x(), c.xu(), List.of(c.xj()));
    }
}
