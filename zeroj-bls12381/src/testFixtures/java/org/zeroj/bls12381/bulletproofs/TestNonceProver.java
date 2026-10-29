package org.zeroj.bls12381.bulletproofs;

import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * TEST-ONLY deterministic range proving (spec {@code bulletproof-range-bls12-381-g1-v1} §7.5), fenced
 * as ADR-0046 fences its seeded prover: this class is in the unpublished {@code testFixtures} source
 * set of {@code zeroj-bls12381}, and the module's metadata check fails the build if that variant is
 * ever published.
 *
 * <p><b>Never use it for a real proof.</b> The nonces depend only on the seed, so two proofs under one
 * seed reuse every nonce, and three proofs of one opening under one seed reveal {@code γ} and then
 * {@code v}. Every vector uses its own seed.
 */
public final class TestNonceProver {

    /** Octets of a nonce seed. */
    public static final int SEED_BYTES = 32;

    private static final byte[] NONCE_TAG =
            "ZeroJ:bulletproof-range-bls12-381-g1-v1/test-nonces-v1".getBytes(StandardCharsets.US_ASCII);

    private TestNonceProver() {
    }

    /** A proof with the test nonces of {@code seed}, through {@code prover}'s ordinary refusals. */
    public static G1RangeProof prove(G1RangeProver prover, G1PedersenOpening opening, int bits, byte[] context,
                                     byte[] seed) {
        Objects.requireNonNull(prover, "prover");
        return prover.prove(opening, bits, context, source(seed));
    }

    /**
     * The spec §7.5 nonce source: {@code Init(DeriveSessionID("…/test-nonces-v1"))}, absorb the
     * 32-octet seed, then each nonce is {@code LE2IP(Squeeze(48)) mod q} from one output stream. A
     * restart fails closed.
     */
    static NonceSource source(byte[] seed) {
        Objects.requireNonNull(seed, "seed");
        if (seed.length != SEED_BYTES) {
            throw new IllegalArgumentException("a test nonce seed is 32 octets");
        }
        DuplexSponge ds = DuplexSponge.init(DuplexSponge.deriveSessionId(NONCE_TAG));
        ds.absorb(seed.clone());
        return new NonceSource() {
            @Override
            public BigInteger next() {
                return FsCodec.decodeUint(ds.squeeze(RangeTranscript.CHALLENGE_BYTES), PointCodec.Q);
            }

            @Override
            public void beforeRestart() {
                throw new IllegalStateException("a test-nonce proof needed a restart; pick another seed");
            }
        };
    }
}
