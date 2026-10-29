package org.zeroj.bls12381.bulletproofs;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;

/**
 * The production nonce source of spec §7.3: each nonce is 64 octets from a {@link SecureRandom}
 * created by this class at run time, read big-endian and reduced mod {@code q}, the sampler of
 * {@code G1Pedersen.randomBlinding}.
 *
 * <p>The source is created per proof and never in a static initialiser, so a native-image build
 * cannot capture a seeded state. The entropy behind {@code SecureRandom} is trusted platform
 * configuration: Java cannot verify it. {@link #create} accepts only the algorithms of
 * {@link #ALLOWED_ALGORITHMS}, as a sanity check against an obviously wrong or substituted default;
 * passing that check does not establish that the entropy is real (spec §7.3, Codex M0 F8).
 */
final class SystemNonceSource implements NonceSource {

    /** Octets drawn per nonce. */
    static final int SAMPLE_BYTES = 64;

    /** The {@code SecureRandom.getAlgorithm()} values the prover accepts (spec §7.3). */
    static final Set<String> ALLOWED_ALGORITHMS = Set.of("NativePRNG", "NativePRNGNonBlocking", "DRBG", "Windows-PRNG");

    private final SecureRandom random;

    private SystemNonceSource(SecureRandom random) {
        this.random = random;
    }

    /**
     * A source over a new default {@link SecureRandom}.
     *
     * @throws IllegalStateException if its algorithm is not in {@link #ALLOWED_ALGORITHMS}
     */
    static SystemNonceSource create() {
        return checked(new SecureRandom());
    }

    /** The allowlist check of {@link #create}, separated so that a test can exercise its refusal. */
    static SystemNonceSource checked(SecureRandom random) {
        String algorithm = random.getAlgorithm();
        if (!ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw new IllegalStateException("SecureRandom algorithm " + algorithm
                    + " is not accepted for range-proof nonces");
        }
        return new SystemNonceSource(random);
    }

    @Override
    public BigInteger next() {
        byte[] sample = new byte[SAMPLE_BYTES];
        try {
            random.nextBytes(sample);
            return new BigInteger(1, sample).mod(PointCodec.Q);
        } finally {
            Arrays.fill(sample, (byte) 0);
        }
    }

    @Override
    public void beforeRestart() {
        // Fresh nonces are simply drawn again.
    }
}
