package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit factories for Jubjub signing assurance profiles. */
public final class JubjubSigners {

    private JubjubSigners() {
    }

    /**
     * Wraps the existing variable-time signer for compatibility/offline use.
     *
     * <p>The wrapper cannot wipe the immutable {@code BigInteger} stored by the legacy
     * keypair. Closing only prevents further use through this signer.
     */
    public static JubjubSigner compatibilityOffline(EdDSAJubjub.Keypair keypair) {
        return new CompatibilitySigner(Objects.requireNonNull(keypair, "keypair"));
    }

    /**
     * Creates the fixed-limb deterministic-v1 compatibility signer.
     *
     * <p>This preserves legacy signature bytes for differential testing but is deliberately
     * not a validated network-reachable profile.
     *
     * <p>The signer assumes destructive ownership of {@code key}: closing the signer closes
     * and wipes the key. If callers deliberately wrap the same key in more than one signer,
     * those wrappers share one destruction domain and closing any one invalidates all of them.
     */
    public static JubjubSigner fixedLimbDeterministicV1Compatibility(
            HardenedJubjubKey key) {
        return new FixedLimbJubjubSigner(
                Objects.requireNonNull(key, "key"),
                FixedLimbJubjubSigner.Mode.DETERMINISTIC_V1,
                null);
    }

    /**
     * Requires a reviewed validated dedicated-host profile.
     *
     * <p>ADR-0039 M4–M8 include external cryptographic review and platform-specific
     * validation. This implementation intentionally fails closed until such a profile is
     * committed to the release; it never falls back to deterministic-v1 or legacy
     * {@code BigInteger} signing.
     *
     * <p>The placeholder intentionally accepts no general {@link HardenedJubjubKey}. A future
     * implementation must provision/import its key through the attested platform boundary
     * (or an unforgeable installation handle) rather than relabelling an untagged key.
     *
     * @throws UnsupportedOperationException until a reviewed platform profile is published
     */
    public static JubjubSigner validatedDedicatedHostJavaRequired() {
        throw new UnsupportedOperationException(
                "No validated Jubjub dedicated-host Java profile is published; "
                        + "ADR-0039 M4-M8 release gates remain required");
    }

    /**
     * Package-private candidate used by vectors, fault tests, and timing experiments. It is
     * impossible to obtain through the validated factory. It assumes the same destructive
     * key and randomness-source ownership as a future hardened signer.
     */
    static JubjubSigner hedgedCandidateForTesting(
            HardenedJubjubKey key, JubjubAuxiliaryRandomSource auxiliaryRandom) {
        return new FixedLimbJubjubSigner(
                Objects.requireNonNull(key, "key"),
                FixedLimbJubjubSigner.Mode.HEDGED_CANDIDATE,
                Objects.requireNonNull(auxiliaryRandom, "auxiliaryRandom"));
    }

    static JubjubAuxiliaryRandomSource sourceForTesting(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        return random::nextBytes;
    }

    private static final class CompatibilitySigner implements JubjubSigner {
        private final EdDSAJubjub.Keypair keypair;
        private final AtomicBoolean closed = new AtomicBoolean();

        private CompatibilitySigner(EdDSAJubjub.Keypair keypair) {
            this.keypair = keypair;
        }

        @Override
        public JubjubSigningProfile profile() {
            return JubjubSigningProfile.COMPATIBILITY_OFFLINE;
        }

        @Override
        public JubjubPoint publicKey() {
            return keypair.pk();
        }

        @Override
        public EdDSAJubjub.Signature sign(JubjubMessage message) {
            if (closed.get()) {
                throw new IllegalStateException("Jubjub signer is closed");
            }
            return EdDSAJubjub.signCompatibilityOffline(
                    keypair, Objects.requireNonNull(message, "message"));
        }

        @Override
        public void close() {
            closed.set(true);
        }
    }
}
