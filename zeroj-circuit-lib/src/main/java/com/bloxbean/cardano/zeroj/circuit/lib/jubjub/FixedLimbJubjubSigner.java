package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Internal deterministic/hedged fixed-limb signer implementation. */
final class FixedLimbJubjubSigner implements JubjubSigner {

    enum Mode {
        DETERMINISTIC_V1,
        HEDGED_CANDIDATE
    }

    @FunctionalInterface
    interface NonceTestHook {
        void afterDerivation(long[] words, int nonceOffset);
    }

    @FunctionalInterface
    interface CandidateTestHook {
        EdDSAJubjub.Signature apply(EdDSAJubjub.Signature candidate);
    }

    @FunctionalInterface
    interface PointMulObserver {
        void beforeNoncePointMultiplication();
    }

    private static final NonceTestHook NO_NONCE_HOOK = (words, offset) -> { };
    private static final CandidateTestHook NO_CANDIDATE_HOOK = candidate -> candidate;
    private static final PointMulObserver NO_POINT_OBSERVER = () -> { };

    private final HardenedJubjubKey key;
    private final Mode mode;
    private final JubjubAuxiliaryRandomSource auxiliaryRandom;
    private final NonceTestHook nonceTestHook;
    private final CandidateTestHook candidateTestHook;
    private final PointMulObserver pointMulObserver;
    private final AtomicBoolean closeStarted = new AtomicBoolean();
    private final CountDownLatch closeComplete = new CountDownLatch(1);
    private volatile Throwable closeFailure;

    FixedLimbJubjubSigner(HardenedJubjubKey key,
                         Mode mode,
                         JubjubAuxiliaryRandomSource auxiliaryRandom) {
        this(key, mode, auxiliaryRandom,
                NO_NONCE_HOOK, NO_CANDIDATE_HOOK, NO_POINT_OBSERVER);
    }

    FixedLimbJubjubSigner(HardenedJubjubKey key,
                         Mode mode,
                         JubjubAuxiliaryRandomSource auxiliaryRandom,
                         NonceTestHook nonceTestHook,
                         CandidateTestHook candidateTestHook,
                         PointMulObserver pointMulObserver) {
        this.key = Objects.requireNonNull(key, "key");
        this.mode = Objects.requireNonNull(mode, "mode");
        this.auxiliaryRandom = auxiliaryRandom;
        this.nonceTestHook = Objects.requireNonNull(nonceTestHook, "nonceTestHook");
        this.candidateTestHook = Objects.requireNonNull(candidateTestHook, "candidateTestHook");
        this.pointMulObserver = Objects.requireNonNull(pointMulObserver, "pointMulObserver");
        if (mode == Mode.HEDGED_CANDIDATE && auxiliaryRandom == null) {
            throw new IllegalArgumentException("hedged candidate requires auxiliary randomness");
        }
        if (mode == Mode.DETERMINISTIC_V1 && auxiliaryRandom != null) {
            throw new IllegalArgumentException(
                    "deterministic-v1 profile must not accept auxiliary randomness");
        }
    }

    @Override
    public JubjubSigningProfile profile() {
        return mode == Mode.DETERMINISTIC_V1
                ? JubjubSigningProfile.FIXED_LIMB_DETERMINISTIC_V1_COMPATIBILITY
                : JubjubSigningProfile.HEDGED_DEDICATED_HOST_CANDIDATE;
    }

    @Override
    public JubjubPoint publicKey() {
        return key.publicKey();
    }

    @Override
    public EdDSAJubjub.Signature sign(JubjubMessage message) {
        Objects.requireNonNull(message, "message");
        if (closeStarted.get()) {
            throw new IllegalStateException("Jubjub signer is closed");
        }

        SigningScratch scratch = new SigningScratch();
        HardenedJubjubKey.Lease lease = key.admit();
        try {
            // Hedged randomness is drawn after admission but before any persistent key material
            // is copied. Provider failure therefore aborts without starting secret arithmetic.
            if (mode == Mode.HEDGED_CANDIDATE) {
                auxiliaryRandom.fill(scratch.auxiliary);
            }
            lease.copyInto(scratch);

            message.copyCanonicalTo(scratch.bytes, SigningScratch.MESSAGE_BYTES);
            long messageMask = CtJubjubFqOps.fromCanonicalBytes(
                    scratch.words, SigningScratch.MESSAGE,
                    scratch.bytes, SigningScratch.MESSAGE_BYTES,
                    scratch.words, SigningScratch.FIELD_WORK);
            if (messageMask != -1L) {
                // A JubjubMessage can only be constructed canonically. This is a public
                // invariant/fault check, not secret-dependent control flow.
                throw new IllegalStateException("JubjubMessage lost canonicality");
            }

            deriveNonce(scratch, SigningScratch.NONCE);
            nonceTestHook.afterDerivation(scratch.words, SigningScratch.NONCE);
            if (mode == Mode.DETERMINISTIC_V1
                    && CtJubjubFrOps.zeroMask(
                            scratch.words, SigningScratch.NONCE) == -1L) {
                throw new IllegalStateException(
                        "Jubjub nonce derivation produced zero; no signature was released");
            }

            CtJubjubPointOps.generator(scratch.words, SigningScratch.GENERATOR);
            pointMulObserver.beforeNoncePointMultiplication();
            CtJubjubPointOps.scalarMul(
                    scratch.words, SigningScratch.NONCE_POINT,
                    scratch.words, SigningScratch.GENERATOR,
                    scratch.words, SigningScratch.NONCE,
                    scratch.words, SigningScratch.POINT_WORK);
            CtJubjubPointOps.normalize(
                    scratch.words, SigningScratch.NORMALIZED_NONCE_POINT,
                    scratch.words, SigningScratch.NONCE_POINT,
                    scratch.words, SigningScratch.POINT_WORK);

            JubjubPoint rPoint = JubjubPublicAdapter.normalizedPoint(
                    scratch.words, SigningScratch.NORMALIZED_NONCE_POINT,
                    scratch.bytes, SigningScratch.PUBLIC_U_BYTES,
                    SigningScratch.PUBLIC_V_BYTES,
                    scratch.words, SigningScratch.FIELD_WORK);
            long challengeMask = JubjubPublicAdapter.challengeToScalar(
                    scratch.words, SigningScratch.CHALLENGE,
                    rPoint, key.publicKey(), message,
                    scratch.bytes, SigningScratch.SCALAR_BYTES,
                    scratch.words, SigningScratch.FIELD_WORK);
            if (challengeMask != -1L) {
                throw new IllegalStateException("public challenge was not canonical");
            }

            CtJubjubFrOps.mul(
                    scratch.words, SigningScratch.SIGNATURE_SCALAR,
                    scratch.words, SigningScratch.CHALLENGE,
                    scratch.words, SigningScratch.SK,
                    scratch.words, SigningScratch.FIELD_WORK);
            CtJubjubFrOps.add(
                    scratch.words, SigningScratch.SIGNATURE_SCALAR,
                    scratch.words, SigningScratch.SIGNATURE_SCALAR,
                    scratch.words, SigningScratch.NONCE);

            // Re-derive after R and S are complete. This catches the modeled class in which a
            // transient fault replaces the stored nonce before both computations, producing an
            // internally valid but attacker-selected nonce that public verification alone
            // cannot detect. A fault that corrupts both derivations identically remains a
            // documented common-mode limitation.
            deriveNonce(scratch, SigningScratch.NONCE_CHECK);
            long nonceMatches = CtJubjubFrOps.equalMask(
                    scratch.words, SigningScratch.NONCE,
                    scratch.words, SigningScratch.NONCE_CHECK);
            long nonceNonZero = ~CtJubjubFrOps.zeroMask(
                    scratch.words, SigningScratch.NONCE);
            if ((nonceMatches & nonceNonZero) != -1L) {
                throw new IllegalStateException(
                        "Jubjub nonce invariant failed; no signature was released");
            }

            EdDSAJubjub.Signature candidate = candidateTestHook.apply(
                    JubjubPublicAdapter.signature(
                            rPoint,
                    scratch.words, SigningScratch.SIGNATURE_SCALAR,
                    scratch.bytes, SigningScratch.SCALAR_BYTES,
                            scratch.words, SigningScratch.FIELD_WORK));
            return JubjubPublicAdapter.verifyBeforeRelease(
                    key.publicKey(), message, candidate);
        } finally {
            try {
                scratch.wipe();
            } finally {
                lease.close();
            }
        }
    }

    @Override
    public void close() {
        if (closeStarted.compareAndSet(false, true)) {
            // key.close() waits for every admitted operation, including an in-progress
            // randomness draw. Only then is it safe to destroy the signer-owned source.
            Throwable failure = null;
            try {
                key.close();
            } catch (RuntimeException | Error keyFailure) {
                failure = keyFailure;
            }
            try {
                if (auxiliaryRandom != null) {
                    auxiliaryRandom.close();
                }
            } catch (RuntimeException | Error sourceFailure) {
                if (failure == null) {
                    failure = sourceFailure;
                } else {
                    failure.addSuppressed(sourceFailure);
                }
            } finally {
                closeFailure = failure;
                closeComplete.countDown();
            }
        }
        awaitCloseCompletion();
        rethrowCloseFailure();
    }

    private void awaitCloseCompletion() {
        boolean interrupted = false;
        while (true) {
            try {
                closeComplete.await();
                break;
            } catch (InterruptedException ignored) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private void rethrowCloseFailure() {
        Throwable failure = closeFailure;
        if (failure instanceof RuntimeException runtimeException) {
            throw runtimeException;
        }
        if (failure instanceof Error error) {
            throw error;
        }
    }

    private void deriveNonce(SigningScratch scratch, int outputOffset) {
        if (mode == Mode.DETERMINISTIC_V1) {
            CtJubjubNonce.deterministicV1(
                    scratch.words, outputOffset,
                    scratch.words, SigningScratch.SK,
                    scratch.words, SigningScratch.MESSAGE,
                    scratch.words, SigningScratch.NONCE_WORK);
        } else {
            CtJubjubNonce.hedgedV1(
                    scratch.words, outputOffset,
                    scratch.words, SigningScratch.NONCE_KEY,
                    scratch.words, SigningScratch.PUBLIC_KEY,
                    scratch.words, SigningScratch.MESSAGE,
                    scratch.auxiliary, 0,
                    scratch.words, SigningScratch.NONCE_WORK);
        }
    }
}
