package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Mutable, non-serializable secret key container for the ADR-0039 fixed-limb signer.
 *
 * <p>The type deliberately has no secret accessor, value equality, hash code, or
 * serialization support. {@link #close()} prevents new operations, waits for admitted
 * operations to finish, and then wipes persistent scalar and nonce-key storage. JVM copies,
 * registers, crash dumps, and caller-owned import buffers remain outside the erasure
 * guarantee.
 *
 * <p>The general factories below do not confer validated randomness/provisioning provenance.
 * A future validated platform factory must create or import this type through its approved
 * boundary and must not trust caller-asserted metadata.
 *
 * <p>Review/compatibility signers that accept this general type assume destructive ownership.
 * Multiple wrappers over one instance share one destruction domain: closing any wrapper
 * closes the key and invalidates the others.
 */
public final class HardenedJubjubKey implements AutoCloseable {

    private enum State {
        OPEN,
        CLOSING,
        CLOSED
    }

    private final Object lifecycle = new Object();
    private final long[] secretScalar;
    private final long[] nonceKey;
    private final long[] publicPoint;
    private final JubjubPoint publicKey;
    private State state = State.OPEN;
    private int activeOperations;

    private HardenedJubjubKey(long[] secretScalar,
                             long[] nonceKey,
                             long[] publicPoint,
                             JubjubPoint publicKey) {
        this.secretScalar = secretScalar;
        this.nonceKey = nonceKey;
        this.publicPoint = publicPoint;
        this.publicKey = publicKey;
    }

    /**
     * Imports an unsigned, big-endian canonical scalar satisfying {@code 0 < sk < l}.
     *
     * <p>The input is defensively copied and the owned copy is wiped. The caller remains
     * responsible for wiping its original buffer.
     */
    public static HardenedJubjubKey importCanonical(byte[] encodedSecret) {
        Objects.requireNonNull(encodedSecret, "encodedSecret");
        if (encodedSecret.length != 32) {
            throw new IllegalArgumentException(
                    "hardened Jubjub secret must be exactly 32 bytes");
        }
        byte[] owned = encodedSecret.clone();
        long[] scalar = new long[CtJubjubFrOps.LIMBS];
        long[] work = new long[SigningScratch.WORDS];
        try {
            long canonical = CtJubjubFrOps.fromCanonicalBytes(
                    scalar, 0, owned, 0, work, 0);
            long nonZero = ~CtJubjubFrOps.zeroMask(scalar, 0);
            if ((canonical & nonZero) != -1L) {
                throw new IllegalArgumentException(
                        "hardened Jubjub secret must satisfy 0 < sk < l");
            }
            return establish(scalar, work);
        } catch (RuntimeException | Error failure) {
            throw failure;
        } finally {
            SigningScratch.wipe(scalar);
            SigningScratch.wipe(owned);
            SigningScratch.wipe(work);
        }
    }

    /**
     * Generates an unbiased scalar in {@code [1,l)} by exact rejection sampling.
     *
     * <p>This general API accepts a caller-selected CSPRNG and is not itself evidence that the
     * source belongs to a future validated platform profile.
     */
    public static HardenedJubjubKey generate(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        byte[] candidate = new byte[32];
        long[] scalar = new long[CtJubjubFrOps.LIMBS];
        long[] work = new long[SigningScratch.WORDS];
        try {
            while (true) {
                random.nextBytes(candidate);
                candidate[0] &= 0x0f;
                long canonical = CtJubjubFrOps.fromCanonicalBytes(
                        scalar, 0, candidate, 0, work, 0);
                long nonZero = ~CtJubjubFrOps.zeroMask(scalar, 0);
                if ((canonical & nonZero) == -1L) {
                    return establish(scalar, work);
                }
                SigningScratch.wipe(candidate);
                SigningScratch.wipe(scalar);
            }
        } catch (RuntimeException | Error failure) {
            throw failure;
        } finally {
            SigningScratch.wipe(scalar);
            SigningScratch.wipe(candidate);
            SigningScratch.wipe(work);
        }
    }

    /** Returns the public key. This remains available after close and contains no secret. */
    public JubjubPoint publicKey() {
        return publicKey;
    }

    /** Returns whether key destruction has completed; this is lifecycle state, not key data. */
    public boolean isClosed() {
        synchronized (lifecycle) {
            return state == State.CLOSED;
        }
    }

    Lease admit() {
        synchronized (lifecycle) {
            if (state != State.OPEN) {
                throw new IllegalStateException("hardened Jubjub key is closing or closed");
            }
            activeOperations++;
            return new Lease(this);
        }
    }

    private void copyInto(SigningScratch scratch) {
        synchronized (lifecycle) {
            // An admitted lease pins the arrays until release, including while close waits.
            if (activeOperations <= 0 || state == State.CLOSED) {
                throw new IllegalStateException("invalid hardened-key operation lease");
            }
            CtJubjubFrOps.copy(scratch.words, SigningScratch.SK, secretScalar, 0);
            CtJubjubFqOps.copy(scratch.words, SigningScratch.NONCE_KEY, nonceKey, 0);
            CtJubjubPointOps.copy(
                    scratch.words, SigningScratch.PUBLIC_KEY, publicPoint, 0);
        }
    }

    private void release() {
        synchronized (lifecycle) {
            if (activeOperations <= 0) {
                throw new IllegalStateException("hardened-key lease released twice");
            }
            activeOperations--;
            if (activeOperations == 0) {
                lifecycle.notifyAll();
            }
        }
    }

    /**
     * Prevents new operations, waits for already-admitted operations, and wipes key storage.
     * Double close is a safe no-op.
     */
    @Override
    public void close() {
        boolean interrupted = false;
        synchronized (lifecycle) {
            if (state == State.CLOSED) {
                return;
            }
            state = State.CLOSING;
            while (activeOperations != 0) {
                try {
                    lifecycle.wait();
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            SigningScratch.wipe(secretScalar);
            SigningScratch.wipe(nonceKey);
            // The point is public, but wiping the internal fixed-limb copy keeps lifecycle
            // behavior simple and prevents accidental future secret use after close.
            SigningScratch.wipe(publicPoint);
            state = State.CLOSED;
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public String toString() {
        return "HardenedJubjubKey[secret=<redacted>, publicKey=" + publicKey + "]";
    }

    private static HardenedJubjubKey establish(long[] importedScalar, long[] work) {
        long[] scalar = importedScalar.clone();
        long[] nonceKey = new long[CtJubjubFqOps.LIMBS];
        long[] generator = new long[CtJubjubPointOps.POINT_LIMBS];
        long[] projective = new long[CtJubjubPointOps.POINT_LIMBS];
        long[] normalized = new long[CtJubjubPointOps.POINT_LIMBS];
        try {
            CtJubjubNonce.deriveNonceKey(nonceKey, 0, scalar, 0, work, 0);
            requireNonZeroNonceKey(nonceKey, 0);
            CtJubjubPointOps.generator(generator, 0);
            CtJubjubPointOps.scalarMul(
                    projective, 0, generator, 0, scalar, 0, work, 0);
            CtJubjubPointOps.normalize(normalized, 0, projective, 0, work, 0);
            JubjubPoint publicKey = JubjubPublicAdapter.normalizedPoint(
                    normalized, 0, new byte[64], 0, 32, work, 0);
            return new HardenedJubjubKey(scalar, nonceKey, normalized.clone(), publicKey);
        } catch (RuntimeException | Error failure) {
            SigningScratch.wipe(scalar);
            SigningScratch.wipe(nonceKey);
            throw failure;
        } finally {
            SigningScratch.wipe(generator);
            SigningScratch.wipe(projective);
            SigningScratch.wipe(normalized);
        }
    }

    /**
     * Rejects the negligible bad-key event in which nonce-key derivation yields zero.
     * Provisioning is already permitted to fail on secret-dependent validity checks; ordinary
     * signing retains its fixed schedule.
     */
    static void requireNonZeroNonceKey(long[] candidate, int offset) {
        if (CtJubjubFqOps.zeroMask(candidate, offset) == -1L) {
            throw new IllegalStateException(
                    "derived Jubjub nonce key was zero; key was not established");
        }
    }

    static final class Lease implements AutoCloseable {
        private HardenedJubjubKey owner;
        private boolean copied;

        private Lease(HardenedJubjubKey owner) {
            this.owner = owner;
        }

        void copyInto(SigningScratch scratch) {
            Objects.requireNonNull(scratch, "scratch");
            if (owner == null) {
                throw new IllegalStateException("hardened-key lease is closed");
            }
            if (copied) {
                throw new IllegalStateException("hardened-key material already copied");
            }
            owner.copyInto(scratch);
            copied = true;
        }

        @Override
        public void close() {
            HardenedJubjubKey current = owner;
            if (current != null) {
                owner = null;
                current.release();
            }
        }
    }
}
