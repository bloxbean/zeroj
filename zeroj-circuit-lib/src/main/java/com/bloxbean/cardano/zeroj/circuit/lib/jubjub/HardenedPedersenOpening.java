package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.util.Objects;

/**
 * Internal mutable secret opening for the fixed-limb Pedersen-generation candidate.
 *
 * <p>The committed integer and blinding are imported with explicit unsigned widths up to
 * 256 bits and stored as residues modulo {@code l}, matching the commitment's algebraic
 * semantics. Applications that need integer binding must separately enforce their intended
 * range. The type has no secret accessor, value equality, hash code, or serialization support.
 *
 * <p>A uniformly random blinding residue is required for hiding. This factory only imports
 * caller-provided material; it does not claim its entropy or provenance.
 *
 * <p>The class remains package-private until the separate M9 timing, platform, and external
 * review gates pass.
 */
final class HardenedPedersenOpening implements AutoCloseable {

    private enum State {
        OPEN,
        CLOSING,
        CLOSED
    }

    private final Object lifecycle = new Object();
    private final long[] value;
    private final long[] blinding;
    private final int valueBits;
    private final int blindingBits;
    private State state = State.OPEN;
    private int activeOperations;

    private HardenedPedersenOpening(long[] value, int valueBits,
                                    long[] blinding, int blindingBits) {
        this.value = value;
        this.valueBits = valueBits;
        this.blinding = blinding;
        this.blindingBits = blindingBits;
    }

    /**
     * Imports unsigned big-endian values at their declared widths and stores each modulo
     * {@code l}. The array length must be exactly {@code ceil(bits/8)}, and unused high bits
     * must be zero.
     */
    static HardenedPedersenOpening fromUnsigned(
            byte[] value, int valueBits,
            byte[] blinding, int blindingBits) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        requireEncodingLength(value, valueBits, "value");
        requireEncodingLength(blinding, blindingBits, "blinding");

        byte[] valuePadded = leftPad(value);
        byte[] blindingPadded = leftPad(blinding);
        long[] valueScalar = new long[4];
        long[] blindingScalar = new long[4];
        long[] work = new long[16];
        try {
            long valueWidth = CtJubjubFrOps.fromUnsigned256Reduced(
                    valueScalar, 0, valuePadded, 0, valueBits, work, 0);
            long blindingWidth = CtJubjubFrOps.fromUnsigned256Reduced(
                    blindingScalar, 0, blindingPadded, 0, blindingBits, work, 0);
            if ((valueWidth & blindingWidth) != -1L) {
                throw new IllegalArgumentException(
                        "Pedersen opening has nonzero bits above its declared width");
            }
            return new HardenedPedersenOpening(
                    valueScalar.clone(), valueBits,
                    blindingScalar.clone(), blindingBits);
        } finally {
            SigningScratch.wipe(valuePadded);
            SigningScratch.wipe(blindingPadded);
            SigningScratch.wipe(valueScalar);
            SigningScratch.wipe(blindingScalar);
            SigningScratch.wipe(work);
        }
    }

    /** Returns the declared application width; it is metadata, not the secret value. */
    public int valueBits() {
        return valueBits;
    }

    /** Returns the declared blinding input width; it is metadata, not the secret value. */
    public int blindingBits() {
        return blindingBits;
    }

    /** Returns whether destruction has completed. */
    public boolean isClosed() {
        synchronized (lifecycle) {
            return state == State.CLOSED;
        }
    }

    Lease admit() {
        synchronized (lifecycle) {
            if (state != State.OPEN) {
                throw new IllegalStateException("hardened Pedersen opening is closing or closed");
            }
            activeOperations++;
            return new Lease(this);
        }
    }

    private void copyInto(PedersenScratch scratch) {
        synchronized (lifecycle) {
            if (activeOperations <= 0 || state == State.CLOSED) {
                throw new IllegalStateException("invalid Pedersen-opening operation lease");
            }
            CtJubjubFrOps.copy(scratch.words, PedersenScratch.VALUE, value, 0);
            CtJubjubFrOps.copy(scratch.words, PedersenScratch.BLINDING, blinding, 0);
        }
    }

    private void release() {
        synchronized (lifecycle) {
            if (activeOperations <= 0) {
                throw new IllegalStateException("Pedersen-opening lease released twice");
            }
            activeOperations--;
            if (activeOperations == 0) {
                lifecycle.notifyAll();
            }
        }
    }

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
            SigningScratch.wipe(value);
            SigningScratch.wipe(blinding);
            state = State.CLOSED;
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public String toString() {
        return "HardenedPedersenOpening[value=<redacted>, blinding=<redacted>, "
                + "valueBits=" + valueBits + ", blindingBits=" + blindingBits + "]";
    }

    private static void requireEncodingLength(byte[] encoded, int bits, String name) {
        if (bits < 1 || bits > 256) {
            throw new IllegalArgumentException(name + "Bits must be in [1,256]");
        }
        int expected = (bits + 7) >>> 3;
        if (encoded.length != expected) {
            throw new IllegalArgumentException(
                    name + " must contain exactly ceil(" + name + "Bits/8) = "
                            + expected + " bytes");
        }
    }

    private static byte[] leftPad(byte[] input) {
        byte[] padded = new byte[32];
        System.arraycopy(input, 0, padded, padded.length - input.length, input.length);
        return padded;
    }

    static final class Lease implements AutoCloseable {
        private HardenedPedersenOpening owner;
        private boolean copied;

        private Lease(HardenedPedersenOpening owner) {
            this.owner = owner;
        }

        void copyInto(PedersenScratch scratch) {
            Objects.requireNonNull(scratch, "scratch");
            if (owner == null) {
                throw new IllegalStateException("Pedersen-opening lease is closed");
            }
            if (copied) {
                throw new IllegalStateException("Pedersen opening was already copied");
            }
            owner.copyInto(scratch);
            copied = true;
        }

        @Override
        public void close() {
            HardenedPedersenOpening current = owner;
            if (current != null) {
                owner = null;
                current.release();
            }
        }
    }
}
