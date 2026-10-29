package org.zeroj.bls12381;

import java.util.Objects;

/**
 * SHAKE128 (FIPS 202 §6.2) as an incremental, copyable extendable-output function: the
 * {@code XOF.New / Update / Copy / Finalize / Read} interface of {@code draft-irtf-cfrg-fiat-shamir-03}
 * §3.2, with rate {@value #RATE} octets (§9.1). It runs on the Keccak-f[1600] permutation that
 * {@link Bls12381Hash} uses for SHAKE256.
 *
 * <p>An instance starts absorbing. The first {@link #squeeze} finalizes it (pad {@code 0x1F ‖ … ‖
 * 0x80}) and every later squeeze continues the same output stream; absorbing after that is an
 * {@link IllegalStateException}. {@link #copy()} snapshots the state in either phase.
 *
 * <p>The permutation's operation sequence does not depend on the data. Instances are not
 * thread-safe.
 */
public final class Shake128 {

    /** The rate in octets: {@code (1600 − 2·128) / 8}. */
    public static final int RATE = 168;

    private static final long DOMAIN_PAD = 0x1FL;
    private static final long FINAL_BIT = 0x80L;

    private final long[] state;
    // Octet position within the current rate block: the next octet absorbed, or squeezed.
    private int position;
    private boolean squeezing;

    /** A fresh state (the empty message). */
    public Shake128() {
        this.state = new long[25];
    }

    private Shake128(Shake128 other) {
        this.state = other.state.clone();
        this.position = other.position;
        this.squeezing = other.squeezing;
    }

    /**
     * Absorbs all of {@code data}.
     *
     * @throws NullPointerException  if {@code data} is null
     * @throws IllegalStateException if this state has already been squeezed
     */
    public void update(byte[] data) {
        Objects.requireNonNull(data, "data");
        update(data, 0, data.length);
    }

    /**
     * Absorbs {@code length} octets of {@code data} from {@code offset}.
     *
     * @throws NullPointerException      if {@code data} is null
     * @throws IndexOutOfBoundsException if the range is outside {@code data}
     * @throws IllegalStateException     if this state has already been squeezed
     */
    public void update(byte[] data, int offset, int length) {
        Objects.requireNonNull(data, "data");
        Objects.checkFromIndexSize(offset, length, data.length);
        if (squeezing) {
            throw new IllegalStateException("SHAKE128 state is already squeezing");
        }
        for (int i = 0; i < length; i++) {
            state[position >>> 3] ^= (data[offset + i] & 0xFFL) << (8 * (position & 7));
            if (++position == RATE) {
                Bls12381Hash.keccakF1600(state);
                position = 0;
            }
        }
    }

    /** An independent copy of this state, in the same phase. */
    public Shake128 copy() {
        return new Shake128(this);
    }

    /**
     * The next {@code length} octets of the output stream. The first call finalizes the state.
     *
     * @throws IllegalArgumentException if {@code length} is negative
     */
    public byte[] squeeze(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("squeeze length must be non-negative");
        }
        byte[] out = new byte[length];
        squeeze(out, 0, length);
        return out;
    }

    /**
     * Writes the next {@code length} octets of the output stream into {@code out} at {@code offset}.
     * The first call finalizes the state.
     *
     * @throws NullPointerException      if {@code out} is null
     * @throws IndexOutOfBoundsException if the range is outside {@code out}
     */
    public void squeeze(byte[] out, int offset, int length) {
        Objects.requireNonNull(out, "out");
        Objects.checkFromIndexSize(offset, length, out.length);
        if (!squeezing) {
            finish();
        }
        for (int i = 0; i < length; i++) {
            if (position == RATE) {
                Bls12381Hash.keccakF1600(state);
                position = 0;
            }
            out[offset + i] = (byte) (state[position >>> 3] >>> (8 * (position & 7)));
            position++;
        }
    }

    private void finish() {
        // FIPS 202 §6.2 and §5.1: SHAKE's 1111 domain suffix, then pad10*1, in the last block.
        state[position >>> 3] ^= DOMAIN_PAD << (8 * (position & 7));
        state[(RATE - 1) >>> 3] ^= FINAL_BIT << (8 * ((RATE - 1) & 7));
        Bls12381Hash.keccakF1600(state);
        position = 0;
        squeezing = true;
    }
}
