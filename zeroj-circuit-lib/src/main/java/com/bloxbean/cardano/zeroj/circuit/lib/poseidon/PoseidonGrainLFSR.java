package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import java.math.BigInteger;

/**
 * Java port of the authoritative Poseidon parameter generator from the
 * Poseidon paper (Grassi et al., 2021), Sage reference implementation:
 * {@code generate_parameters_grain.sage} in the IAIK hadeshash repository,
 * pinned commit {@code 208b5a164c6a252b137997694d90931b2bb851c5} (2023-05-02).
 * See {@code src/main/resources/poseidon/} for the pinned Sage script and
 * reproduction instructions.
 *
 * <p>This class is intentionally a direct, line-by-line port of the Sage
 * script for verifiability. Outputs must match the Sage script byte-for-byte
 * for equivalent parameter inputs. Correctness is enforced by a cross-check
 * test against the known circomlibjs BN254 t=3 constants already shipped in
 * {@code PoseidonConstants} — those were themselves produced by running this
 * Sage script with the BN254 arguments.
 *
 * <p>Currently supports GF(p) with S-box {@code x^alpha}. GF(2^n) and
 * {@code x^{-1}} S-box are not implemented (not needed by any ZeroJ target).
 *
 * <p>The Poseidon paper's MDS security Algorithms 1, 2, 3 are not ported: for
 * every parameter set ZeroJ targets (BN254 t=3, BLS12-381 t=3 and t=5 with
 * standard RF/RP), the first-generated Cauchy matrix passes all three
 * algorithms, verified empirically by cross-checking against published
 * reference implementations. Should a future target require retries, those
 * algorithms would need to be added.
 */
public final class PoseidonGrainLFSR {

    /** Fixed LFSR register size, per Poseidon paper §5.1. */
    private static final int REG_SIZE = 80;

    /** Number of warm-up steps before the generator starts emitting bits. */
    private static final int WARMUP = 160;

    /** FIELD field value for GF(p) (the only kind supported). Used in init. */
    private static final int FIELD_KIND_GFP = 1;

    /** SBOX field value for x^α S-box (the only kind supported). Used in init. */
    private static final int SBOX_X_ALPHA = 0;

    /**
     * Accept-list of {@code (fieldSize, t, rf, rp, primeHex)} tuples for which
     * the first-sampled Cauchy MDS matrix has been empirically verified to pass
     * the Poseidon paper's Algorithms 1/2/3 (so skipping them in Java is safe).
     * See class-level Javadoc and ADR-0015 for details.
     */
    private static final java.util.Set<String> VETTED_PARAMS = java.util.Set.of(
            // BN254 t=3 α=5 RF=8 RP=57 — verified against iden3/circomlibjs constants.
            "254|3|8|57|0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
            // BLS12-381 t=3 α=5 RF=8 RP=57 — verified via Sage script cross-check.
            "255|3|8|57|0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
    );

    /** Field size in bits (n): 254 for BN254, 255 for BLS12-381. */
    private final int fieldSize;
    /** State width t (number of cells). */
    private final int t;
    /** Full rounds (typically 8). */
    private final int rf;
    /** Partial rounds. */
    private final int rp;
    /** Scalar field prime modulus. */
    private final BigInteger prime;

    /** 80-bit LFSR register, as a circular buffer. */
    private final int[] register = new int[REG_SIZE];
    /** Head index: array position of LFSR logical position 0. */
    private int head;

    private PoseidonGrainLFSR(int fieldSize, int t, int rf, int rp, BigInteger prime) {
        this.fieldSize = fieldSize;
        this.t = t;
        this.rf = rf;
        this.rp = rp;
        this.prime = prime;
        initRegister();
        warmup();
    }

    /**
     * Creates a generator for Poseidon parameters over {@code GF(p)} with
     * {@code x^alpha} S-box. The tuple {@code (fieldSize, t, rf, rp, prime)}
     * must appear in {@link #VETTED_PARAMS}: skipping the MDS security
     * algorithms is only safe for parameter combinations we've empirically
     * verified produce a secure first-pass matrix.
     *
     * @param fieldSize bit-length {@code n} of the scalar field (254 for BN254, 255 for BLS12-381)
     * @param t         state width (e.g. 3 for two-to-one hash)
     * @param rf        full rounds (typically 8)
     * @param rp        partial rounds
     * @param prime     scalar field modulus
     * @throws UnsupportedOperationException for parameter tuples outside the accept-list
     */
    public static PoseidonGrainLFSR forGFp(int fieldSize, int t, int rf, int rp, BigInteger prime) {
        String key = fieldSize + "|" + t + "|" + rf + "|" + rp + "|0x" + prime.toString(16);
        if (!VETTED_PARAMS.contains(key)) {
            throw new UnsupportedOperationException(
                    "Parameter tuple not on ZeroJ's vetted list (MDS security algorithms 1/2/3 "
                            + "are not ported; first-pass Cauchy matrix is only trusted for "
                            + "explicitly vetted tuples). Requested: " + key + ". "
                            + "Adding a new tuple requires running the hadeshash Sage script "
                            + "to confirm first-pass acceptance and updating VETTED_PARAMS + ADR-0015.");
        }
        return new PoseidonGrainLFSR(fieldSize, t, rf, rp, prime);
    }

    /**
     * Populates {@link #register} with the initial 80-bit sequence from the
     * concatenation of parameter bit-fields, exactly as {@code init_generator}
     * in the Sage script:
     *
     * <pre>
     *   FIELD  (2 bits)  | SBOX  (4 bits)  | n (12 bits) | t (12 bits)
     *   R_F (10 bits)    | R_P (10 bits)   | 30 ones
     * </pre>
     *
     * All fields are zero-left-padded to their designated widths. The leftmost
     * bit of each field (its MSB) is placed at the lowest LFSR position; thus
     * logical position 0 is the MSB of {@code FIELD}.
     */
    private void initRegister() {
        int pos = 0;
        pos = appendBits(pos, FIELD_KIND_GFP, 2);
        pos = appendBits(pos, SBOX_X_ALPHA, 4);
        pos = appendBits(pos, fieldSize, 12);
        pos = appendBits(pos, t, 12);
        pos = appendBits(pos, rf, 10);
        pos = appendBits(pos, rp, 10);
        for (int i = 0; i < 30; i++) {
            register[pos++] = 1;
        }
        if (pos != REG_SIZE) {
            throw new IllegalStateException("Init sequence length != " + REG_SIZE + " (got " + pos + ")");
        }
        this.head = 0;
    }

    /**
     * Writes {@code width} bits of {@code value} into {@link #register} starting
     * at {@code pos}, MSB-first. Returns the next write position. {@code value}
     * must fit in {@code width} bits; no overflow check is performed (all call
     * sites pass values that fit by construction — widths are at most 12).
     */
    private int appendBits(int pos, int value, int width) {
        for (int i = width - 1; i >= 0; i--) {
            register[pos++] = (value >>> i) & 1;
        }
        return pos;
    }

    /** Runs {@link #WARMUP} LFSR steps whose outputs are discarded. */
    private void warmup() {
        for (int i = 0; i < WARMUP; i++) {
            stepRaw();
        }
    }

    /**
     * Advances the LFSR one step and returns the new feedback bit. Mirrors:
     * <pre>
     *   new_bit = bit_sequence[62] XOR bit_sequence[51] XOR bit_sequence[38]
     *           XOR bit_sequence[23] XOR bit_sequence[13] XOR bit_sequence[0]
     *   bit_sequence.pop(0); bit_sequence.append(new_bit)
     * </pre>
     */
    private int stepRaw() {
        int b0  = register[head];
        int b13 = register[(head + 13) % REG_SIZE];
        int b23 = register[(head + 23) % REG_SIZE];
        int b38 = register[(head + 38) % REG_SIZE];
        int b51 = register[(head + 51) % REG_SIZE];
        int b62 = register[(head + 62) % REG_SIZE];
        int newBit = b0 ^ b13 ^ b23 ^ b38 ^ b51 ^ b62;
        // pop(0) + append(newBit): overwrite old position-0 slot, advance head.
        register[head] = newBit;
        head = (head + 1) % REG_SIZE;
        return newBit;
    }

    /**
     * Produces one output bit using the self-shrinking generator rule from the
     * Sage script. For each yielded bit, two raw LFSR bits are consumed; if
     * the first is zero, the second is discarded and another pair is tried.
     */
    public int nextBit() {
        int first = stepRaw();
        while (first == 0) {
            stepRaw();          // discard paired second bit
            first = stepRaw();  // new "first" of next pair
        }
        return stepRaw();       // yield the second bit of the winning pair
    }

    /**
     * Produces a non-negative integer of exactly {@code numBits} bits by
     * concatenating LFSR output bits MSB-first (first-generated bit is the
     * most significant). Mirrors {@code grain_random_bits} in the Sage script.
     */
    public BigInteger nextNBitInteger(int numBits) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < numBits; i++) {
            result = result.shiftLeft(1);
            if (nextBit() == 1) {
                result = result.or(BigInteger.ONE);
            }
        }
        return result;
    }

    /**
     * Generates all {@code (RF + RP) * t} round constants, rejection-sampling
     * until each value is in {@code [0, prime)}. Mirrors
     * {@code generate_constants} in the Sage script for the GF(p) branch.
     */
    public BigInteger[] generateRoundConstants() {
        int num = (rf + rp) * t;
        BigInteger[] constants = new BigInteger[num];
        for (int i = 0; i < num; i++) {
            BigInteger v = nextNBitInteger(fieldSize);
            while (v.compareTo(prime) >= 0) {
                v = nextNBitInteger(fieldSize);
            }
            constants[i] = v;
        }
        return constants;
    }

    /**
     * Generates a {@code t x t} Cauchy MDS matrix as {@code create_mds_p} in
     * the Sage script does. Samples {@code 2t} distinct field elements
     * {@code [x_1..x_t, y_1..y_t]} (resampling all on any duplicate, where
     * equality is taken modulo {@code prime}) and sets
     * {@code M[i][j] = (x_i + y_j)^{-1} (mod prime)}. If any {@code x_i + y_j}
     * is zero, the entire outer sampling loop restarts.
     *
     * <p><b>Note</b>: the Sage script wraps this in an outer
     * {@code generate_matrix} that runs Algorithms 1/2/3 and resamples on
     * security rejection. Those algorithms are not ported here — see the
     * class-level Javadoc for the justification and limits.
     *
     * @return a row-major {@code t x t} matrix of field elements
     */
    public BigInteger[][] generateMdsMatrix() {
        while (true) {
            BigInteger[] rand = sampleDistinctFieldElements(2 * t);
            BigInteger[] xs = new BigInteger[t];
            BigInteger[] ys = new BigInteger[t];
            System.arraycopy(rand, 0, xs, 0, t);
            System.arraycopy(rand, t, ys, 0, t);

            BigInteger[][] m = new BigInteger[t][t];
            boolean hadZeroSum = false;
            // IMPORTANT: do NOT break on hadZeroSum. The Sage script
            // (create_mds_p) also continues iterating once its flag is false —
            // see comments there: after setting flag=False, the inner loops
            // still execute the "else" branch-skip. Since neither Sage nor
            // this port advances the LFSR inside the matrix construction, an
            // early break would be observationally identical *today*, but
            // could diverge if the inner body ever gains a grain_random_bits
            // call (or a future Sage update changes semantics). Keep the
            // structural mirror to Sage so any such change is caught by the
            // regression tests rather than silently drifting.
            for (int i = 0; i < t; i++) {
                for (int j = 0; j < t; j++) {
                    BigInteger sum = xs[i].add(ys[j]).mod(prime);
                    if (sum.signum() == 0) {
                        hadZeroSum = true;
                    } else if (!hadZeroSum) {
                        m[i][j] = sum.modInverse(prime);
                    }
                }
            }
            if (!hadZeroSum) {
                return m;
            }
            // Outer while retries by drawing fresh samples — matches Sage's
            // `continue` after `flag == False`.
        }
    }

    /**
     * Draws {@code count} field elements (each reduced mod {@code prime})
     * whose field-sense values are pairwise distinct. Matches the Sage
     * behavior: on any duplicate, resample the entire list (not just the
     * duplicate) so the LFSR state advances identically.
     */
    private BigInteger[] sampleDistinctFieldElements(int count) {
        BigInteger[] rand = new BigInteger[count];
        drawAll(rand);
        while (hasDuplicates(rand)) {
            drawAll(rand);
        }
        return rand;
    }

    private void drawAll(BigInteger[] buf) {
        for (int i = 0; i < buf.length; i++) {
            buf[i] = nextNBitInteger(fieldSize).mod(prime);
        }
    }

    private static boolean hasDuplicates(BigInteger[] arr) {
        for (int i = 0; i < arr.length; i++) {
            for (int j = i + 1; j < arr.length; j++) {
                if (arr[i].equals(arr[j])) {
                    return true;
                }
            }
        }
        return false;
    }
}
