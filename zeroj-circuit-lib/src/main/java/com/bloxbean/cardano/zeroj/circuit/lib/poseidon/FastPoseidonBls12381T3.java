package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Allocation-lean host implementation of ZeroJ's BLS12-381 {@code t=3}
 * Poseidon permutation.
 *
 * <p>This is a host-side optimization only. It uses the exact constants and
 * left-fold/sponge conventions defined by {@link PoseidonHash} and
 * {@link PoseidonParamsBLS12_381T3}. Per-thread workspaces avoid sharing
 * mutable arithmetic buffers between concurrent tree builders.
 */
public final class FastPoseidonBls12381T3 {
    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;
    private static final int LIMBS = FrArith381.LIMBS;
    private static final int WIDTH = 3;
    private static final long[] ZERO = new long[LIMBS];
    private static final long[] ROUND_CONSTANTS = montgomery(PARAMS.c());
    private static final long[] MDS = montgomery(PARAMS.m());
    private static final ThreadLocal<Workspace> WORKSPACES = ThreadLocal.withInitial(Workspace::new);

    private FastPoseidonBls12381T3() {}

    /** Matches {@link PoseidonHash#hashN(PoseidonParams, BigInteger...)} exactly. */
    public static BigInteger hashN(BigInteger... inputs) {
        Objects.requireNonNull(inputs, "inputs");
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");

        Workspace workspace = WORKSPACES.get();
        toMontgomery(inputs[0], workspace.left, 0);
        if (inputs.length == 1) {
            permuteMontgomery(ZERO, workspace.left, ZERO, workspace.accumulator, workspace);
            return fromMontgomery(workspace.accumulator);
        }

        toMontgomery(inputs[1], workspace.right, 0);
        permuteMontgomery(ZERO, workspace.left, workspace.right, workspace.accumulator, workspace);
        for (int index = 2; index < inputs.length; index++) {
            toMontgomery(inputs[index], workspace.right, 0);
            permuteMontgomery(
                    ZERO, workspace.accumulator, workspace.right, workspace.accumulator, workspace);
        }
        return fromMontgomery(workspace.accumulator);
    }

    /**
     * Matches the full-rate {@link PoseidonHash#spongeHash} convention for
     * BLS12-381 {@code t=3}: {@code Permute([capacity,left,right])[0]}.
     */
    public static BigInteger spongeHash(
            BigInteger capacity, BigInteger left, BigInteger right) {
        Workspace workspace = WORKSPACES.get();
        toMontgomery(capacity, workspace.capacity, 0);
        toMontgomery(left, workspace.left, 0);
        toMontgomery(right, workspace.right, 0);
        permuteMontgomery(
                workspace.capacity, workspace.left, workspace.right,
                workspace.accumulator, workspace);
        return fromMontgomery(workspace.accumulator);
    }

    private static void permuteMontgomery(
            long[] capacity,
            long[] left,
            long[] right,
            long[] output,
            Workspace workspace) {
        long[] state = workspace.state;
        long[] next = workspace.next;
        long[] scratch = workspace.scratch;
        FrArith381.copy(state, 0, capacity, 0);
        FrArith381.copy(state, LIMBS, left, 0);
        FrArith381.copy(state, LIMBS * 2, right, 0);

        int fullRounds = PARAMS.rf();
        int partialRounds = PARAMS.rp();
        int totalRounds = fullRounds + partialRounds;
        for (int round = 0; round < totalRounds; round++) {
            int constantsOffset = round * WIDTH * LIMBS;
            for (int cell = 0; cell < WIDTH; cell++) {
                int offset = cell * LIMBS;
                FrArith381.add(state, offset, state, offset,
                        ROUND_CONSTANTS, constantsOffset + offset);
            }

            boolean full = round < fullRounds / 2
                    || round >= fullRounds / 2 + partialRounds;
            sbox(state, 0, scratch);
            if (full) {
                sbox(state, LIMBS, scratch);
                sbox(state, LIMBS * 2, scratch);
            }

            for (int row = 0; row < WIDTH; row++) {
                int out = row * LIMBS;
                int matrix = row * WIDTH * LIMBS;
                FrArith381.mul(next, out, MDS, matrix, state, 0);
                FrArith381.mul(scratch, 0, MDS, matrix + LIMBS, state, LIMBS);
                FrArith381.add(next, out, next, out, scratch, 0);
                FrArith381.mul(scratch, 0, MDS, matrix + LIMBS * 2, state, LIMBS * 2);
                FrArith381.add(next, out, next, out, scratch, 0);
            }

            long[] swap = state;
            state = next;
            next = swap;
        }
        FrArith381.copy(output, 0, state, 0);
    }

    private static void sbox(long[] state, int offset, long[] scratch) {
        // x^5 = (x^2)^2 * x. FrArith operations permit output/input aliasing.
        FrArith381.sqr(scratch, 0, state, offset);
        FrArith381.sqr(scratch, LIMBS, scratch, 0);
        FrArith381.mul(state, offset, scratch, LIMBS, state, offset);
    }

    private static long[] montgomery(BigInteger[] values) {
        long[] output = new long[values.length * LIMBS];
        for (int index = 0; index < values.length; index++) {
            long[] limbs = MontFr381.fromBigInteger(values[index]).toLimbs();
            System.arraycopy(limbs, 0, output, index * LIMBS, LIMBS);
        }
        return output;
    }

    private static void toMontgomery(BigInteger value, long[] destination, int offset) {
        Objects.requireNonNull(value, "Poseidon input");
        long[] limbs = MontFr381.fromBigInteger(value).toLimbs();
        System.arraycopy(limbs, 0, destination, offset, LIMBS);
    }

    private static BigInteger fromMontgomery(long[] value) {
        return MontFr381.fromMontLimbs(value[0], value[1], value[2], value[3]).toBigInteger();
    }

    private static final class Workspace {
        private final long[] capacity = new long[LIMBS];
        private final long[] left = new long[LIMBS];
        private final long[] right = new long[LIMBS];
        private final long[] accumulator = new long[LIMBS];
        private final long[] state = new long[WIDTH * LIMBS];
        private final long[] next = new long[WIDTH * LIMBS];
        private final long[] scratch = new long[LIMBS * 2];
    }
}
