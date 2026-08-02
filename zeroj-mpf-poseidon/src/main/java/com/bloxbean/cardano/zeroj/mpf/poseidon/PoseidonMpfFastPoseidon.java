package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Allocation-lean host implementation of ZeroJ's BLS12-381 t=3 Poseidon fold.
 * The circuit continues to use the same generated parameters and constraints;
 * this class changes only off-chain arithmetic representation.
 */
final class PoseidonMpfFastPoseidon {
    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;
    private static final int LIMBS = FrArith381.LIMBS;
    private static final int WIDTH = 3;
    private static final long[] ROUND_CONSTANTS = montgomery(PARAMS.c());
    private static final long[] MDS = montgomery(PARAMS.m());
    private static final ThreadLocal<Workspace> WORKSPACES = ThreadLocal.withInitial(Workspace::new);

    private PoseidonMpfFastPoseidon() {}

    static BigInteger hashN(BigInteger... inputs) {
        Objects.requireNonNull(inputs, "inputs");
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");

        Workspace workspace = WORKSPACES.get();
        long[] left = workspace.left;
        long[] right = workspace.right;
        long[] accumulator = workspace.accumulator;
        long[] state = workspace.state;
        long[] next = workspace.next;
        long[] scratch = workspace.scratch;

        toMontgomery(inputs[0], left, 0);
        if (inputs.length == 1) {
            Arrays.fill(right, 0L);
            permutePair(left, right, accumulator, state, next, scratch);
            return fromMontgomery(accumulator);
        }

        toMontgomery(inputs[1], right, 0);
        permutePair(left, right, accumulator, state, next, scratch);
        for (int i = 2; i < inputs.length; i++) {
            toMontgomery(inputs[i], right, 0);
            permutePair(accumulator, right, accumulator, state, next, scratch);
        }
        return fromMontgomery(accumulator);
    }

    private static void permutePair(
            long[] left,
            long[] right,
            long[] output,
            long[] stateBuffer,
            long[] nextBuffer,
            long[] scratch) {
        long[] state = stateBuffer;
        long[] next = nextBuffer;
        Arrays.fill(state, 0L);
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

            boolean full = round < fullRounds / 2 || round >= fullRounds / 2 + partialRounds;
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
        long[] out = new long[values.length * LIMBS];
        for (int i = 0; i < values.length; i++) {
            long[] limbs = MontFr381.fromBigInteger(values[i]).toLimbs();
            System.arraycopy(limbs, 0, out, i * LIMBS, LIMBS);
        }
        return out;
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
        private final long[] left = new long[LIMBS];
        private final long[] right = new long[LIMBS];
        private final long[] accumulator = new long[LIMBS];
        private final long[] state = new long[WIDTH * LIMBS];
        private final long[] next = new long[WIDTH * LIMBS];
        private final long[] scratch = new long[LIMBS * 2];
    }
}
