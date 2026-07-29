package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * Fixed-limb Poseidon t=3, alpha=5, RF=8, RP=57 permutation used by hardened Jubjub nonce
 * derivation. State cells are consecutive four-limb Montgomery elements.
 */
final class CtPoseidonT3 {

    static final int WIDTH = 3;
    static final int STATE_LIMBS = WIDTH * CtJubjubFqOps.LIMBS;
    static final int WORK_LIMBS = 25;
    private static final int FULL_ROUNDS = 8;
    private static final int PARTIAL_ROUNDS = 57;
    private static final int TOTAL_ROUNDS = FULL_ROUNDS + PARTIAL_ROUNDS;

    private CtPoseidonT3() {
    }

    static void permute(long[] state, int so, long[] work, int wo) {
        int next = wo;
        int x2 = wo + 12;
        int x4 = wo + 16;
        int product = wo + 20;
        int carry = wo + 24;

        for (int round = 0; round < TOTAL_ROUNDS; round++) {
            for (int cell = 0; cell < WIDTH; cell++) {
                int stateCell = so + cell * 4;
                CtPoseidonT3Constants.addRoundConstant(state, stateCell, round, cell);
            }

            boolean fullRound = round < FULL_ROUNDS / 2
                    || round >= FULL_ROUNDS / 2 + PARTIAL_ROUNDS;
            int sboxCells = fullRound ? WIDTH : 1;
            for (int cell = 0; cell < sboxCells; cell++) {
                int stateCell = so + cell * 4;
                CtJubjubFqOps.square(work, x2, state, stateCell, work, carry);
                CtJubjubFqOps.square(work, x4, work, x2, work, carry);
                CtJubjubFqOps.mul(state, stateCell, work, x4, state, stateCell,
                        work, carry);
            }

            for (int row = 0; row < WIDTH; row++) {
                int nextCell = next + row * 4;
                CtJubjubFqOps.zero(work, nextCell);
                for (int column = 0; column < WIDTH; column++) {
                    int stateCell = so + column * 4;
                    CtPoseidonT3Constants.multiplyMdsEntry(
                            work, product, row, column, state, stateCell, work, carry);
                    CtJubjubFqOps.add(work, nextCell, work, nextCell, work, product);
                }
            }
            for (int cell = 0; cell < WIDTH; cell++) {
                CtJubjubFqOps.copy(state, so + cell * 4, work, next + cell * 4);
            }
        }
    }
}
