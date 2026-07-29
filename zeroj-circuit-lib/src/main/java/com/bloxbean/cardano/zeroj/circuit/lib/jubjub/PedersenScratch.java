package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/** Fixed-shape operation-owned storage for one hardened Pedersen generation. */
final class PedersenScratch {

    static final int VALUE = 0;
    static final int BLINDING = VALUE + 4;
    static final int GENERATOR = BLINDING + 4;
    static final int H = GENERATOR + CtJubjubPointOps.POINT_LIMBS;
    static final int VALUE_POINT = H + CtJubjubPointOps.POINT_LIMBS;
    static final int BLINDING_POINT = VALUE_POINT + CtJubjubPointOps.POINT_LIMBS;
    static final int SUM = BLINDING_POINT + CtJubjubPointOps.POINT_LIMBS;
    static final int NORMALIZED = SUM + CtJubjubPointOps.POINT_LIMBS;
    static final int POINT_WORK = NORMALIZED + CtJubjubPointOps.POINT_LIMBS;
    static final int CHECK_WORK = POINT_WORK + CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS;
    static final int WORDS = CHECK_WORK + 48;

    final long[] words = new long[WORDS];
    final byte[] publicCoordinates = new byte[64];

    void wipe() {
        SigningScratch.wipe(words);
        // Coordinates are public after candidate completion, but wiping keeps every exit path
        // and future extension mechanically uniform.
        SigningScratch.wipe(publicCoordinates);
    }
}
