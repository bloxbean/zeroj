package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * Fixed-limb nonce derivation primitives. Deterministic-v1 exactly reproduces the existing
 * suite; hedged-v1 is the externally-review-gated candidate specified by ADR-0039 M4.
 */
final class CtJubjubNonce {

    static final int WORK_LIMBS = 64;

    private static final long[] V1_NONCE_TAG = {
            0x93b2db90e63e7568L, 0x9fc87d3bf54e2fa3L,
            0xdbf71a349a26282dL, 0x3c80e2dd9134aa1fL
    };
    private static final long[] HEDGED_NONCE_KEY_TAG = {
            0xbfe975512c907406L, 0x4e84d61cb2f40e32L,
            0xcbea17488c67a823L, 0x1953aec8364592d0L
    };
    private static final long[] HEDGED_NONCE_TAG = {
            0x4b5ed756d1330ca5L, 0x20010a16c8c0899bL,
            0xe6a4e7a648be9308L, 0x03db0e75f7756178L
    };

    private CtJubjubNonce() {
    }

    /**
     * {@code r = Poseidon_t3(V1_NONCE_TAG; sk,msg) mod l}.
     */
    static void deterministicV1(long[] outFr, int oo,
                                long[] secretFr, int so,
                                long[] messageFq, int mo,
                                long[] work, int wo) {
        int state = wo;
        int normalSecret = wo + 12;
        int poseidonWork = wo + 16;
        CtJubjubFqOps.copy(work, state, V1_NONCE_TAG, 0);
        CtJubjubFrOps.toNormal(work, normalSecret, secretFr, so, work, poseidonWork);
        CtJubjubFqOps.fromNormal(
                work, state + 4, work, normalSecret, work, poseidonWork);
        CtJubjubFqOps.copy(work, state + 8, messageFq, mo);
        CtPoseidonT3.permute(work, state, work, poseidonWork);
        CtJubjubFrOps.reduceFromFq(outFr, oo, work, state, work, normalSecret);
    }

    /**
     * Derives the persistent secret nonce key as
     * {@code Poseidon_t3(HEDGED_NONCE_KEY_TAG; sk,0)}.
     */
    static void deriveNonceKey(long[] outFq, int oo,
                               long[] secretFr, int so,
                               long[] work, int wo) {
        int state = wo;
        int normalSecret = wo + 12;
        int poseidonWork = wo + 16;
        CtJubjubFqOps.copy(work, state, HEDGED_NONCE_KEY_TAG, 0);
        CtJubjubFrOps.toNormal(work, normalSecret, secretFr, so, work, poseidonWork);
        CtJubjubFqOps.fromNormal(
                work, state + 4, work, normalSecret, work, poseidonWork);
        CtJubjubFqOps.zero(work, state + 8);
        CtPoseidonT3.permute(work, state, work, poseidonWork);
        CtJubjubFqOps.copy(outFq, oo, work, state);
    }

    /**
     * Fixed-arity hedged candidate transcript:
     *
     * <pre>
     * state = (HEDGED_NONCE_TAG, 0, 0)
     * state[1..2] += (nonceKey, msg);  state = P(state)
     * state[1..2] += (pk.u, pk.v);     state = P(state)
     * state[1..2] += (aux[0..15], aux[16..31]); state = P(state)
     * r = (state[0] mod (l-1)) + 1
     * </pre>
     *
     * The two auxiliary halves are unsigned 128-bit big-endian field elements, making the
     * 32-byte encoding injective without a reduction. {@code publicKeyPoint} must be the
     * canonical normalized extended representation {@code (u,v,1,u*v)}. Hashing raw
     * projective {@code U,V} coordinates would make the nonce depend on the representative
     * rather than the public key.
     */
    static void hedgedV1(long[] outFr, int oo,
                         long[] nonceKeyFq, int no,
                         long[] publicKeyPoint, int po,
                         long[] messageFq, int mo,
                         byte[] auxiliary, int ao,
                         long[] work, int wo) {
        int state = wo;
        int auxHigh = wo + 12;
        int auxLow = wo + 16;
        int importWork = wo + 20;
        int poseidonWork = wo + 25;

        CtJubjubFqOps.copy(work, state, HEDGED_NONCE_TAG, 0);
        CtJubjubFqOps.zero(work, state + 4);
        CtJubjubFqOps.zero(work, state + 8);

        CtJubjubFqOps.add(work, state + 4, work, state + 4, nonceKeyFq, no);
        CtJubjubFqOps.add(work, state + 8, work, state + 8, messageFq, mo);
        CtPoseidonT3.permute(work, state, work, poseidonWork);

        CtJubjubFqOps.add(work, state + 4, work, state + 4,
                publicKeyPoint, po + CtJubjubPointOps.U);
        CtJubjubFqOps.add(work, state + 8, work, state + 8,
                publicKeyPoint, po + CtJubjubPointOps.V);
        CtPoseidonT3.permute(work, state, work, poseidonWork);

        CtJubjubFqOps.fromUnsigned128(
                work, auxHigh, auxiliary, ao, work, importWork);
        CtJubjubFqOps.fromUnsigned128(
                work, auxLow, auxiliary, ao + 16, work, importWork);
        CtJubjubFqOps.add(work, state + 4, work, state + 4, work, auxHigh);
        CtJubjubFqOps.add(work, state + 8, work, state + 8, work, auxLow);
        CtPoseidonT3.permute(work, state, work, poseidonWork);

        CtJubjubFrOps.mapFromFqNonZero(outFr, oo, work, state, work, auxHigh);
    }
}
