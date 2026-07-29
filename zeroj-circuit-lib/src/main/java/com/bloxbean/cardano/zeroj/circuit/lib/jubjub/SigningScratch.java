package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Fixed-shape, operation-owned storage for one hardened signing operation.
 *
 * <p>All offsets are public constants. No region size or allocation depends on secret data.
 * The object is never cached by a signer and is wiped on every exit path.
 */
final class SigningScratch {

    static final int SK = 0;
    static final int NONCE_KEY = SK + 4;
    static final int MESSAGE = NONCE_KEY + 4;
    static final int NONCE = MESSAGE + 4;
    static final int NONCE_CHECK = NONCE + 4;
    static final int CHALLENGE = NONCE_CHECK + 4;
    static final int SIGNATURE_SCALAR = CHALLENGE + 4;
    static final int GENERATOR = SIGNATURE_SCALAR + 4;
    static final int PUBLIC_KEY = GENERATOR + CtJubjubPointOps.POINT_LIMBS;
    static final int NONCE_POINT = PUBLIC_KEY + CtJubjubPointOps.POINT_LIMBS;
    static final int NORMALIZED_NONCE_POINT = NONCE_POINT + CtJubjubPointOps.POINT_LIMBS;
    static final int POINT_WORK =
            NORMALIZED_NONCE_POINT + CtJubjubPointOps.POINT_LIMBS;
    static final int NONCE_WORK = POINT_WORK + CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS;
    static final int FIELD_WORK = NONCE_WORK + CtJubjubNonce.WORK_LIMBS;
    static final int WORDS = FIELD_WORK + 64;

    static final int MESSAGE_BYTES = 0;
    static final int PUBLIC_U_BYTES = MESSAGE_BYTES + 32;
    static final int PUBLIC_V_BYTES = PUBLIC_U_BYTES + 32;
    static final int SCALAR_BYTES = PUBLIC_V_BYTES + 32;
    static final int BYTES = SCALAR_BYTES + 32;

    private static final VarHandle LONG_ELEMENT =
            MethodHandles.arrayElementVarHandle(long[].class);
    private static final VarHandle BYTE_ELEMENT =
            MethodHandles.arrayElementVarHandle(byte[].class);

    final long[] words = new long[WORDS];
    final byte[] auxiliary = new byte[32];
    final byte[] bytes = new byte[BYTES];

    void wipe() {
        // Volatile element stores are intentionally stronger than Arrays.fill here. They make
        // the wipe observable to the JVM and materially reduce the risk of dead-store
        // elimination. ADR-0039 still requires generated-code inspection for each supported
        // platform and does not claim perfect JVM/register erasure.
        wipe(words);
        wipe(auxiliary);
        wipe(bytes);
        VarHandle.fullFence();
    }

    static void wipe(long[] values) {
        for (int i = 0; i < values.length; i++) {
            LONG_ELEMENT.setVolatile(values, i, 0L);
        }
    }

    static void wipe(byte[] values) {
        for (int i = 0; i < values.length; i++) {
            BYTE_ELEMENT.setVolatile(values, i, (byte) 0);
        }
    }
}
