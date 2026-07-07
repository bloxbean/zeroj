package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.lib.hash.Blake2b;

import java.util.Objects;

/**
 * Symbolic BLAKE2b adapter for annotation-based ({@code @ZKCircuit}) circuits.
 * Wraps {@link Blake2b}; {@code hash224} is the Cardano payment/stake key-hash function.
 */
public final class ZkBlake2b {

    private ZkBlake2b() {}

    /** blake2b-224 of {@code message} → 28-byte digest (Cardano key hash). */
    public static ZkBytes hash224(ZkContext zk, ZkBytes message) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(message, "message");
        return ZkBytesSupport.toZkBytes(zk, Blake2b.hash224(zk.builder().api(), ZkBytesSupport.toVariables(zk, message)));
    }

    /** blake2b-256 of {@code message} → 32-byte digest. */
    public static ZkBytes hash256(ZkContext zk, ZkBytes message) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(message, "message");
        return ZkBytesSupport.toZkBytes(zk, Blake2b.hash256(zk.builder().api(), ZkBytesSupport.toVariables(zk, message)));
    }

    /** blake2b with an explicit output length in [1,64] bytes. */
    public static ZkBytes hash(ZkContext zk, ZkBytes message, int outLenBytes) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(message, "message");
        return ZkBytesSupport.toZkBytes(zk, Blake2b.hash(zk.builder().api(), ZkBytesSupport.toVariables(zk, message), outLenBytes));
    }
}
