package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.lib.hash.Sha512;

import java.util.Objects;

/**
 * Symbolic SHA-512 adapter for annotation-based ({@code @ZKCircuit}) circuits.
 * Wraps {@link Sha512} so a {@link ZkBytes} message hashes to a 64-byte {@link ZkBytes} digest.
 */
public final class ZkSha512 {

    private ZkSha512() {}

    /** SHA-512 of {@code message} → 64-byte digest. */
    public static ZkBytes hash(ZkContext zk, ZkBytes message) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(message, "message");
        return ZkBytesSupport.toZkBytes(zk, Sha512.hashBytes(zk.builder().api(), ZkBytesSupport.toVariables(zk, message)));
    }
}
