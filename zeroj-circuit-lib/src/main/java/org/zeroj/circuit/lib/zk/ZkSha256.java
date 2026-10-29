package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.annotation.ZkBytes;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.lib.hash.Sha256;

import java.util.Objects;

/**
 * Symbolic SHA-256 adapter for annotation-based ({@code @ZKCircuit}) circuits.
 * Wraps {@link Sha256} so a {@link ZkBytes} message hashes to a 32-byte digest.
 * The existing {@code ZkBytes} container requires a nonempty message; use
 * {@link Sha256#hashBytes} directly for an empty message.
 */
public final class ZkSha256 {

    private ZkSha256() {}

    /** SHA-256 of {@code message}, returning the complete 32-byte digest. */
    public static ZkBytes hash(ZkContext zk, ZkBytes message) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(message, "message");
        return ZkBytesSupport.toZkBytes(zk,
                Sha256.hashBytes(zk.builder().api(), ZkBytesSupport.toVariables(zk, message)));
    }
}
