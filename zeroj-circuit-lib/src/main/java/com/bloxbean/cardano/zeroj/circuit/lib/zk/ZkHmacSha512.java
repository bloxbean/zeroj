package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.lib.hash.HmacSha512;

import java.util.Objects;

/**
 * Symbolic HMAC-SHA512 adapter for annotation-based ({@code @ZKCircuit}) circuits.
 * Wraps {@link HmacSha512} so a {@link ZkBytes} key + message produce a 64-byte {@link ZkBytes} MAC.
 */
public final class ZkHmacSha512 {

    private ZkHmacSha512() {}

    /** HMAC-SHA512 of {@code message} under {@code key} → 64-byte MAC. */
    public static ZkBytes hmac(ZkContext zk, ZkBytes key, ZkBytes message) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        return ZkBytesSupport.toZkBytes(zk, HmacSha512.hmacBytes(zk.builder().api(),
                ZkBytesSupport.toVariables(zk, key), ZkBytesSupport.toVariables(zk, message)));
    }
}
