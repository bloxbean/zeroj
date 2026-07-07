package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared {@link ZkBytes} ↔ {@link Variable}[] conversions for the byte-oriented hash adapters
 * ({@link ZkSha512}, {@link ZkHmacSha512}, {@link ZkBlake2b}).
 */
final class ZkBytesSupport {

    private ZkBytesSupport() {}

    /** Assert ownership and unwrap a {@link ZkBytes} to raw byte variables (for the CircuitAPI gadgets). */
    static Variable[] toVariables(ZkContext zk, ZkBytes bytes) {
        for (Signal s : bytes.signals()) zk.requireSignal(s);
        Variable[] out = new Variable[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) out[i] = bytes.get(i).signal().variable();
        return out;
    }

    /** Wrap raw byte variables (each provably in [0,255]) back into a range-checked {@link ZkBytes}. */
    static ZkBytes toZkBytes(ZkContext zk, Variable[] bytes) {
        List<ZkUInt> values = new ArrayList<>(bytes.length);
        for (Variable v : bytes) values.add(ZkUInt.wrap(zk.builder(), zk.builder().wrap(v), 8));
        return new ZkBytes(values);
    }
}
