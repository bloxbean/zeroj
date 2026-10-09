package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkValue;
import org.zeroj.circuit.lib.jubjub.InCircuitElGamal;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A ciphertext {@code (A, B)} computed in a circuit by {@link ZkElGamal#encrypt}
 * ({@code elgamal-jubjub-v1} §9.1).
 *
 * <p>It is exposed to a verifier as four public inputs, {@code A.u, A.v, B.u, B.v} (spec §8),
 * bound with {@link #assertAffineEquals}. There is deliberately no in-circuit ciphertext
 * addition: the profile defines plaintext bounds for host-side sums only.
 */
public final class ZkElGamalCiphertext implements ZkValue {

    private final ZkJubjubPoint handle;
    private final ZkJubjubPoint blinded;

    ZkElGamalCiphertext(ZkContext context, InCircuitElGamal.Ciphertext ciphertext) {
        this.handle = ZkJubjubPoint.wrap(context, ciphertext.handle());
        this.blinded = ZkJubjubPoint.wrap(context, ciphertext.blinded());
    }

    /** {@code A = [k]·G}. */
    public ZkJubjubPoint handle() {
        return handle;
    }

    /** {@code B = [m]·G + [k]·PK}. */
    public ZkJubjubPoint blinded() {
        return blinded;
    }

    /**
     * Binds the ciphertext to affine coordinates, in spec §8 order. Unlike the key and DLEQ
     * entry points, this does not require the coordinates to be public inputs: a ciphertext may
     * legitimately be bound to a hash or another derived value. Making the binding part of the
     * verifier's statement is the circuit author's job.
     */
    public void assertAffineEquals(ZkContext zk, ZkField handleU, ZkField handleV,
                                   ZkField blindedU, ZkField blindedV) {
        Objects.requireNonNull(zk, "zk");
        handle.assertAffineEquals(zk, handleU, handleV);
        blinded.assertAffineEquals(zk, blindedU, blindedV);
    }

    @Override
    public List<Signal> signals() {
        List<Signal> out = new ArrayList<>(handle.signals());
        out.addAll(blinded.signals());
        return out;
    }

    /** Points computed by the gadget from well-formed inputs; nothing further is needed. */
    @Override
    public void assertWellFormed() {}
}
