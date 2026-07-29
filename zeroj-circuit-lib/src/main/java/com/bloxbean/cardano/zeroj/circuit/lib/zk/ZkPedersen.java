package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.BitDecomposition;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBits;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitPedersen;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;

import java.util.Objects;

/**
 * Symbolic Pedersen commitment adapter for annotation-based circuits.
 */
public final class ZkPedersen {
    public static final int MAX_SCALAR_BITS = 252;

    private ZkPedersen() {}

    public static ZkJubjubPoint commit(ZkContext zk, ZkUInt value, ZkUInt blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        return commit(zk, value, blinding, Math.max(value.bits(), blinding.bits()));
    }

    /**
     * Commits to {@code value} with {@code blinding}.
     *
     * <p>{@code scalarBits} is validated as an upper bound on both operands, but each scalar
     * is multiplied at <b>its own declared width</b>: a 16-bit value alongside a 252-bit
     * blinding pays for 16 bits on the value leg. Passing the shared maximum to both legs, as
     * this method used to, made every small commitment cost as much as the widest operand.
     *
     * <p><b>Order matters.</b> Both decompositions are obtained <em>before</em> the
     * canonicality check runs. {@code assertCanonicalScalar} compares against {@code l} at
     * {@link #MAX_SCALAR_BITS}, and its range precondition is discharged from the DSL's range
     * cache — but only if a bound is already recorded for the wire. Run it first on a derived
     * value that has no cached bound and it mints a full 252-bit decomposition that is then
     * thrown away, which is precisely the duplicate this reuse removes.
     */
    public static ZkJubjubPoint commit(ZkContext zk, ZkUInt value, ZkUInt blinding, int scalarBits) {
        validateScalarInputs(zk, value, blinding, scalarBits);
        // Mint (or retrieve) both owned decompositions at their actual widths FIRST, so the
        // canonicality check below is satisfied from the range cache rather than emitting a
        // second, wider decomposition.
        BitDecomposition valueBits = value.decomposition();
        BitDecomposition blindingBits = blinding.decomposition();
        assertCanonicalScalar(zk, value.signal().variable());
        assertCanonicalScalar(zk, blinding.signal().variable());
        return ZkJubjubPoint.wrap(zk, InCircuitPedersen.commit(
                zk.builder().api(), valueBits, blindingBits));
    }

    /**
     * Commits using LSB-first scalar bit vectors.
     */
    public static ZkJubjubPoint commitBits(ZkContext zk, ZkBits valueBits, ZkBits blindingBits) {
        validateBitInputs(zk, valueBits, blindingBits);
        Variable[] valueVariables = variables(valueBits);
        Variable[] blindingVariables = variables(blindingBits);
        assertCanonicalScalar(zk, zk.builder().api().fromBinary(valueVariables));
        assertCanonicalScalar(zk, zk.builder().api().fromBinary(blindingVariables));
        return ZkJubjubPoint.wrap(zk, InCircuitPedersen.commit(
                zk.builder().api(),
                valueVariables,
                blindingVariables));
    }

    public static void verifyOpening(
            ZkContext zk,
            ZkJubjubPoint commitment,
            ZkUInt value,
            ZkUInt blinding,
            int scalarBits) {
        Objects.requireNonNull(commitment, "commitment");
        commitment.requireSameContext(zk);
        commit(zk, value, blinding, scalarBits).assertEqual(zk, commitment);
    }

    public static void verifyOpening(
            ZkContext zk,
            ZkJubjubPoint commitment,
            ZkUInt value,
            ZkUInt blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        verifyOpening(zk, commitment, value, blinding, Math.max(value.bits(), blinding.bits()));
    }

    private static void validateScalarInputs(ZkContext zk, ZkUInt value, ZkUInt blinding, int scalarBits) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        validateScalarBits(scalarBits);
        if (value.bits() > scalarBits || blinding.bits() > scalarBits) {
            throw new IllegalArgumentException("scalarBits must cover value and blinding bit widths");
        }
        zk.requireSignal(value.signal());
        zk.requireSignal(blinding.signal());
    }

    private static void validateBitInputs(ZkContext zk, ZkBits valueBits, ZkBits blindingBits) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(valueBits, "valueBits");
        Objects.requireNonNull(blindingBits, "blindingBits");
        validateScalarBits(valueBits.size());
        validateScalarBits(blindingBits.size());
        for (var bit : valueBits.values()) {
            zk.requireSignal(bit.signal());
        }
        for (var bit : blindingBits.values()) {
            zk.requireSignal(bit.signal());
        }
    }

    private static void validateScalarBits(int scalarBits) {
        if (scalarBits <= 0 || scalarBits > MAX_SCALAR_BITS) {
            throw new IllegalArgumentException("scalarBits must be in [1, " + MAX_SCALAR_BITS + "]");
        }
    }

    private static void assertCanonicalScalar(ZkContext zk, Variable scalar) {
        var api = zk.builder().api();
        api.assertEqual(
                api.lessThan(scalar, api.constant(JubjubCurve.SUBGROUP_ORDER), MAX_SCALAR_BITS),
                api.constant(1));
    }

    private static Variable[] variables(ZkBits bits) {
        Variable[] variables = new Variable[bits.size()];
        for (int i = 0; i < bits.size(); i++) {
            variables[i] = bits.get(i).signal().variable();
        }
        return variables;
    }
}
