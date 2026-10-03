package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.annotation.ZkBits;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitPedersen;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;

import java.util.Objects;

/**
 * Symbolic Pedersen commitment adapter for annotation-based circuits
 * ({@code pedersen-jubjub-v1}, see {@code docs/specs/pedersen-jubjub-v1.md}).
 *
 * <p>Both scalars are asserted canonical ({@code < l}). The value keeps its declared width;
 * the blinding must be declared at exactly {@value #BLINDING_BITS} bits and must not be a
 * public input or a circuit constant (ADR-0051 D2). Sample it with
 * {@link org.zeroj.circuit.lib.jubjub.PedersenCommitment#randomBlinding}.
 */
public final class ZkPedersen {
    public static final int MAX_SCALAR_BITS = 252;

    /** Required declared width of every blinding, in bits (ADR-0051 D2). */
    public static final int BLINDING_BITS = InCircuitPedersen.BLINDING_BITS;

    private ZkPedersen() {}

    /**
     * Commits to {@code value} with {@code blinding}.
     *
     * <p>The value leg is multiplied at the value's own declared width (1–252), so a 64-bit
     * amount pays for 64 bits. The blinding must be declared at {@value #BLINDING_BITS} bits:
     * a narrower blinding makes the commitment brute-forceable from public data, so it is
     * rejected at circuit-definition time, as is a blinding that is directly a public input
     * or a constant.
     *
     * <p><b>Order matters.</b> Both decompositions are obtained <em>before</em> the
     * canonicality check runs. {@code assertCanonicalScalar} compares against {@code l} at
     * {@link #MAX_SCALAR_BITS}, and its range precondition is discharged from the DSL's range
     * cache — but only if a bound is already recorded for the wire. Run it first on a derived
     * value that has no cached bound and it mints a full 252-bit decomposition that is then
     * thrown away, which is precisely the duplicate this reuse removes.
     */
    public static ZkJubjubPoint commit(ZkContext zk, ZkUInt value, ZkUInt blinding) {
        validateScalarInputs(zk, value, blinding);
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
     * Commits using LSB-first scalar bit vectors. The blinding vector must be exactly
     * {@value #BLINDING_BITS} bits, none of them a public input or a constant.
     */
    public static ZkJubjubPoint commitBits(ZkContext zk, ZkBits valueBits, ZkBits blindingBits) {
        validateBitInputs(zk, valueBits, blindingBits);
        Variable[] valueVariables = variables(valueBits);
        Variable[] blindingVariables = variables(blindingBits);
        var api = zk.builder().api();
        for (Variable bit : blindingVariables) {
            api.requireNotPublicOrConstant(bit);
        }
        assertCanonicalScalar(zk, api.fromBinary(valueVariables));
        assertCanonicalScalar(zk, api.fromBinary(blindingVariables));
        return ZkJubjubPoint.wrap(zk, InCircuitPedersen.commit(
                api,
                valueVariables,
                blindingVariables));
    }

    /**
     * Asserts that {@code (value, blinding)} opens {@code commitment}. The same width and
     * provenance rules as {@link #commit(ZkContext, ZkUInt, ZkUInt)} apply.
     */
    public static void verifyOpening(
            ZkContext zk,
            ZkJubjubPoint commitment,
            ZkUInt value,
            ZkUInt blinding) {
        Objects.requireNonNull(commitment, "commitment");
        commitment.requireSameContext(zk);
        commit(zk, value, blinding).assertEqual(zk, commitment);
    }

    private static void validateScalarInputs(ZkContext zk, ZkUInt value, ZkUInt blinding) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        zk.requireSignal(value.signal());
        zk.requireSignal(blinding.signal());
        if (value.bits() <= 0 || value.bits() > MAX_SCALAR_BITS) {
            throw new IllegalArgumentException(
                    "value width must be in [1, " + MAX_SCALAR_BITS + "], got " + value.bits());
        }
        requireBlindingWidth(blinding.bits());
        zk.builder().api().requireNotPublicOrConstant(blinding.signal().variable());
    }

    private static void validateBitInputs(ZkContext zk, ZkBits valueBits, ZkBits blindingBits) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(valueBits, "valueBits");
        Objects.requireNonNull(blindingBits, "blindingBits");
        if (valueBits.size() <= 0 || valueBits.size() > MAX_SCALAR_BITS) {
            throw new IllegalArgumentException(
                    "value width must be in [1, " + MAX_SCALAR_BITS + "], got " + valueBits.size());
        }
        requireBlindingWidth(blindingBits.size());
        for (var bit : valueBits.values()) {
            zk.requireSignal(bit.signal());
        }
        for (var bit : blindingBits.values()) {
            zk.requireSignal(bit.signal());
        }
    }

    private static void requireBlindingWidth(int bits) {
        if (bits != BLINDING_BITS) {
            throw new IllegalArgumentException(
                    "blinding must be declared at exactly " + BLINDING_BITS + " bits, got " + bits
                            + ". A narrower blinding cannot hide the committed value: a k-bit "
                            + "blinding is recovered from the public commitment by enumerating "
                            + "2^k candidates per value (ADR-0051 D2).");
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
