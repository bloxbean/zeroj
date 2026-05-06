package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;

import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.A;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.TWO_D;

/**
 * In-circuit Jubjub gadgets. Each method takes a {@link CircuitAPI},
 * wires for the relevant point(s), and emits the constraints implementing
 * the operation.
 *
 * <h2>Point representation inside the circuit</h2>
 * A Jubjub point is four {@link Variable}s: {@code U}, {@code V},
 * {@code Z}, {@code T} — extended twisted Edwards coordinates with
 * affine {@code (u, v) = (U/Z, V/Z)} and invariant {@code T = U·V/Z}.
 * The {@link Point} record bundles them.
 *
 * <h2>Field binding</h2>
 * All gadgets call {@code api.requireField(PoseidonParamsBLS12_381T3
 * .INSTANCE.field())} so that a subsequent compile or witness calculation
 * for a non-BLS12-381 curve will fail at compile time. Jubjub is only
 * meaningful over BLS12-381 scalar field; pairing with BN254 would produce
 * a syntactically valid but cryptographically nonsense circuit.
 *
 * <h2>Security caveats</h2>
 * <ul>
 *   <li>Input points from untrusted sources must be subgroup-checked
 *       <b>before</b> being passed to these gadgets. There is no implicit
 *       subgroup check here; adding one per operation would be
 *       unacceptably expensive.</li>
 *   <li>Scalar inputs used with {@link #scalarMulFixedBase} must be bit-
 *       decomposed <b>with range-check</b> (use {@link CircuitAPI#toBinary}
 *       on the scalar wire first).</li>
 *   <li>These gadgets do not enforce the scalar is reduced modulo
 *       {@link JubjubCurve#SUBGROUP_ORDER}. For EdDSA verification this
 *       must be enforced at the higher layer.</li>
 * </ul>
 */
public final class InCircuitJubjub {

    private InCircuitJubjub() {}

    /**
     * A Jubjub point as four circuit wires in extended-coordinate form.
     */
    public record Point(Variable u, Variable v, Variable z, Variable t) {}

    /**
     * Wraps an off-circuit {@link JubjubPoint} as four circuit constants.
     * Useful for building fixed-base scalar-mul tables at compile time.
     */
    public static Point constant(CircuitAPI api, JubjubPoint p) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
        // Normalize to Z = 1 so constants have canonical form (affine lifted).
        BigInteger uAff = p.affineU();
        BigInteger vAff = p.affineV();
        BigInteger tAff = uAff.multiply(vAff).mod(JubjubCurve.BASE_FIELD_PRIME);
        return new Point(api.constant(uAff), api.constant(vAff),
                api.constant(BigInteger.ONE), api.constant(tAff));
    }

    /**
     * Unified twisted-Edwards addition {@code P + Q} per HWCD §3.2 for
     * {@code a = -1}. Complete for Jubjub (no exceptional inputs).
     *
     * <p>Cost: 9 constraint-level multiplications (some are
     * constant-scalar mults which may fold into linear combinations
     * depending on the backend; the R1CS compiler will emit ~9
     * multiplication gates).
     */
    public static Point add(CircuitAPI api, Point p, Point q) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
        // A = (V1 - U1)·(V2 - U2)
        Variable vMinusU1 = api.sub(p.v, p.u);
        Variable vMinusU2 = api.sub(q.v, q.u);
        Variable aVal = api.mul(vMinusU1, vMinusU2);

        // B = (V1 + U1)·(V2 + U2)
        Variable vPlusU1 = api.add(p.v, p.u);
        Variable vPlusU2 = api.add(q.v, q.u);
        Variable bVal = api.mul(vPlusU1, vPlusU2);

        // C = T1 · 2d · T2
        Variable t1Times2d = api.mul(p.t, api.constant(TWO_D));
        Variable cVal = api.mul(t1Times2d, q.t);

        // D = Z1 · 2 · Z2
        Variable z1Times2 = api.mul(p.z, api.constant(BigInteger.TWO));
        Variable dVal = api.mul(z1Times2, q.z);

        // Linear combinations
        Variable eVal = api.sub(bVal, aVal);
        Variable fVal = api.sub(dVal, cVal);
        Variable gVal = api.add(dVal, cVal);
        Variable hVal = api.add(bVal, aVal);

        // Output: U3 = E·F, V3 = G·H, T3 = E·H, Z3 = F·G
        return new Point(
                api.mul(eVal, fVal),
                api.mul(gVal, hVal),
                api.mul(fVal, gVal),
                api.mul(eVal, hVal));
    }

    /**
     * Twisted-Edwards doubling {@code 2·P} per HWCD §3.3 dedicated
     * formula for {@code a = -1}.
     */
    public static Point doubled(CircuitAPI api, Point p) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
        // A = U^2
        Variable aVal = api.mul(p.u, p.u);
        // B = V^2
        Variable bVal = api.mul(p.v, p.v);
        // C = 2·Z^2
        Variable zSquared = api.mul(p.z, p.z);
        Variable cVal = api.mul(zSquared, api.constant(BigInteger.TWO));
        // D = a·A = -A
        Variable dVal = api.mul(aVal, api.constant(A));
        // E = (U + V)^2 - A - B
        Variable uPlusV = api.add(p.u, p.v);
        Variable uPlusVSquared = api.mul(uPlusV, uPlusV);
        Variable eVal = api.sub(api.sub(uPlusVSquared, aVal), bVal);
        // G = D + B
        Variable gVal = api.add(dVal, bVal);
        // F = G - C
        Variable fVal = api.sub(gVal, cVal);
        // H = D - B
        Variable hVal = api.sub(dVal, bVal);
        return new Point(
                api.mul(eVal, fVal),
                api.mul(gVal, hVal),
                api.mul(fVal, gVal),
                api.mul(eVal, hVal));
    }

    /**
     * Conditional selection between two points. Returns {@code cond ? ifTrue : ifFalse}
     * coordinate-wise. {@code cond} must be asserted boolean by the caller.
     */
    public static Point select(CircuitAPI api, Variable cond, Point ifTrue, Point ifFalse) {
        return new Point(
                api.select(cond, ifTrue.u, ifFalse.u),
                api.select(cond, ifTrue.v, ifFalse.v),
                api.select(cond, ifTrue.z, ifFalse.z),
                api.select(cond, ifTrue.t, ifFalse.t));
    }

    /**
     * Conditional addition: {@code result = cond ? (acc + p) : acc}.
     * {@code cond} must be asserted boolean.
     */
    public static Point conditionalAdd(CircuitAPI api, Variable cond, Point acc, Point p) {
        Point sum = add(api, acc, p);
        return select(api, cond, sum, acc);
    }

    /**
     * In-circuit identity point {@code (0, 1, 1, 0)}.
     */
    public static Point identity(CircuitAPI api) {
        return new Point(api.constant(0), api.constant(1), api.constant(1), api.constant(0));
    }

    /**
     * Fixed-base scalar multiplication {@code [k]·G} where {@code G} is
     * an off-circuit point baked in at compile time. Uses a simple
     * double-and-add over the bit decomposition of {@code k}.
     *
     * <p>Cost: {@code numBits} conditional additions against pre-doubled
     * copies of the base (precomputed at compile time). Each addition is
     * ~8 multiplications plus 4 muxes; a 255-bit scalar-mul costs
     * roughly 2500 constraints.
     *
     * @param api         circuit API
     * @param basePoint   fixed off-circuit base point (e.g. Jubjub generator)
     * @param scalarBits  scalar as an LSB-first array of boolean variables
     *                    (each must be asserted 0/1 by the caller)
     * @return            in-circuit {@code [k]·basePoint} in extended coords
     */
    public static Point scalarMulFixedBase(CircuitAPI api, JubjubPoint basePoint, Variable[] scalarBits) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
        if (scalarBits == null || scalarBits.length == 0) {
            throw new IllegalArgumentException("scalarBits must not be empty");
        }
        if (scalarBits.length > 255) {
            throw new IllegalArgumentException(
                    "scalarBits.length must be at most 255; got " + scalarBits.length
                            + " (Jubjub scalar field is 252-bit; 255 tolerates slight overprovisioning)");
        }
        // Precompute table[i] = [2^i] · basePoint off-circuit.
        JubjubPoint[] table = new JubjubPoint[scalarBits.length];
        table[0] = basePoint;
        for (int i = 1; i < scalarBits.length; i++) {
            table[i] = table[i - 1].doubled();
        }

        Point acc = identity(api);
        for (int i = 0; i < scalarBits.length; i++) {
            Point addend = constant(api, table[i]);
            acc = conditionalAdd(api, scalarBits[i], acc, addend);
        }
        return acc;
    }

    /**
     * Overload accepting the scalar as a single {@link Variable}; internally
     * bit-decomposes to {@code numBits} bits (LSB-first, each bit asserted
     * boolean). For a 252-bit Jubjub scalar pass {@code numBits = 252}.
     */
    public static Point scalarMulFixedBase(CircuitAPI api, JubjubPoint basePoint,
                                           Variable scalar, int numBits) {
        Variable[] bits = api.toBinary(scalar, numBits);
        return scalarMulFixedBase(api, basePoint, bits);
    }

    /**
     * Variable-base scalar multiplication {@code [k]·P} where {@code P} is
     * an in-circuit point (not known at compile time). Uses double-and-add
     * over {@code scalarBits} LSB-first.
     *
     * <p>Cost per bit: one in-circuit doubling (~7 muls) + one conditional
     * addition (~9 muls + 4 mux). For a 252-bit scalar this is roughly
     * {@code 252 × 20 ≈ 5000 constraints} — about 3× more expensive than
     * the fixed-base variant because in-circuit doublings are required each
     * iteration.
     *
     * <p>Caveats:
     * <ul>
     *   <li>{@code base} must be in the prime-order subgroup; call
     *       {@code isInSubgroup()} off-circuit on every untrusted point
     *       before passing it into a witness.</li>
     *   <li>This does not enforce that the scalar is reduced modulo
     *       {@link JubjubCurve#SUBGROUP_ORDER}. For protocols that depend
     *       on that reduction (EdDSA), the caller must range-check the
     *       scalar separately.</li>
     * </ul>
     *
     * @param api        circuit API
     * @param base       in-circuit base point (extended coords)
     * @param scalarBits scalar bits LSB-first (each asserted boolean by caller)
     */
    public static Point scalarMulVariableBase(CircuitAPI api, Point base, Variable[] scalarBits) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
        if (scalarBits == null || scalarBits.length == 0) {
            throw new IllegalArgumentException("scalarBits must not be empty");
        }
        if (scalarBits.length > 255) {
            throw new IllegalArgumentException(
                    "scalarBits.length must be at most 255; got " + scalarBits.length);
        }
        Point acc = identity(api);
        Point doubledBase = base;
        for (int i = 0; i < scalarBits.length; i++) {
            acc = conditionalAdd(api, scalarBits[i], acc, doubledBase);
            if (i < scalarBits.length - 1) {
                doubledBase = doubled(api, doubledBase);
            }
        }
        return acc;
    }

    /**
     * Overload that bit-decomposes the scalar {@link Variable} first.
     */
    public static Point scalarMulVariableBase(CircuitAPI api, Point base,
                                              Variable scalar, int numBits) {
        Variable[] bits = api.toBinary(scalar, numBits);
        return scalarMulVariableBase(api, base, bits);
    }
}
