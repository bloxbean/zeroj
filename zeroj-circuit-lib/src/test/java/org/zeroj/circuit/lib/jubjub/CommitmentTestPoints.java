package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.HexFormat;

/**
 * Jubjub encodings for the strict-decoder tests of {@code commitment-profiles-v1} §10 and §13.4:
 * the identity, torsion points of order 2, 4 and 8, a mixed-order point, both {@code u = 0} sign
 * aliases, an off-curve encoding and {@code v ≥ p}.
 */
final class CommitmentTestPoints {

    static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;

    static final byte[] IDENTITY = JubjubPoint.IDENTITY.toBytes();
    /** [l]·G_full: the 8-torsion component of the full generator, of order exactly 8. */
    static final JubjubPoint T8 = JubjubPoint.FULL_GENERATOR.scalarMul(L);
    static final byte[] ORDER_8 = T8.toBytes();
    static final byte[] ORDER_4 = T8.doubled().toBytes();
    static final byte[] ORDER_2 = T8.doubled().doubled().toBytes();
    static final byte[] MIXED = JubjubPoint.SUBGROUP_GENERATOR.add(T8).toBytes();
    /** Spec §10: the identity with the sign bit set. */
    static final byte[] ALIAS_IDENTITY = hex("0100000000000000000000000000000000000000000000000000000000000080");
    /** Spec §10: the order-2 point {@code (0, −1)} with the sign bit set. */
    static final byte[] ALIAS_ORDER_2 = hex("00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7edf3");
    static final byte[] V_NOT_BELOW_P = le32(P);
    static final byte[] OFF_CURVE = firstOffCurve();

    private CommitmentTestPoints() {
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    static byte[] le32(BigInteger v) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = v.shiftRight(8 * i).byteValue();
        return out;
    }

    private static byte[] firstOffCurve() {
        for (int v = 2; ; v++) {
            byte[] candidate = le32(BigInteger.valueOf(v));
            try {
                JubjubPoint.fromBytes(candidate);
            } catch (IllegalArgumentException offCurve) {
                return candidate;
            }
        }
    }
}
