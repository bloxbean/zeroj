package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;

import java.math.BigInteger;

/**
 * Field configuration for a specific elliptic curve — holds the scalar field prime
 * and related parameters.
 *
 * @param curve the elliptic curve identifier
 * @param prime the scalar field order (Fr)
 * @param n32   number of 32-bit limbs per field element
 * @param name  human-readable name
 */
public record FieldConfig(CurveId curve, BigInteger prime, int n32, String name) {

    /** BN254 scalar field: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617 */
    public static final FieldConfig BN254 = new FieldConfig(
            CurveId.BN254,
            new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
            8, "BN254");

    /** BLS12-381 scalar field: r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 */
    public static final FieldConfig BLS12_381 = new FieldConfig(
            CurveId.BLS12_381,
            new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16),
            8, "BLS12-381");

    /** Pallas scalar field (Pasta cycle, used by Halo2 IPA). */
    public static final FieldConfig PALLAS = new FieldConfig(
            CurveId.PALLAS,
            new BigInteger("28948022309329048855892746252171976963363056481941560715954676764349967630337"),
            8, "Pallas");

    /** Look up configuration for a curve. */
    public static FieldConfig forCurve(CurveId curve) {
        return switch (curve) {
            case BN254 -> BN254;
            case BLS12_381 -> BLS12_381;
            case PALLAS -> PALLAS;
        };
    }

    /** Field element byte size (n32 * 4). */
    public int n8() { return n32 * 4; }
}
