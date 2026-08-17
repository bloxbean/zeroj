package com.bloxbean.cardano.zeroj.api;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class R1CSCanonicalIdentityTest {
    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    void exactDigestDistinguishesEquationsWithIdenticalDimensions() {
        R1CSFlat first = flat(BigInteger.ONE);
        R1CSFlat second = flat(BigInteger.TWO);
        String firstDigest = R1CSFlatIO.canonicalSha256(first, 3, 1);
        String secondDigest = R1CSFlatIO.canonicalSha256(second, 3, 1);

        assertEquals("782662a4cc3eef1b5c191cba8ea79d27fd70785b6820a594c7a7e73117a278b1",
                firstDigest, "cross-implementation zeroj-r1cs-canonical-v1 vector");
        assertNotEquals(firstDigest, secondDigest);
        assertEquals(firstDigest, R1CSFlatIO.canonicalSha256(first, 3, 1));
    }

    @Test
    void dictionaryLayoutDoesNotChangeCanonicalRelationIdentity() {
        R1CSFlat.Builder builder = R1CSFlat.builder();
        builder.add(Map.of(2, BigInteger.ONE), Map.of(0, BigInteger.TWO),
                Map.of(1, BigInteger.ONE));
        R1CSFlat normal = builder.build();

        BigInteger[] reversedDictionary = {BigInteger.TWO, BigInteger.ONE};
        R1CSFlat reordered = R1CSFlat.fromArrays(
                1,
                new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{2}, new int[]{1}),
                new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{0}, new int[]{0}),
                new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{1}, new int[]{1}),
                reversedDictionary);

        assertEquals(
                R1CSFlatIO.canonicalSha256(normal, 3, 1),
                R1CSFlatIO.canonicalSha256(reordered, 3, 1));
    }

    @Test
    void malformedWireOrderAndOutOfRangeReferencesFailClosed() {
        BigInteger[] dictionary = {BigInteger.ONE};
        R1CSFlat duplicateWire = R1CSFlat.fromArrays(
                1,
                new R1CSFlat.HeapMatrix(
                        new int[]{0, 2}, new int[]{2, 2}, new int[]{0, 0}),
                new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[0], new int[0]),
                new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[0], new int[0]),
                dictionary);
        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.canonicalSha256(duplicateWire, 3, 1));

        R1CSFlat outOfRange = R1CSFlat.fromArrays(
                1,
                new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{3}, new int[]{0}),
                new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[0], new int[0]),
                new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[0], new int[0]),
                dictionary);
        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.canonicalSha256(outOfRange, 3, 1));
    }

    @Test
    void coefficientFieldAliasesFailClosed() {
        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.canonicalSha256(flat(FR), 3, 1));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.canonicalSha256(flat(FR.add(BigInteger.ONE)), 3, 1));
        assertEquals(64, R1CSFlatIO.canonicalSha256(flat(FR.subtract(BigInteger.ONE)), 3, 1).length());
    }

    @Test
    void exactFingerprintRejectsNonCanonicalNumericAliases() {
        String digest = "0".repeat(64);

        assertEquals(new R1CSFlatIO.ExactFingerprint(1, 3, 1, digest),
                R1CSFlatIO.parseExactFingerprint("c1-w3-p1-r" + digest));
        assertNull(R1CSFlatIO.parseExactFingerprint("c01-w3-p1-r" + digest));
        assertNull(R1CSFlatIO.parseExactFingerprint("c1-w03-p1-r" + digest));
        assertNull(R1CSFlatIO.parseExactFingerprint("c1-w3-p01-r" + digest));
    }

    private static R1CSFlat flat(BigInteger outputCoefficient) {
        R1CSFlat.Builder builder = R1CSFlat.builder();
        builder.add(Map.of(2, BigInteger.ONE), Map.of(2, BigInteger.ONE),
                Map.of(1, outputCoefficient));
        return builder.build();
    }
}
