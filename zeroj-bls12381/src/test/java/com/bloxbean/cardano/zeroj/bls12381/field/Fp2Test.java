package com.bloxbean.cardano.zeroj.bls12381.field;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Fp2Test {

    @Test
    void sqrtMinusOne_usesFp2SpecialCaseBranch() {
        Fp2 minusOne = Fp2.ONE.neg();

        Fp2 root = minusOne.sqrt().orElseThrow();

        assertEquals(minusOne, root.square());
        assertTrue(root.equals(Fp2.of(Fp.ZERO, Fp.ONE)) || root.equals(Fp2.of(Fp.ZERO, Fp.ONE.neg())));
    }
}
