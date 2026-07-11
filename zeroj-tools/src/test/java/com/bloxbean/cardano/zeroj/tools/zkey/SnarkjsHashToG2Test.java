package com.bloxbean.cardano.zeroj.ceremony;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ADR-0031 M5: {@link SnarkjsHashToG2} vs a captured ffjavascript ground truth — the fixed test
 * vector {@code hash[i] = (i*7+3) & 0xFF} run through snarkjs's {@code hashToG2} on this machine
 * (see scratch oracle script; values are the affine G2 coordinates).
 */
class SnarkjsHashToG2Test {

    @Test
    void fixedVector_matchesFfjavascript() {
        byte[] hash = new byte[64];
        for (int i = 0; i < 64; i++) hash[i] = (byte) ((i * 7 + 3) & 0xFF);

        var p = SnarkjsHashToG2.hashToG2(hash);

        assertEquals(new BigInteger("5206c703328d8030f2c7c431d73b5450234721bfa2cb1f027114086ec07cc46a138cee6a025bacc9c9ea2dd7c95f6c2", 16),
                p.x().reBigInt(), "x.c0");
        assertEquals(new BigInteger("80090f97b0426ea50af165634772726c9818f2dbb7516b173fccff51553f5a25066e540057e7018c91f44691851e358", 16),
                p.x().imBigInt(), "x.c1");
        assertEquals(new BigInteger("12d7625368277f875a53075c258aa01c088f3ef261a4536f24d3fae39f3c24c9da38582a021d23124a46f695f3e94885", 16),
                p.y().reBigInt(), "y.c0");
        assertEquals(new BigInteger("d768412f9d0463b2dfc993e5e30b49c2134c3d05ac467c2bc87861cca8187a5ffedc801ba785c8b233ac88e9e920833", 16),
                p.y().imBigInt(), "y.c1");
    }
}
