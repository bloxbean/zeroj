package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ADR-0061 D2 / I9: the bases used here are the G1 Pedersen profile's, and the generator holder's checks run. */
class BulletproofBasesTest {

    @Test
    @DisplayName("G and H equal the pedersen-bls12-381-g1-v1 bases: commitments to (1, 0) and (0, 1)")
    void basesMatchProfile() {
        G1Pedersen p = G1Pedersen.pureJava();
        assertArrayEquals(p.commitScalar(BigInteger.ONE, BigInteger.ZERO).toPointBytes(), PointCodec.encode(BulletproofGenerators.g()));
        assertArrayEquals(p.commitScalar(BigInteger.ZERO, BigInteger.ONE).toPointBytes(), PointCodec.encode(BulletproofGenerators.h()));
        assertEquals(BulletproofGenerators.G_HEX, HexFormat.of().formatHex(PointCodec.encode(BulletproofGenerators.g())));
    }

    @Test
    @DisplayName("The 129 pinned points decode and re-encode to their pins, and D_gens is the spec value")
    void pinnedGenerators() {
        for (int i = 0; i < BulletproofGenerators.MAX_BITS; i++) {
            assertEquals(BulletproofGenerators.G_VEC_HEX.get(i), HexFormat.of().formatHex(PointCodec.encode(BulletproofGenerators.gVec(i))));
            assertEquals(BulletproofGenerators.H_VEC_HEX.get(i), HexFormat.of().formatHex(PointCodec.encode(BulletproofGenerators.hVec(i))));
            assertTrue(BulletproofGenerators.gVec(i).isValid());
        }
        assertEquals(BulletproofGenerators.U_HEX, HexFormat.of().formatHex(PointCodec.encode(BulletproofGenerators.u())));
        assertEquals("69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19",
                HexFormat.of().formatHex(BulletproofGenerators.digest()));
        assertEquals(70, BulletproofGenerators.DST_BP.length());
    }

    @Test
    @DisplayName("The nonce source accepts only allowlisted SecureRandom algorithms (a sanity check, not an entropy proof)")
    void nonceSourceAllowlist() throws Exception {
        SystemNonceSource source = SystemNonceSource.create();
        BigInteger n = source.next();
        assertTrue(n.signum() >= 0 && n.compareTo(PointCodec.Q) < 0);
        assertTrue(SystemNonceSource.ALLOWED_ALGORITHMS.contains(new SecureRandom().getAlgorithm()));
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> SystemNonceSource.checked(SecureRandom.getInstance("SHA1PRNG")));
        assertTrue(e.getMessage().contains("SHA1PRNG"));
    }
}
