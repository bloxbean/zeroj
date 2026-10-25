package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

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
    @DisplayName("Each nonce is exactly 64 octets from the source, read big-endian and reduced mod q, and the buffer is wiped (reviewer (c), M1 F2)")
    void nonceSampling() {
        List<byte[]> requests = new ArrayList<>();
        int[] counter = {0};
        SecureRandom spy = new SecureRandom() {
            @Override
            public String getAlgorithm() {
                return "DRBG";
            }

            @Override
            public void nextBytes(byte[] bytes) {
                requests.add(bytes);
                // Octets 0, 1, …, 63, then 64, …, 127: not palindromic, so the byte order is pinned.
                for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) counter[0]++;
            }
        };
        SystemNonceSource source = SystemNonceSource.checked(spy);
        // OS2IP(octets) mod q, computed with Python's int.from_bytes(…, "big") % q (Codex M1 r2 F3).
        assertEquals(new BigInteger("49390169590659034352182350487395535045561095549834662993610314140065425466348"),
                source.next());
        assertEquals(new BigInteger("248821931173421418027472439674655785776878240158471827891885852000486751455"),
                source.next());
        assertEquals(2, requests.size());
        for (byte[] r : requests) {
            assertEquals(64, r.length);
            assertArrayEquals(new byte[64], r, "the sample buffer is wiped after use");
        }
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
