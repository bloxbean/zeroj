package org.zeroj.circuit.lib.jubjub;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0054 M1: ZeroJ's {@link Hpke} against BouncyCastle 1.83's independent
 * {@code org.bouncycastle.crypto.hpke.HPKE} for the same suite, in both directions, and the
 * negative cases of the milestone.
 */
class HpkeDifferentialTest {

    private static final HPKE BC = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256,
            HPKE.aead_CHACHA20_POLY1305);

    private static AsymmetricCipherKeyPair bcPair(byte[] sk) {
        X25519PrivateKeyParameters priv = new X25519PrivateKeyParameters(sk, 0);
        return new AsymmetricCipherKeyPair(priv.generatePublicKey(), priv);
    }

    @Test
    @DisplayName("ZeroJ seal → BouncyCastle open, and BouncyCastle seal → ZeroJ open, on random keys, info, aad and plaintexts")
    void bothDirections() throws Exception {
        SecureRandom rng = new SecureRandom();
        Random sizes = new Random(9180);
        for (int i = 0; i < 200; i++) {
            byte[] skR = new byte[32];
            rng.nextBytes(skR);
            byte[] pkR = X25519Bytes.publicFromPrivate(skR);
            assertArrayEquals(((X25519PublicKeyParameters) bcPair(skR).getPublic()).getEncoded(), pkR, "public key");
            byte[] info = random(rng, sizes.nextInt(80));
            byte[] aad = random(rng, sizes.nextInt(3) == 0 ? 0 : sizes.nextInt(40));
            byte[] pt = random(rng, sizes.nextInt(300));

            Hpke.Sealed ours = Hpke.sealBase(pkR, info, aad, pt, rng);
            assertArrayEquals(pt, BC.open(ours.enc(), bcPair(skR), info, aad, ours.ct(), null, null, null), "BC opens ZeroJ");

            byte[][] theirs = BC.seal(new X25519PublicKeyParameters(pkR, 0), info, aad, pt, null, null, null);
            byte[] ct = theirs[0].length == pt.length + Hpke.N_T ? theirs[0] : theirs[1];
            byte[] enc = ct == theirs[0] ? theirs[1] : theirs[0];
            assertEquals(Hpke.N_ENC, enc.length);
            assertArrayEquals(pt, Hpke.openBase(enc, skR, info, aad, ct), "ZeroJ opens BC");

            // Same ephemeral on both sides: identical bytes.
            byte[] skE = new byte[32];
            rng.nextBytes(skE);
            Hpke.Sealed fixed = Hpke.sealBaseWithEphemeral(skE, pkR, info, aad, pt);
            // BouncyCastle's SetupBaseS with an explicit ephemeral pair (its seal(..., kpS) argument is the
            // Auth-mode sender key, not the ephemeral).
            HPKEContextWithEncapsulation bcContext = BC.setupBaseS(new X25519PublicKeyParameters(pkR, 0), info, bcPair(skE));
            assertArrayEquals(bcContext.getEncapsulation(), fixed.enc());
            assertArrayEquals(bcContext.seal(aad, pt), fixed.ct());
        }
    }

    @Test
    @DisplayName("Negatives: tampered enc or ct, wrong info, aad or key, small-order and wrong-length enc all fail")
    void negatives() throws Exception {
        SecureRandom rng = new SecureRandom();
        byte[] skR = random(rng, 32);
        byte[] pkR = X25519Bytes.publicFromPrivate(skR);
        byte[] info = "info".getBytes();
        byte[] pt = random(rng, 100);
        Hpke.Sealed s = Hpke.sealBase(pkR, info, new byte[0], pt, rng);
        assertArrayEquals(pt, Hpke.openBase(s.enc(), skR, info, new byte[0], s.ct()));

        for (int i = 0; i < s.ct().length; i++) {
            byte[] ct = s.ct().clone();
            ct[i] ^= 1;
            assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(s.enc(), skR, info, new byte[0], ct), "ct byte " + i);
        }
        for (int i = 0; i < 31; i++) { // byte 31 bit 0 flip keeps a different but valid u; covered below
            byte[] enc = s.enc().clone();
            enc[i] ^= 1;
            assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(enc, skR, info, new byte[0], s.ct()), "enc byte " + i);
        }
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(s.enc(), skR, "infx".getBytes(), new byte[0], s.ct()));
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(s.enc(), skR, info, new byte[]{0}, s.ct()));
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(s.enc(), random(rng, 32), info, new byte[0], s.ct()));
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(Arrays.copyOf(s.enc(), 31), skR, info, new byte[0], s.ct()));
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(s.enc(), skR, info, new byte[0], Arrays.copyOf(s.ct(), 115)));
        // Small-order enc: the DH output is all-zero, refused (RFC 9180 §7.1.4).
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(new byte[32], skR, info, new byte[0], s.ct()));
        byte[] one = new byte[32];
        one[0] = 1;
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(one, skR, info, new byte[0], s.ct()));
        // Sealing to a small-order recipient key fails for the sender too.
        assertThrows(Hpke.HpkeException.class, () -> Hpke.sealBase(new byte[32], info, new byte[0], pt, rng));
        // Non-canonical enc with the same reduced value is a different encapsulation (kem_context binds the bytes).
        byte[] highBit = s.enc().clone();
        highBit[31] ^= (byte) 0x80;
        assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(highBit, skR, info, new byte[0], s.ct()));
    }

    @Test
    @DisplayName("Fresh ephemeral per seal: two seals of the same message never share enc or ct")
    void freshEphemeral() throws Exception {
        SecureRandom rng = new SecureRandom();
        byte[] pkR = X25519Bytes.publicFromPrivate(random(rng, 32));
        byte[] pt = random(rng, 100);
        Hpke.Sealed a = Hpke.sealBase(pkR, new byte[0], new byte[0], pt, rng);
        Hpke.Sealed b = Hpke.sealBase(pkR, new byte[0], new byte[0], pt, rng);
        assertEquals(false, Arrays.equals(a.enc(), b.enc()));
        assertEquals(false, Arrays.equals(a.ct(), b.ct()));
    }

    private static byte[] random(SecureRandom rng, int n) {
        byte[] b = new byte[n];
        rng.nextBytes(b);
        return b;
    }
}
