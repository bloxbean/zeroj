package org.zeroj.circuit.lib.jubjub;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zeroj.circuit.lib.jubjub.JubjubCurve.BASE_FIELD_PRIME;
import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * ADR-0055 M1: the profile's primitives ({@link SaplingNoteCrypto}) against the Zcash Sapling
 * note-encryption vectors (zcash/zcash-test-vectors {@code 78321be}, vendored unchanged), run with
 * the Zcash personalization (ADR-0055 I10), plus negatives for point decoding and the AEAD.
 */
class ConfidentialNoteKnownAnswerTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The vectors as maps of field name to hex: the first two rows are a source line and the header. */
    static List<Map<String, String>> zcashVectors() throws IOException {
        JsonNode root;
        try (InputStream in = ConfidentialNoteKnownAnswerTest.class
                .getResourceAsStream("/standard-vectors/zcash-sapling-note-encryption.json")) {
            root = JSON.readTree(in);
        }
        String[] names = root.get(1).get(0).asText().split(",");
        List<Map<String, String>> vectors = new ArrayList<>();
        for (int row = 2; row < root.size(); row++) {
            Map<String, String> v = new LinkedHashMap<>();
            for (int i = 0; i < names.length; i++) {
                JsonNode cell = root.get(row).get(i);
                v.put(names[i].trim(), cell.isTextual() ? cell.asText() : cell.toString());
            }
            vectors.add(v);
        }
        return vectors;
    }

    /** A Zcash scalar field: 32 bytes, little-endian. */
    private static BigInteger littleEndianScalar(String hex) {
        byte[] le = HEX.parseHex(hex);
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
        return new BigInteger(1, be);
    }

    @Test
    @DisplayName("Zcash Sapling note encryption, all 10 vectors: Agree both ways, KDF^Sapling, Sym encrypt and decrypt (I10)")
    void zcashSaplingVectors() throws IOException {
        List<Map<String, String>> vectors = zcashVectors();
        assertEquals(10, vectors.size());
        for (int n = 0; n < vectors.size(); n++) {
            Map<String, String> v = vectors.get(n);
            String id = "vector " + n;
            byte[] epk = HEX.parseHex(v.get("epk"));
            byte[] sharedSecret = HEX.parseHex(v.get("shared_secret"));
            JubjubPoint pkd = SaplingNoteCrypto.decodeKey(HEX.parseHex(v.get("default_pk_d")));
            JubjubPoint epkPoint = SaplingNoteCrypto.decodeKey(epk);
            assertNotNull(pkd, id + " pk_d");
            assertNotNull(epkPoint, id + " epk");

            BigInteger esk = littleEndianScalar(v.get("esk"));
            BigInteger ivk = littleEndianScalar(v.get("ivk"));
            assertArrayEquals(sharedSecret, SaplingNoteCrypto.agree(esk, pkd).toBytes(), id + " [8·esk]·pk_d");
            assertArrayEquals(sharedSecret, SaplingNoteCrypto.agree(ivk, epkPoint).toBytes(), id + " [8·ivk]·epk");

            byte[] kEnc = HEX.parseHex(v.get("k_enc"));
            JubjubPoint shared = SaplingNoteCrypto.agree(ivk, epkPoint);
            assertArrayEquals(kEnc, SaplingNoteCrypto.kdf(SaplingNoteCrypto.ZCASH_PERSONALIZATION, shared, epk), id + " k_enc");

            byte[] pEnc = HEX.parseHex(v.get("p_enc"));
            byte[] cEnc = HEX.parseHex(v.get("c_enc"));
            assertArrayEquals(cEnc, SaplingNoteCrypto.encrypt(kEnc, pEnc), id + " c_enc");
            assertArrayEquals(pEnc, SaplingNoteCrypto.decrypt(kEnc, cEnc), id + " decrypt");
        }
    }

    @Test
    @DisplayName("The profile's personalization differs from Zcash's, so a ZeroJ key never equals a Sapling one (Q1)")
    void personalizationSeparates() throws IOException {
        Map<String, String> v = zcashVectors().get(0);
        byte[] epk = HEX.parseHex(v.get("epk"));
        JubjubPoint shared = SaplingNoteCrypto.agree(littleEndianScalar(v.get("ivk")), SaplingNoteCrypto.decodeKey(epk));
        byte[] zeroj = SaplingNoteCrypto.kdf(SaplingNoteCrypto.PERSONALIZATION, shared, epk);
        assertEquals(32, zeroj.length);
        assertThrows(AssertionError.class,
                () -> assertArrayEquals(HEX.parseHex(v.get("k_enc")), zeroj));
        assertNull(SaplingNoteCrypto.decrypt(zeroj, HEX.parseHex(v.get("c_enc"))), "a Sapling ciphertext does not open under the ZeroJ key");
    }

    @Test
    @DisplayName("The AEAD self-test passes on this platform, and fails closed for a provider that accepts a forged tag")
    void selfTest() {
        NoteAeadSelfTest.run();
        // A provider that skips tag verification: decrypts with the right keystream, ignores the tag.
        NoteAeadSelfTest.Primitives noTagCheck = new NoteAeadSelfTest.Primitives() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext) {
                return SaplingNoteCrypto.encrypt(key, plaintext);
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] ciphertext) {
                byte[] opened = SaplingNoteCrypto.decrypt(key, ciphertext);
                return opened != null ? opened : new byte[ciphertext.length - 16]; // a forged tag "opens"
            }
        };
        assertThrows(IllegalStateException.class, () -> NoteAeadSelfTest.run(noTagCheck));
        // A provider whose encryption is wrong.
        NoteAeadSelfTest.Primitives wrongCipher = new NoteAeadSelfTest.Primitives() {
            @Override
            public byte[] encrypt(byte[] key, byte[] plaintext) {
                byte[] out = SaplingNoteCrypto.encrypt(key, plaintext);
                out[0] ^= 1;
                return out;
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] ciphertext) {
                return SaplingNoteCrypto.decrypt(key, ciphertext);
            }
        };
        assertThrows(IllegalStateException.class, () -> NoteAeadSelfTest.run(wrongCipher));
    }

    @Test
    @DisplayName("decodeKey refuses wrong lengths, non-canonical encodings, the identity, small-order and mixed-order points (spec §2.2, §5 step 2)")
    void decodeKeyRefusals() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertNotNull(SaplingNoteCrypto.decodeKey(g.toBytes()));
        assertNull(SaplingNoteCrypto.decodeKey(null));
        assertNull(SaplingNoteCrypto.decodeKey(new byte[31]));
        assertNull(SaplingNoteCrypto.decodeKey(new byte[33]));
        assertNull(SaplingNoteCrypto.decodeKey(JubjubPoint.IDENTITY.toBytes()), "identity");
        JubjubPoint order2 = JubjubPoint.fromAffine(BigInteger.ZERO, BASE_FIELD_PRIME.subtract(BigInteger.ONE));
        assertNull(SaplingNoteCrypto.decodeKey(order2.toBytes()), "order 2");
        assertNull(SaplingNoteCrypto.decodeKey(g.add(order2).toBytes()), "mixed order");
        JubjubPoint fullGenerator = JubjubPoint.FULL_GENERATOR;
        assertNull(SaplingNoteCrypto.decodeKey(fullGenerator.toBytes()), "full-order generator");
        assertNull(SaplingNoteCrypto.decodeKey(fullGenerator.scalarMul(SUBGROUP_ORDER).toBytes()), "small-order component only");
        byte[] nonCanonical = new byte[32];
        byte[] p = BASE_FIELD_PRIME.toByteArray();
        for (int i = 0; i < 32 && i < p.length; i++) nonCanonical[i] = p[p.length - 1 - i]; // v = p, little-endian
        assertNull(SaplingNoteCrypto.decodeKey(nonCanonical), "v = p");
        byte[] zeroUSignSet = JubjubPoint.IDENTITY.toBytes();
        zeroUSignSet[31] |= (byte) 0x80;
        assertNull(SaplingNoteCrypto.decodeKey(zeroUSignSet), "u = 0 with the sign bit set (ZIP 216)");
    }

    @Test
    @DisplayName("decrypt: a short ciphertext, a wrong key and a flipped bit are input failures (null), never exceptions")
    void decryptInputFailures() {
        byte[] key = new byte[32];
        byte[] ct = SaplingNoteCrypto.encrypt(key, new byte[41]);
        assertEquals(57, ct.length);
        assertNull(SaplingNoteCrypto.decrypt(key, new byte[15]));
        byte[] otherKey = key.clone();
        otherKey[0] = 1;
        assertNull(SaplingNoteCrypto.decrypt(otherKey, ct));
        for (int bit = 0; bit < ct.length * 8; bit += 37) {
            byte[] tampered = ct.clone();
            tampered[bit / 8] ^= (byte) (1 << (bit % 8));
            assertNull(SaplingNoteCrypto.decrypt(key, tampered), "bit " + bit);
        }
    }

    @Test
    @DisplayName("A missing AEAD provider is a platform fault (IllegalStateException), never \"not mine\"")
    void platformFault() {
        DkgEncryptedHarness.withoutProvider("SunJCE", () -> {
            assertThrows(IllegalStateException.class, NoteAeadSelfTest::run);
            assertThrows(IllegalStateException.class, () -> SaplingNoteCrypto.decrypt(new byte[32], new byte[57]));
            assertThrows(IllegalStateException.class, () -> SaplingNoteCrypto.encrypt(new byte[32], new byte[41]));
        });
    }

    @Test
    @DisplayName("Agree and DerivePublic refuse a zero or out-of-range scalar")
    void scalarRange() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertThrows(IllegalArgumentException.class, () -> SaplingNoteCrypto.agree(BigInteger.ZERO, g));
        assertThrows(IllegalArgumentException.class, () -> SaplingNoteCrypto.agree(SUBGROUP_ORDER, g));
        assertThrows(IllegalArgumentException.class, () -> SaplingNoteCrypto.derivePublic(BigInteger.ZERO));
        assertArrayEquals(g.scalarMul(BigInteger.valueOf(8)).toBytes(), SaplingNoteCrypto.agree(BigInteger.ONE, g).toBytes(),
                "Agree(1, G) = [8]·G");
    }
}
