package org.zeroj.circuit.lib.jubjub;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * ADR-0054 M1: the HPKE building blocks against published vectors only (see
 * {@code src/test/resources/standard-vectors/README.md}). No expected value comes from ZeroJ code.
 */
class HpkeKnownAnswerTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final ObjectMapper JSON = new ObjectMapper();

    private static JsonNode load(String name) throws IOException {
        try (InputStream in = Objects.requireNonNull(
                HpkeKnownAnswerTest.class.getResourceAsStream("/standard-vectors/" + name), name)) {
            return JSON.readTree(in);
        }
    }

    private static byte[] hex(JsonNode node, String field) {
        return HEX.parseHex(node.get(field).asText());
    }

    // ---------------------------------------------------------------- RFC 9180 A.2.1

    @Test
    @DisplayName("RFC 9180 A.2.1 (Base): key derivation, key schedule and all 257 encryptions, sealed and opened")
    void rfc9180A21() throws Exception {
        JsonNode suite = load("hpke-x25519-sha256-chacha20poly1305-base.json");
        assertEquals(1, suite.size());
        JsonNode v = suite.get(0);
        assertEquals(0, v.get("mode").asInt());
        assertEquals(Hpke.KEM_ID, v.get("kem_id").asInt());
        assertEquals(Hpke.KDF_ID, v.get("kdf_id").asInt());
        assertEquals(Hpke.AEAD_ID, v.get("aead_id").asInt());

        // DeriveKeyPair (§7.1.3) and SerializePublicKey.
        byte[] skE = Hpke.deriveKeyPair(hex(v, "ikmE"));
        byte[] skR = Hpke.deriveKeyPair(hex(v, "ikmR"));
        assertArrayEquals(hex(v, "skEm"), skE);
        assertArrayEquals(hex(v, "skRm"), skR);
        assertArrayEquals(hex(v, "pkEm"), X25519Bytes.publicFromPrivate(skE));
        assertArrayEquals(hex(v, "pkRm"), X25519Bytes.publicFromPrivate(skR));

        // SetupBaseS with the vector's ephemeral key; the key schedule outputs.
        byte[] info = hex(v, "info");
        byte[][] enc = new byte[1][];
        Hpke.Context sender = Hpke.setupBaseSWithEphemeral(skE, hex(v, "pkRm"), info, enc);
        assertArrayEquals(hex(v, "enc"), enc[0]);
        assertArrayEquals(hex(v, "key"), sender.key());
        assertArrayEquals(hex(v, "base_nonce"), sender.baseNonce());
        Hpke.Context recipient = Hpke.setupBaseR(enc[0], skR, info);
        assertArrayEquals(hex(v, "key"), recipient.key());
        assertArrayEquals(hex(v, "base_nonce"), recipient.baseNonce());

        // Every listed encryption, at its own sequence number (§5.2).
        JsonNode encryptions = v.get("encryptions");
        assertEquals(257, encryptions.size());
        for (int seq = 0; seq < encryptions.size(); seq++) {
            JsonNode e = encryptions.get(seq);
            assertArrayEquals(hex(e, "nonce"), xorNonce(sender.baseNonce(), seq), "nonce " + seq);
            sender.setSequence(seq);
            assertArrayEquals(hex(e, "ct"), sender.seal(hex(e, "aad"), hex(e, "pt")), "seal " + seq);
            recipient.setSequence(seq);
            assertArrayEquals(hex(e, "pt"), recipient.open(hex(e, "aad"), hex(e, "ct")), "open " + seq);
        }

        // Single-shot is sequence 0.
        Hpke.Sealed single = Hpke.sealBaseWithEphemeral(skE, hex(v, "pkRm"), info,
                hex(encryptions.get(0), "aad"), hex(encryptions.get(0), "pt"));
        assertArrayEquals(hex(v, "enc"), single.enc());
        assertArrayEquals(hex(encryptions.get(0), "ct"), single.ct());
        assertArrayEquals(hex(encryptions.get(0), "pt"),
                Hpke.openBase(single.enc(), skR, info, hex(encryptions.get(0), "aad"), single.ct()));
    }

    @Test
    @DisplayName("Context sequence (§5.2): seal and open advance it, a failed open does not, and the limit is refused (review C-3)")
    void contextSequence() throws Exception {
        JsonNode v = load("hpke-x25519-sha256-chacha20poly1305-base.json").get(0);
        byte[] skE = hex(v, "skEm");
        byte[] skR = hex(v, "skRm");
        byte[] info = hex(v, "info");
        byte[][] enc = new byte[1][];
        Hpke.Context sender = Hpke.setupBaseSWithEphemeral(skE, hex(v, "pkRm"), info, enc);
        Hpke.Context recipient = Hpke.setupBaseR(enc[0], skR, info);

        // No setSequence: the k-th call uses sequence k, so the vector's encryptions come out in order.
        JsonNode encryptions = v.get("encryptions");
        for (int seq = 0; seq < encryptions.size(); seq++) {
            JsonNode e = encryptions.get(seq);
            byte[] ct = hex(e, "ct");
            assertArrayEquals(ct, sender.seal(hex(e, "aad"), hex(e, "pt")), "seal " + seq);
            byte[] tampered = ct.clone();
            tampered[0] ^= 1;
            assertThrows(Hpke.HpkeException.class, () -> recipient.open(hex(e, "aad"), tampered), "tampered " + seq);
            assertArrayEquals(hex(e, "pt"), recipient.open(hex(e, "aad"), ct), "a failed open leaves sequence " + seq);
        }

        // One below the limit still works and advances to it; the next call is refused, both ways.
        JsonNode first = encryptions.get(0);
        sender.setSequence(Long.MAX_VALUE - 1);
        recipient.setSequence(Long.MAX_VALUE - 1);
        byte[] last = sender.seal(hex(first, "aad"), hex(first, "pt"));
        assertArrayEquals(hex(first, "pt"), recipient.open(hex(first, "aad"), last));
        assertThrows(GeneralSecurityException.class, () -> sender.seal(hex(first, "aad"), hex(first, "pt")));
        assertThrows(Hpke.HpkeException.class, () -> recipient.open(hex(first, "aad"), last));
        assertThrows(IllegalArgumentException.class, () -> sender.setSequence(-1));
    }

    private static byte[] xorNonce(byte[] baseNonce, long seq) {
        byte[] out = baseNonce.clone();
        byte[] s = Hpke.i2osp(seq, Hpke.N_N);
        for (int i = 0; i < out.length; i++) out[i] ^= s[i];
        return out;
    }

    // ---------------------------------------------------------------- X25519

    @Test
    @DisplayName("RFC 7748 §5.2 and §6.1 X25519 vectors")
    void rfc7748() throws Exception {
        // §5.2, first vector (scalar, u-coordinate, output).
        assertArrayEquals(HEX.parseHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
                X25519Bytes.dh(X25519Bytes.privateKey(HEX.parseHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")),
                        HEX.parseHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")));
        // §5.2, second vector: the u-coordinate has bit 255 set, which X25519 must mask.
        assertArrayEquals(HEX.parseHex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
                X25519Bytes.dh(X25519Bytes.privateKey(HEX.parseHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")),
                        HEX.parseHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")));
        // §6.1 Diffie–Hellman.
        byte[] a = HEX.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] b = HEX.parseHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assertArrayEquals(HEX.parseHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), X25519Bytes.publicFromPrivate(a));
        assertArrayEquals(HEX.parseHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), X25519Bytes.publicFromPrivate(b));
        byte[] k = HEX.parseHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assertArrayEquals(k, X25519Bytes.dh(X25519Bytes.privateKey(a), X25519Bytes.publicFromPrivate(b)));
        assertArrayEquals(k, X25519Bytes.dh(X25519Bytes.privateKey(b), X25519Bytes.publicFromPrivate(a)));
    }

    /**
     * Every Wycheproof X25519 test through {@link X25519Bytes#dh}. "valid" must match. "invalid"
     * must fail. "acceptable" cases (small-order and twist inputs, non-canonical values) may match
     * or fail, but this implementation's behaviour is pinned: an all-zero result fails (RFC 9180
     * §7.1.4); any other result must equal the shared value.
     */
    @Test
    @DisplayName("Wycheproof x25519_test.json: 518 tests, all-zero results refused")
    void wycheproofX25519() throws Exception {
        JsonNode root = load("wycheproof-x25519_test.json");
        int total = 0, zeroRefused = 0, nonCanonical = 0;
        for (JsonNode group : root.get("testGroups")) {
            for (JsonNode t : group.get("tests")) {
                total++;
                byte[] priv = hex(t, "private");
                byte[] pub = hex(t, "public");
                byte[] shared = hex(t, "shared");
                String result = t.get("result").asText();
                boolean expectZero = X25519Bytes.isAllZero(shared);
                if (!X25519Bytes.isCanonical(pub)) nonCanonical++;
                String id = "tcId " + t.get("tcId").asInt() + " " + t.get("comment").asText();
                if ("invalid".equals(result)) {
                    assertThrows(GeneralSecurityException.class, () -> X25519Bytes.dh(X25519Bytes.privateKey(priv), pub), id);
                } else if (expectZero) {
                    assertThrows(GeneralSecurityException.class, () -> X25519Bytes.dh(X25519Bytes.privateKey(priv), pub), id);
                    zeroRefused++;
                } else {
                    assertArrayEquals(shared, X25519Bytes.dh(X25519Bytes.privateKey(priv), pub), id);
                }
            }
        }
        assertEquals(518, total);
        assertTrue(zeroRefused > 0, "Wycheproof contains all-zero cases");
        assertTrue(nonCanonical > 0, "Wycheproof contains non-canonical public values");
    }

    @Test
    @DisplayName("Canonicality (spec §2.1) and the small-order probe (§2.2) agree with Wycheproof's small-order cases")
    void canonicalAndProbe() {
        byte[] p = X25519Bytes.littleEndian(X25519Bytes.P);
        assertFalse(X25519Bytes.isCanonical(p), "u = p");
        assertFalse(X25519Bytes.isCanonical(X25519Bytes.littleEndian(X25519Bytes.P.add(BigInteger.ONE))), "u = p + 1");
        byte[] high = X25519Bytes.BASE_POINT.clone();
        high[31] |= (byte) 0x80;
        assertFalse(X25519Bytes.isCanonical(high), "bit 255 set");
        assertTrue(X25519Bytes.isCanonical(X25519Bytes.BASE_POINT));
        assertTrue(X25519Bytes.isCanonical(X25519Bytes.littleEndian(X25519Bytes.P.subtract(BigInteger.ONE))));
        assertFalse(X25519Bytes.isCanonical(new byte[31]));
        assertTrue(X25519Bytes.passesSmallOrderProbe(X25519Bytes.BASE_POINT));
        assertFalse(X25519Bytes.passesSmallOrderProbe(new byte[32]), "u = 0");
        byte[] one = new byte[32];
        one[0] = 1;
        assertFalse(X25519Bytes.passesSmallOrderProbe(one), "u = 1");
    }

    @Test
    @DisplayName("Small-order probe: refuses exactly the canonical public values Wycheproof lists with all-zero shared secrets")
    void probeMatchesWycheproof() throws Exception {
        JsonNode root = load("wycheproof-x25519_test.json");
        List<String> checked = new ArrayList<>();
        for (JsonNode group : root.get("testGroups")) {
            for (JsonNode t : group.get("tests")) {
                byte[] pub = hex(t, "public");
                if (!X25519Bytes.isCanonical(pub)) continue;
                boolean zero = X25519Bytes.isAllZero(hex(t, "shared"));
                // Clamping makes "all-zero for one scalar" equivalent to "all-zero for every scalar".
                assertEquals(!zero, X25519Bytes.passesSmallOrderProbe(pub), "tcId " + t.get("tcId").asInt());
                if (zero) checked.add(t.get("public").asText());
            }
        }
        assertTrue(checked.size() >= 3, "small-order canonical cases seen: " + checked.size());
    }

    // ---------------------------------------------------------------- ChaCha20-Poly1305

    @Test
    @DisplayName("RFC 8439 §2.8.2 and Wycheproof chacha20_poly1305_test.json through the JDK cipher Hpke uses")
    void chacha20Poly1305() throws Exception {
        // RFC 8439 §2.8.2.
        byte[] key = HEX.parseHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = HEX.parseHex("070000004041424344454647");
        byte[] aad = HEX.parseHex("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                + "sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
        byte[] expected = HEX.parseHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
                + "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
                + "1ae10b594f09e26a7e902ecbd0600691");
        assertArrayEquals(expected, chacha(Cipher.ENCRYPT_MODE, key, nonce, aad, pt));
        assertArrayEquals(pt, chacha(Cipher.DECRYPT_MODE, key, nonce, aad, expected));

        JsonNode root = load("wycheproof-chacha20_poly1305_test.json");
        int total = 0, run = 0;
        for (JsonNode group : root.get("testGroups")) {
            for (JsonNode t : group.get("tests")) {
                total++;
                byte[] k = hex(t, "key"), iv = hex(t, "iv"), a = hex(t, "aad"), msg = hex(t, "msg");
                byte[] ctTag = concat(hex(t, "ct"), hex(t, "tag"));
                String result = t.get("result").asText();
                String id = "tcId " + t.get("tcId").asInt();
                if (iv.length != Hpke.N_N || k.length != Hpke.N_K) {
                    // HPKE only ever uses 32-byte keys and 12-byte nonces; other sizes must be refused.
                    assertEquals("invalid", result, id);
                    assertThrows(GeneralSecurityException.class, () -> chacha(Cipher.DECRYPT_MODE, k, iv, a, ctTag), id);
                    continue;
                }
                run++;
                if ("valid".equals(result)) {
                    assertArrayEquals(ctTag, chacha(Cipher.ENCRYPT_MODE, k, iv, a, msg), id);
                    assertArrayEquals(msg, chacha(Cipher.DECRYPT_MODE, k, iv, a, ctTag), id);
                } else {
                    assertThrows(GeneralSecurityException.class, () -> chacha(Cipher.DECRYPT_MODE, k, iv, a, ctTag), id);
                }
            }
        }
        assertEquals(325, total);
        assertTrue(run > 250, "12-byte-nonce cases: " + run);
    }

    private static byte[] chacha(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        if (aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    // ---------------------------------------------------------------- HKDF-SHA256

    @Test
    @DisplayName("RFC 5869 A.1–A.3 and Wycheproof hkdf_sha256_test.json through the JDK KDF Hpke uses")
    void hkdf() throws Exception {
        String[][] rfc = {
                // ikm, salt, info, L, prk, okm  (RFC 5869 A.1, A.2, A.3)
                {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", "42",
                        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
                {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                        "82", "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
                {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", "42",
                        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"}};
        KDF kdf = KDF.getInstance("HKDF-SHA256");
        for (String[] r : rfc) {
            HKDFParameterSpec.Builder b = HKDFParameterSpec.ofExtract().addIKM(HEX.parseHex(r[0]));
            if (!r[1].isEmpty()) b.addSalt(HEX.parseHex(r[1]));
            byte[] prk = kdf.deriveData(b.extractOnly());
            assertArrayEquals(HEX.parseHex(r[4]), prk, "prk");
            assertArrayEquals(HEX.parseHex(r[5]), kdf.deriveData(HKDFParameterSpec.expandOnly(
                    new SecretKeySpec(prk, "HKDF-PRK"), HEX.parseHex(r[2]), Integer.parseInt(r[3]))), "okm");
        }

        JsonNode root = load("wycheproof-hkdf_sha256_test.json");
        int total = 0;
        for (JsonNode group : root.get("testGroups")) {
            for (JsonNode t : group.get("tests")) {
                total++;
                byte[] ikm = hex(t, "ikm"), salt = hex(t, "salt"), info = hex(t, "info");
                int size = t.get("size").asInt();
                String id = "tcId " + t.get("tcId").asInt();
                try {
                    HKDFParameterSpec.Builder b = HKDFParameterSpec.ofExtract().addIKM(ikm);
                    if (salt.length > 0) b.addSalt(salt);
                    byte[] prk = kdf.deriveData(b.extractOnly());
                    byte[] okm = kdf.deriveData(HKDFParameterSpec.expandOnly(new SecretKeySpec(prk, "HKDF-PRK"), info, size));
                    if ("invalid".equals(t.get("result").asText())) fail(id + ": expected a refusal");
                    assertArrayEquals(hex(t, "okm"), okm, id);
                } catch (GeneralSecurityException | IllegalArgumentException refused) {
                    assertEquals("invalid", t.get("result").asText(), id + ": " + refused);
                }
            }
        }
        assertEquals(86, total);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
