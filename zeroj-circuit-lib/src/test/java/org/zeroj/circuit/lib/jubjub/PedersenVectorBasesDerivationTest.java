package org.zeroj.circuit.lib.jubjub;

import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 M3: re-derives every {@code pedersen-jubjub-vector-v1} base with Zcash's
 * {@code FindGroupHash} ({@code docs/specs/pedersen-jubjub-vector-v1.md} §1–§2), using
 * BouncyCastle's BLAKE2s — not code the library ships — and ZeroJ's ZIP-216 decoder.
 *
 * <p>First the same derivation must reproduce the twelve Zcash Sapling generators from
 * {@code sapling-crypto} 0.9.0 bit-for-bit, which shows it is Zcash's group hash and not merely
 * self-consistent. Then it must reproduce the pinned {@link PedersenVectorBases}.
 */
class PedersenVectorBasesDerivationTest {

    private static final byte[] URS =
            "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0".getBytes(StandardCharsets.US_ASCII);

    /** {@code (personalisation, message, counter, u, v)} from spec §1.1. */
    private record Known(String personalization, byte[] message, int counter, String u, String v) {}

    private static final List<Known> ZCASH = List.of(
            new Known("Zcash_cv", ascii("v"), 0,
                    "273f910d9ecc1615d8618ed1d15fef4e9472c89ac043042d36183b2cb4d7ef51",
                    "466a7e3a82f67ab1d32294fd89774ad6bc3332d0fa1ccd18a77a81f50667c8d7"),
            new Known("Zcash_cv", ascii("r"), 0,
                    "6800f4fa0f001cfc7ff6826ad58004b4d1d8da41af03744e3bce3b7793664337",
                    "6d81d3a9cb45dedbe6fb2a6e1e22ab50ad46f1b0473b803b3caefab9380b6a8b"),
            new Known("Zcash_PH", ascii("r"), 4,
                    "26eb9f8a9ec72a8ca1409aa1f33bec2cf0919d06ffb1ecdaa5143b34a8e36462",
                    "114b7501ad104c57949d77476e262c9596b78beafa9cc44cd4fc6365796c77ac"),
            new Known("Zcash_PH", le32(0), 5,
                    "73c016a42ded9578b5ea25de7ec0e3782f0c718f6f0fbadd194e42926f661b51",
                    "289e87a2d3521b5779c9166b837edc5ef9472e8bc04e463277bfabd432243cca"),
            new Known("Zcash_PH", le32(1), 0,
                    "15a36d1f0f390d8852a35a8c1908dd87a361ee3fd48fdf77b9819dc82d90607e",
                    "015d8c7f5b43fe33f7891142c001d9251f3abeeb98fad3e87b0dc53c4ebf1891"),
            new Known("Zcash_PH", le32(2), 0,
                    "664321a58246e2f6eb69ae39f5c84210bae8e5c46641ae5c76d6f7c2b67fc475",
                    "362e1500d24eee9ee000a46c8e8ce8538bb22a7f1784b49880ed502c9793d457"),
            new Known("Zcash_PH", le32(3), 0,
                    "323a6548ce9d9876edc5f4a9cff29fd57d02d50e654b87f24c767804c1c4a2cc",
                    "2f7ee40c4b56cad891070acbd8d947b75103afa1a11f6a8584714beca33570e9"),
            new Known("Zcash_PH", le32(4), 0,
                    "3bd2666000b5479689b64b4e03362796efd5931305f2f0bf46809430657f82d1",
                    "494bc52103ab9d0a397832381406c9e5b3b9d8095859d14c99968299c3658aef"),
            new Known("Zcash_PH", le32(5), 0,
                    "63447b2ba31bb28ada049746d76d3ee51d9e5ca21135ff6fcb3c023258d32079",
                    "64ec4689e8bfb6e564cdb1070a136a28a80200d2c66b13a7436082119f8d629a"),
            new Known("Zcash_G_", new byte[0], 2,
                    "0926d4f32059c712d418a7ff26753b6ad5b9a7d3ef8e282747bf46920a95a753",
                    "57a1019e6de9b67553bb37d0c21cfd056d65674dcedbddbc305632adaaf2b530"),
            new Known("Zcash_H_", new byte[0], 1,
                    "1457a50231cde2df704303f1e8906081adf2d038f2fbb8203af2dbefb96e2571",
                    "54b6d10718df2a7adec901840f4948cc50df51eaf5a149d2467af9f7e05de8e7"),
            new Known("Zcash_J_", new byte[0], 1,
                    "2400c2e2e3362644db56b6db8d8075ede81cee09a561229e2ce33921888d30db",
                    "61369d5440bf84a5fc9e8a15a096ba8fe155b8e8ffff2e42a3f7fa36c72b0065"));

    /**
     * The test-side hash itself, against published vectors (ADR-0051 verification strategy): RFC
     * 7693 Appendix B (BLAKE2s-256 of "abc", no key, no personalisation). The personalised form is
     * covered by the Zcash known answers below, whose derivation it drives.
     */
    @Test
    @DisplayName("Test-side BLAKE2s matches RFC 7693 Appendix B")
    void blake2sRfc7693() {
        var blake2s = new Blake2sDigest(256);
        byte[] abc = ascii("abc");
        blake2s.update(abc, 0, abc.length);
        byte[] out = new byte[32];
        blake2s.doFinal(out, 0);
        assertEquals("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
                HexFormat.of().formatHex(out));

        // The empty-input digest, cross-checked against CPython's hashlib.blake2s.
        var empty = new Blake2sDigest(256);
        byte[] emptyOut = new byte[32];
        empty.doFinal(emptyOut, 0);
        assertEquals("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
                HexFormat.of().formatHex(emptyOut));
    }

    @Test
    @DisplayName("FindGroupHash reproduces all twelve Zcash Sapling generators (sapling-crypto 0.9.0)")
    void zcashKnownAnswers() {
        for (Known k : ZCASH) {
            Derived d = findGroupHash(ascii(k.personalization()), k.message());
            assertEquals(k.counter(), d.counter(), k.personalization() + " counter");
            assertEquals(new BigInteger(k.u(), 16), d.point().affineU(), k.personalization() + " u");
            assertEquals(new BigInteger(k.v(), 16), d.point().affineV(), k.personalization() + " v");
        }
    }

    @Test
    @DisplayName("The pinned vector bases equal FindGroupHash(\"ZeroJ_PV\", ...)")
    void pinnedBasesMatchDerivation() {
        byte[] personalization = ascii(PedersenVectorBases.PERSONALIZATION);
        assertEquals(8, personalization.length);
        for (int i = 0; i < PedersenVectorBases.MAX_DIMENSION; i++) {
            JubjubPoint derived = findGroupHash(personalization, le32(i)).point();
            assertTrue(derived.projectiveEquals(PedersenVectorBases.valueBase(i)), "G_" + i);
        }
        assertTrue(findGroupHash(personalization, ascii("r")).point()
                .projectiveEquals(PedersenVectorBases.blindingBase()), "H_V");
    }

    @Test
    @DisplayName("All 17 bases are distinct, non-identity subgroup points, distinct from v1's G and H")
    void baseProperties() {
        List<JubjubPoint> all = new ArrayList<>();
        for (int i = 0; i < PedersenVectorBases.MAX_DIMENSION; i++) all.add(PedersenVectorBases.valueBase(i));
        all.add(PedersenVectorBases.blindingBase());
        Set<String> encodings = new HashSet<>();
        for (JubjubPoint p : all) {
            assertTrue(p.isInSubgroup());
            assertFalse(p.isIdentity());
            assertTrue(encodings.add(HexFormat.of().formatHex(p.toBytes())), "duplicate base");
            assertFalse(p.projectiveEquals(JubjubPoint.SUBGROUP_GENERATOR));
            assertFalse(p.projectiveEquals(PedersenCommitment.H));
        }
    }

    // ------------------------------------------------------------------
    //  FindGroupHash, written from spec §1
    // ------------------------------------------------------------------

    private record Derived(JubjubPoint point, int counter) {}

    private static Derived findGroupHash(byte[] personalization, byte[] message) {
        byte[] tag = Arrays.copyOf(message, message.length + 1);
        for (int counter = 0; counter <= 254; counter++) {
            tag[message.length] = (byte) counter;
            JubjubPoint q = groupHash(personalization, tag);
            if (q != null) return new Derived(q, counter);
        }
        throw new IllegalStateException("FindGroupHash did not converge");
    }

    private static JubjubPoint groupHash(byte[] personalization, byte[] message) {
        var blake2s = new Blake2sDigest(null, 32, null, personalization);
        blake2s.update(URS, 0, URS.length);
        blake2s.update(message, 0, message.length);
        byte[] h = new byte[32];
        blake2s.doFinal(h, 0);
        JubjubPoint p;
        try {
            p = JubjubPoint.fromBytes(h);
        } catch (IllegalArgumentException notAPoint) {
            return null;
        }
        JubjubPoint q = p.mulByCofactor();
        return q.isIdentity() ? null : q.normalized();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] le32(int i) {
        return new byte[]{(byte) i, (byte) (i >>> 8), (byte) (i >>> 16), (byte) (i >>> 24)};
    }
}
