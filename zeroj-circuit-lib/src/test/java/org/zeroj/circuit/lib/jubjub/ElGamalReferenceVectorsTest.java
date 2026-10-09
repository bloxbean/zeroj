package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * ADR-0052 M0/M1: the library against the independent {@code elgamal-jubjub-v1} reference.
 *
 * <p>{@code src/test/resources/elgamal-reference/reference-output.txt} was produced by a
 * standard-library Python implementation written from {@code docs/specs/elgamal-jubjub-v1.md}
 * and {@code docs/specs/pedersen-jubjub-v1.md} only: affine arithmetic, generic Tonelli–Shanks,
 * linear discrete logs. No ZeroJ Java source was read. Every value below is therefore computed
 * twice, by unrelated code, and compared here. The reference also cross-checked the
 * {@code zeroj-usecases} prototype's vectors. Regenerate with
 * {@code python3 elgamal_jubjub_v1_reference.py} in that directory.
 */
class ElGamalReferenceVectorsTest {

    private static final String RESOURCE = "/elgamal-reference/reference-output.txt";
    private static final HexFormat HEX = HexFormat.of();
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    private static Map<String, String> ref;

    @BeforeAll
    static void load() throws IOException {
        ref = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(
                ElGamalReferenceVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE);
             var reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                ref.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
    }

    private static String get(String key) {
        return Objects.requireNonNull(ref.get(key), () -> "missing reference key " + key);
    }

    private static BigInteger num(String key) {
        String s = get(key);
        boolean negative = s.startsWith("-");
        String body = negative ? s.substring(1) : s;
        BigInteger value = body.startsWith("0x") ? new BigInteger(body.substring(2), 16) : new BigInteger(body);
        return negative ? value.negate() : value;
    }

    private static byte[] bytes(String key) {
        return HEX.parseHex(get(key));
    }

    private static BigInteger scalar(String tag) {
        return num("scalar." + tag);
    }

    /** {@code scalar(tag) = OS2IP(SHA-256("zeroj.elgamal.v1.test." + tag)) mod l} (spec §12). */
    private static BigInteger derive(String tag) throws NoSuchAlgorithmException {
        byte[] h = MessageDigest.getInstance("SHA-256")
                .digest(("zeroj.elgamal.v1.test." + tag).getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, h).mod(JubjubCurve.SUBGROUP_ORDER);
    }

    private static void assertPoint(String prefix, JubjubPoint point) {
        JubjubPoint n = point.normalized();
        assertEquals(num(prefix + ".u"), n.u(), prefix + ".u");
        assertEquals(num(prefix + ".v"), n.v(), prefix + ".v");
    }

    private static void assertCiphertext(String prefix, ElGamalCiphertext c) {
        assertPoint(prefix + ".A", c.handle());
        assertPoint(prefix + ".B", c.blinded());
        assertArrayEquals(bytes(prefix + ".encoding"), c.encode(), prefix + ".encoding");
    }

    private static List<BigInteger> numbers(String key) {
        List<BigInteger> out = new ArrayList<>();
        for (String part : get(key).split(",")) out.add(new BigInteger(part.substring(2), 16));
        return out;
    }

    @Test
    @DisplayName("The reference run passed its own checks and matched every spec pin")
    void referenceRunPassed() {
        assertEquals("elgamal-jubjub-v1", get("profile"));
        assertEquals("pass", get("result"));
        int checks = 0;
        for (var e : ref.entrySet()) {
            if (e.getKey().startsWith("check.") || e.getKey().startsWith("spec_match.")) {
                assertEquals("true", e.getValue(), e.getKey());
                checks++;
            }
        }
        assertTrue(checks > 100, "checks: " + checks);
        assertEquals(JubjubCurve.BASE_FIELD_PRIME, num("curve.p"));
        assertEquals(JubjubCurve.SUBGROUP_ORDER, num("curve.l"));
        assertEquals(JubjubCurve.D, num("curve.d"));
        assertPoint("G", G);
        assertArrayEquals(bytes("G.encoding"), G.toBytes());
    }

    @Test
    @DisplayName("§12 test scalars: the Java derivation equals the reference's")
    void scalars() throws NoSuchAlgorithmException {
        for (String tag : List.of("sk", "k0", "k1", "k16", "k64", "share1", "share2", "share3",
                "ballot1", "ballot2", "ballot3", "ballot4", "ballot5", "wrap1", "wrap2")) {
            assertEquals(scalar(tag), derive(tag), tag);
        }
    }

    @Test
    @DisplayName("Single key: public key, encryptions at widths 1/16/64, add, scale and decryption")
    void singleKey() {
        ElGamalSecretKey sk = ElGamalSecretKey.of(scalar("sk"));
        assertPoint("single.pk", sk.publicKey().point());
        assertArrayEquals(bytes("single.pk.encoding"), sk.publicKey().encode());
        NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
        Map<String, ElGamalCiphertext> cts = new LinkedHashMap<>();
        for (String c : List.of("m0w1", "m1w1", "m12345w16", "mmaxw64")) {
            String p = "single.enc." + c;
            ElGamalCiphertext ct = ElGamal.encryptWithRandomness(
                    ctx, num(p + ".m"), num(p + ".w").intValueExact(), num(p + ".k"));
            assertCiphertext(p, ct);
            assertEquals(num(p + ".bound"), ct.bound(), p + ".bound");
            if (ref.containsKey(p + ".dec")) {
                assertEquals(num(p + ".dec").longValueExact(),
                        ElGamal.decryptWithSecret(ct, sk, ct.bound().longValueExact()));
            }
            cts.put(c, ct);
        }
        ElGamalCiphertext add01 = cts.get("m0w1").add(cts.get("m1w1"));
        assertCiphertext("single.add01", add01);
        assertEquals(num("single.add01.bound"), add01.bound());
        assertEquals(num("single.add01.dec").longValueExact(), ElGamal.decryptWithSecret(add01, sk, 2));
        ElGamalCiphertext scaled = cts.get("m12345w16").scale(3);
        assertCiphertext("single.scale3_12345", scaled);
        assertEquals(num("single.scale3_12345.bound"), scaled.bound());
        assertEquals(num("single.scale3_12345.dec").longValueExact(),
                ElGamal.decryptWithSecret(scaled, sk, scaled.bound().longValueExact()));
        // The bound rule's boundary for width 64 (c·(2^64 − 1) < l).
        ElGamalCiphertext top = cts.get("mmaxw64");
        assertEquals(num("bound.w64.b"), top.bound());
        top.scale(num("bound.w64.max_scale_accepted"));
        assertThrows(IllegalArgumentException.class, () -> top.scale(num("bound.w64.min_scale_refused")));
    }

    @Test
    @DisplayName("n-of-n: shares, joint key, registered order, ballots, sum, shares, statements and tally")
    void nOfN() {
        List<ElGamalSecretKey> keys = new ArrayList<>();
        List<VerifiedKeyShare> shares = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            ElGamalSecretKey k = ElGamalSecretKey.of(num("nofn.share" + j + ".sk"));
            assertArrayEquals(bytes("nofn.share" + j + ".pk.encoding"), k.publicKey().encode());
            keys.add(k);
            shares.add(VerifiedKeyShare.fromSecret(k));
        }
        NOfNKeyContext ctx = ElGamalPublicKey.aggregate(shares);
        assertPoint("nofn.pk", ctx.jointKey().point());
        assertArrayEquals(bytes("nofn.pk.encoding"), ctx.jointKey().encode());
        String[] order = get("nofn.registered_encodings").split(",");
        for (int i = 0; i < order.length; i++) {
            assertArrayEquals(HEX.parseHex(order[i]), ctx.shares().get(i).publicKey().encode(), "registered " + i);
        }

        List<ElGamalCiphertext> ballots = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            String p = "nofn.ballot" + i;
            ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, num(p + ".m"), 1, num(p + ".k"));
            assertCiphertext(p, c);
            ballots.add(c);
        }
        AtomicReference<EncryptionStatement> statement = new AtomicReference<>();
        ElGamal.admit(ballots.get(0).raw(), ctx, 1, s -> { statement.set(s); return true; });
        assertEquals(numbers("nofn.encstmt.ballot1.publicInputs"), statement.get().publicInputs());

        ElGamalCiphertext sum = ElGamalCiphertext.sum(ballots);
        assertCiphertext("nofn.sum", sum);
        assertEquals(num("nofn.sum.bound"), sum.bound());
        List<VerifiedDecryptionShare> ds = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            VerifiedDecryptionShare d = ElGamal.decryptionShare(keys.get(j - 1), sum);
            assertPoint("nofn.D" + j, d.share());
            assertArrayEquals(bytes("nofn.D" + j + ".encoding"), d.encode());
            assertEquals(numbers("nofn.dleq" + j + ".publicInputs"), d.statement().publicInputs());
            assertEquals(numbers("nofn.pop" + j + ".publicInputs"), keys.get(j - 1).possessionStatement().publicInputs());
            ds.add(d);
        }
        assertEquals(num("nofn.tally").longValueExact(), ElGamal.decrypt(sum, ds, 5));
        List<JubjubPoint> points = ds.stream().map(VerifiedDecryptionShare::share).toList();
        assertPoint("nofn.M", RawElGamalCiphertext.unmask(sum.blinded(), points));
    }

    @Test
    @DisplayName("Registered-share order is unsigned lexicographic over encodings (the sortvec vector)")
    void sortOrder() {
        List<VerifiedKeyShare> shares = new ArrayList<>();
        for (String multiple : get("sortvec.multiples").split(",")) {
            shares.add(VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(new BigInteger(multiple))));
        }
        NOfNKeyContext ctx = ElGamalPublicKey.aggregate(shares);
        String[] multiples = get("sortvec.multiples").split(",");
        String[] encodings = get("sortvec.encodings").split(",");
        String[] expected = get("sortvec.registered_order").split(",");
        for (int i = 0; i < expected.length; i++) {
            int index = Arrays.asList(multiples).indexOf(expected[i]);
            assertArrayEquals(HEX.parseHex(encodings[index]), ctx.shares().get(i).publicKey().encode());
        }
    }

    @Test
    @DisplayName("ADR counterexamples: wrong secret, mixed key, forged share, wrapped sum")
    void counterexamples() {
        // Wrong secret: (G, 4G) under PK = 3G.
        NOfNKeyContext three = NOfNKeyContext.singleKey(ElGamalSecretKey.of(BigInteger.valueOf(3)));
        ElGamalCiphertext c = ElGamal.encryptWithRandomness(three, BigInteger.ONE, 1, BigInteger.ONE);
        assertPoint("cx.wrongsecret.PK", three.jointKey().point());
        assertPoint("cx.wrongsecret.A", c.handle());
        assertPoint("cx.wrongsecret.B", c.blinded());
        assertThrows(IllegalArgumentException.class,
                () -> ElGamal.decryptWithSecret(c, ElGamalSecretKey.of(num("cx.wrongsecret.secret_wrong")), 1));
        assertEquals(num("cx.wrongsecret.dec_right").longValueExact(),
                ElGamal.decryptWithSecret(c, ElGamalSecretKey.of(num("cx.wrongsecret.secret_right")), 1));

        // Mixed key: refused safely; the raw sum is the reference's.
        NOfNKeyContext two = NOfNKeyContext.singleKey(ElGamalSecretKey.of(BigInteger.TWO));
        ElGamalCiphertext c2 = ElGamal.encryptWithRandomness(two, BigInteger.ONE, 1, BigInteger.ONE);
        assertArrayEquals(bytes("cx.mixed.c1.encoding"), c.encode());
        assertArrayEquals(bytes("cx.mixed.c2.encoding"), c2.encode());
        assertThrows(IllegalArgumentException.class, () -> c.add(c2));
        assertArrayEquals(bytes("cx.mixed.sum.encoding"), c.raw().add(c2.raw()).encode());

        // Forged share: keys 3G, 5G; m = 1, k = 7.
        ElGamalSecretKey s1 = ElGamalSecretKey.of(BigInteger.valueOf(3));
        ElGamalSecretKey s2 = ElGamalSecretKey.of(BigInteger.valueOf(5));
        NOfNKeyContext ctx = ElGamalPublicKey.aggregate(
                List.of(VerifiedKeyShare.fromSecret(s1), VerifiedKeyShare.fromSecret(s2)));
        assertPoint("cx.forged.PK", ctx.jointKey().point());
        ElGamalCiphertext f = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, BigInteger.valueOf(7));
        assertPoint("cx.forged.A", f.handle());
        assertPoint("cx.forged.B", f.blinded());
        assertPoint("cx.forged.D1", ElGamal.decryptionShare(s1, f).share());
        assertPoint("cx.forged.D2", ElGamal.decryptionShare(s2, f).share());
        JubjubPoint forged = JubjubPoint.fromAffine(num("cx.forged.D2_forged.u"), num("cx.forged.D2_forged.v"));
        ElGamalHostApiTest.KnownSecretsDleqVerifier verifier =
                new ElGamalHostApiTest.KnownSecretsDleqVerifier().know(BigInteger.valueOf(3), BigInteger.valueOf(5));
        assertThrows(IllegalArgumentException.class,
                () -> VerifiedDecryptionShare.verify(f, s2.publicKey(), forged, verifier));

        // Wrapped sum: decrypts to 0 raw; Enc(l − 1) is refused at width 64.
        ElGamalSecretKey sk = ElGamalSecretKey.of(scalar("sk"));
        JubjubPoint pk = sk.publicKey().point();
        BigInteger m1 = num("cx.wrap.m1");
        RawElGamalCiphertext w1 = RawElGamalCiphertext.of(G.scalarMul(num("cx.wrap.k1")),
                G.scalarMul(m1).add(pk.scalarMul(num("cx.wrap.k1"))));
        RawElGamalCiphertext w2 = RawElGamalCiphertext.of(G.scalarMul(num("cx.wrap.k2")),
                G.add(pk.scalarMul(num("cx.wrap.k2"))));
        assertArrayEquals(bytes("cx.wrap.c1.encoding"), w1.encode());
        assertArrayEquals(bytes("cx.wrap.c2.encoding"), w2.encode());
        assertArrayEquals(bytes("cx.wrap.sum.encoding"), w1.add(w2).encode());
        assertThrows(IllegalArgumentException.class,
                () -> ElGamal.encryptWithRandomness(NOfNKeyContext.singleKey(sk), m1, 64, num("cx.wrap.k1")));
    }

    @Test
    @DisplayName("Decoding vectors: every reject is rejected, every accept round-trips")
    void decodingVectors() {
        int cases = 0;
        for (String key : ref.keySet()) {
            if (!key.startsWith("decode_neg.") || !key.endsWith(".input")) continue;
            String name = key.substring("decode_neg.".length(), key.length() - ".input".length());
            String p = "decode_neg." + name;
            byte[] input = bytes(p + ".input");
            boolean accept = get(p + ".expected").equals("accept");
            String kind = get(p + ".kind");
            cases++;
            try {
                byte[] reencoded = switch (kind) {
                    case "ciphertext" -> RawElGamalCiphertext.decode(input).encode();
                    case "publickey" -> VerifiedKeyShare.verify(input, s -> true).publicKey().encode();
                    default -> throw new AssertionError("unknown kind " + kind);
                };
                if (!accept) fail(name + " should be rejected (" + get(p + ".expected") + ")");
                assertArrayEquals(input, reencoded, name);
            } catch (IllegalArgumentException e) {
                if (accept) fail(name + " should be accepted: " + e.getMessage());
            }
        }
        assertTrue(cases >= 22, "decode cases: " + cases);
    }

    @Test
    @DisplayName("Affine vectors: canonical, on-curve, in the subgroup, and non-identity for keys")
    void affineVectors() {
        int cases = 0;
        for (String key : ref.keySet()) {
            if (!key.startsWith("affine_neg.") || !key.endsWith(".expected")) continue;
            String p = key.substring(0, key.length() - ".expected".length());
            boolean accept = get(key).equals("accept");
            String kind = get(p + ".kind");
            cases++;
            try {
                JubjubPoint point = ElGamalEncodings.affineSubgroupPoint(num(p + ".u"), num(p + ".v"), p);
                if (kind.equals("publickey")) ElGamalEncodings.requireKeyPoint(point, p);
                if (!accept) fail(p + " should be rejected (" + get(key) + ")");
            } catch (IllegalArgumentException e) {
                if (accept) fail(p + " should be accepted: " + e.getMessage());
            }
        }
        assertTrue(cases >= 11, "affine cases: " + cases);
    }
}
