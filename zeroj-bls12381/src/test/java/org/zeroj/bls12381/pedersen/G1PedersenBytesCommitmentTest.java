package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentProfiles;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M2: the {@code pedersen-bls12-381-g1-bytes-v1} profile ({@code pedersen-bls12-381-g1-v1}
 * §3.2, §5, §10.2). The {@code HashBytesToScalarG1} values are copied from the spec text, which the
 * independent Python reference produced; an in-test RFC 9380 {@code expand_message_xmd} written from
 * the RFC with {@link MessageDigest} is a second oracle, and seeded faults in that oracle (no length
 * suffix, the Jubjub order, the Jubjub tag) show that each of those mistakes changes every value.
 */
class G1PedersenBytesCommitmentTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();

    /** {@code q} as written in spec §1, not taken from the code under test. */
    private static final BigInteger Q = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    /** The Jubjub order {@code l} ({@code pedersen-jubjub-v1}); used only for a seeded fault. */
    private static final BigInteger JUBJUB_L = new BigInteger(
            "0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7", 16);
    private static final byte[] DST_S =
            "ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] JUBJUB_DST =
            "ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DOC = "invoice #42 v3".getBytes(StandardCharsets.UTF_8);

    /** One row of spec §10.2: payload, {@code uniform_bytes}, {@code s}. Copied from the spec text. */
    private record Vector(String name, byte[] payload, String uniform, String s) {}

    private static final List<Vector> VECTORS = List.of(
            new Vector("empty", new byte[0],
                    "62afac35dff21f5a55ff2569ca3c589ef5401cfc94aafe1110981e7c11b89a13d931cede053d24094deda3524a53b80e",
                    "36315447437668222813564192209050807153821375512821708312164585800119004767398"),
            new Vector("pattern 1", G1PedersenBytesStreamTest.pattern(1),
                    "8bf9523b8cfad53f2a64e7c124b637a4a7dc7665d60ccf16e2f3e260b04ddbf366a510869c7e787d331c35a9222f28cc",
                    "17446826573447758279414620354847772216162392386874241427805739007456445167270"),
            new Vector("pattern 55", G1PedersenBytesStreamTest.pattern(55),
                    "e219c89968b49b2d930e377d427b7e56c65473ea36c92f6ce02e5efc83974e69fbba34909f18fe9c76d6147d1a65c7cc",
                    "4769885727161205208895793752532058125538937305946508790125793345496789763442"),
            new Vector("pattern 56", G1PedersenBytesStreamTest.pattern(56),
                    "91f731ee2e033609f3f27e1fcfac8202c8d415cc5ac5597eee949f5a96dfb4965d739d0a583b4273d5dae005a9cc45e0",
                    "44447803342360626358699221713325796379764762051949152351159963802212607565535"),
            new Vector("pattern 64", G1PedersenBytesStreamTest.pattern(64),
                    "d4acbd20d83ed5a47394b62c6e2301b5cdca43e1dabcbe10a0999adb71f7becdcc3fc44e845702440a04e54975607dfd",
                    "21158407019535989839516034496492483749423603674815396635618901986493989358291"),
            new Vector("pattern 129", G1PedersenBytesStreamTest.pattern(129),
                    "90293fbe6622a3d8ed03f6f733dd36eba35919771d85be7e2dc88aac08c8c365a6eeaaee7a536bc38b40d5eac62c06df",
                    "10636700515201835153547363743684853122590858874478588016559740395075199699391"),
            new Vector("pattern 1024", G1PedersenBytesStreamTest.pattern(1024),
                    "d968d99d55ccb4300830c9ca5bf4a5e7e352e71f2b43a1e7357487eab5259b1b7a1540a8bb690e50009d8b4b2fa12797",
                    "51032631804351372587695208740820262018544153677477339797817422801122177762967"),
            new Vector("ASCII abc", "abc".getBytes(StandardCharsets.US_ASCII),
                    "0648a88bce794163caa6686ba5d3bbf550c02d8e842a550642ef33832468ead60428b888e585dfe40c33f79db5f2b3e7",
                    "425016933681726855004915202875618514367841089254790273686098534787449164925"));

    // ---- spec §5 constants ----

    @Test
    @DisplayName("DST_S is exactly the 52-octet ASCII tag of spec §5; DST_prime ends with 0x34; q is the BLS12-381 order")
    void constants() throws Exception {
        byte[] dst = G1PedersenBytesHash.DST.getBytes(StandardCharsets.US_ASCII);
        assertEquals(52, dst.length);
        assertEquals("5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62797465732d76312d4832532d584d443a5348412d323536",
                HEX.formatHex(dst));
        assertArrayEquals(DST_S, dst);
        assertArrayEquals(dst, G1PedersenBytesHash.DST.getBytes(StandardCharsets.UTF_8), "pure ASCII");
        assertEquals(0x34, dst.length, "the DST_prime length octet is 0x34");
        assertEquals(Q, G1PedersenStrict.Q);
        assertNotEquals(JUBJUB_L, G1PedersenStrict.Q);

        // DST_prime = DST_S ‖ 0x34 is what the code feeds the digest: b1 = H(b0 ‖ 0x01 ‖ DST_S ‖ 0x34),
        // recomputed here from the code's own b0.
        byte[][] im = G1PedersenBytesHash.intermediatesForTesting("abc".getBytes(StandardCharsets.US_ASCII));
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(im[0]);
        sha.update((byte) 0x01);
        sha.update(DST_S);
        sha.update((byte) 0x34);
        assertArrayEquals(sha.digest(), im[1], "b1 uses DST_prime = DST_S ‖ 0x34");
    }

    @Test
    @DisplayName("MAX_PAYLOAD_BYTES is 2^61 − 256 = 2305843009213693696")
    void maxPayload() {
        assertEquals(BigInteger.TWO.pow(61).subtract(BigInteger.valueOf(256)),
                BigInteger.valueOf(G1PedersenBytesHash.MAX_PAYLOAD_BYTES));
        assertEquals(2305843009213693696L, G1PedersenBytesHash.MAX_PAYLOAD_BYTES);
    }

    // ---- spec §10.2 test values ----

    @Test
    @DisplayName("Spec §10.2: uniform_bytes and s of all eight payloads, from the spec text")
    void specTestValues() {
        for (Vector v : VECTORS) {
            byte[][] im = G1PedersenBytesHash.intermediatesForTesting(v.payload());
            assertEquals(4, im.length);
            assertEquals(32, im[0].length);
            assertEquals(32, im[1].length);
            assertEquals(32, im[2].length);
            assertEquals(48, im[3].length);
            assertEquals(v.uniform(), HEX.formatHex(im[3]), v.name() + ": uniform_bytes");
            BigInteger s = G1PedersenBytesHash.hashToScalar(v.payload());
            assertEquals(new BigInteger(v.s()), s, v.name() + ": s");
            // s = OS2IP(uniform_bytes) mod q, with q from the spec text.
            assertEquals(new BigInteger(1, HEX.parseHex(v.uniform())).mod(Q), s, v.name() + ": reduction mod q");
            // uniform_bytes = b1 ‖ b2[0..16).
            assertArrayEquals(im[1], Arrays.copyOfRange(im[3], 0, 32), v.name() + ": b1 prefix");
            assertArrayEquals(Arrays.copyOfRange(im[2], 0, 16), Arrays.copyOfRange(im[3], 32, 48), v.name() + ": b2 prefix");
        }
    }

    @Test
    @DisplayName("Independent oracle: RFC 9380 expand_message_xmd over B ‖ I2OSP(n, 8) reproduces the spec values and the code, including b0, b1, b2")
    void independentOracle() throws Exception {
        for (Vector v : VECTORS) {
            byte[][] oracle = expandXmd(frame(v.payload()), DST_S, 48);
            assertEquals(v.uniform(), HEX.formatHex(oracle[oracle.length - 1]), v.name() + ": oracle vs spec");
            assertEquals(new BigInteger(v.s()), new BigInteger(1, oracle[oracle.length - 1]).mod(Q), v.name());
            byte[][] im = G1PedersenBytesHash.intermediatesForTesting(v.payload());
            assertArrayEquals(oracle[0], im[0], v.name() + ": b0");
            assertArrayEquals(oracle[1], im[1], v.name() + ": b1");
            assertArrayEquals(oracle[2], im[2], v.name() + ": b2");
        }
        // Random payloads of random lengths, including around the SHA-256 block boundaries.
        for (int i = 0; i < 200; i++) {
            byte[] payload = new byte[i < 140 ? i : RANDOM.nextInt(5000)];
            RANDOM.nextBytes(payload);
            byte[][] oracle = expandXmd(frame(payload), DST_S, 48);
            assertEquals(new BigInteger(1, oracle[oracle.length - 1]).mod(Q), G1PedersenBytesHash.hashToScalar(payload),
                    "length " + payload.length);
        }
    }

    @Test
    @DisplayName("Seeded faults: no length suffix, the Jubjub order, the Jubjub tag or a length prefix would change every §10.2 value")
    void seededFaultsAreDetected() throws Exception {
        for (Vector v : VECTORS) {
            BigInteger specS = new BigInteger(v.s());
            byte[] specUniform = HEX.parseHex(v.uniform());

            byte[] noSuffix = last(expandXmd(v.payload(), DST_S, 48));
            assertFalse(Arrays.equals(specUniform, noSuffix), v.name() + ": dropping I2OSP(n, 8) must be caught");

            BigInteger modL = new BigInteger(1, specUniform).mod(JUBJUB_L);
            assertNotEquals(specS, modL, v.name() + ": reducing mod the Jubjub order must be caught");

            byte[] jubjubTag = last(expandXmd(frame(v.payload()), JUBJUB_DST, 48));
            assertFalse(Arrays.equals(specUniform, jubjubTag), v.name() + ": the Jubjub tag must be caught");

            byte[] prefix = last(expandXmd(concat(i2osp8(v.payload().length), v.payload()), DST_S, 48));
            if (v.payload().length == 0) {
                // With an empty B, prefix and suffix framing are the same octets: the control case.
                assertArrayEquals(specUniform, prefix, "empty: prefix and suffix framing coincide");
            } else {
                assertFalse(Arrays.equals(specUniform, prefix), v.name() + ": a length prefix must be caught");
            }

            byte[] l64 = last(expandXmd(frame(v.payload()), DST_S, 64));
            assertFalse(Arrays.equals(specUniform, Arrays.copyOf(l64, 48)), v.name() + ": L = 64 must be caught");
        }
    }

    // ---- commit / verify ----

    @Test
    @DisplayName("A fresh commitment opens with its payload and blinding, and with nothing else")
    void opensOnlyWithItsOpening() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(DOC, r);
        assertTrue(PEDERSEN.verifyBytes(c, DOC, r));

        assertFalse(PEDERSEN.verifyBytes(c, Arrays.copyOf(DOC, DOC.length - 1), r), "truncated");
        assertFalse(PEDERSEN.verifyBytes(c, Arrays.copyOf(DOC, DOC.length + 1), r), "extended with a zero");
        assertFalse(PEDERSEN.verifyBytes(c, concat(DOC, DOC), r), "doubled");
        assertFalse(PEDERSEN.verifyBytes(c, new byte[0], r), "empty");
        assertFalse(PEDERSEN.verifyBytes(c, DOC, r.add(BigInteger.ONE).mod(Q)), "other blinding");
        assertFalse(PEDERSEN.verifyBytes(c, DOC, G1Pedersen.randomBlinding(RANDOM)), "random blinding");

        G1PedersenBytesCommitment other = PEDERSEN.commitBytes(DOC, G1Pedersen.randomBlinding(RANDOM));
        assertFalse(PEDERSEN.verifyBytes(other, DOC, r), "other commitment");
    }

    @Test
    @DisplayName("Every single-bit flip of the payload fails verification")
    void everyBitFlipFails() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(DOC, r);
        Set<BigInteger> scalars = new HashSet<>();
        scalars.add(G1PedersenBytesHash.hashToScalar(DOC));
        for (int bit = 0; bit < 8 * DOC.length; bit++) {
            byte[] flipped = DOC.clone();
            flipped[bit >>> 3] ^= (byte) (1 << (bit & 7));
            assertFalse(PEDERSEN.verifyBytes(c, flipped, r), "bit " + bit);
            assertTrue(scalars.add(G1PedersenBytesHash.hashToScalar(flipped)), "distinct scalar for bit " + bit);
        }
    }

    @Test
    @DisplayName("Fresh blindings hide equal payloads; equal openings give equal commitments")
    void hidingAndDeterminism() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        assertEquals(PEDERSEN.commitBytes(DOC, r), PEDERSEN.commitBytes(DOC, r));
        assertNotEquals(PEDERSEN.commitBytes(DOC, G1Pedersen.randomBlinding(RANDOM)),
                PEDERSEN.commitBytes(DOC, G1Pedersen.randomBlinding(RANDOM)));
    }

    @Test
    @DisplayName("An empty payload is a valid payload, distinct from a single zero octet")
    void emptyPayload() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(new byte[0], r);
        assertTrue(PEDERSEN.verifyBytes(c, new byte[0], r));
        assertFalse(PEDERSEN.verifyBytes(c, new byte[1], r));
        assertNotEquals(PEDERSEN.commitBytes(new byte[1], r), c);
        // Empty payload with r = 0 is [s_empty]·G, not the identity.
        G1PedersenBytesCommitment zero = PEDERSEN.commitBytes(new byte[0], BigInteger.ZERO);
        assertNotEquals("c0" + "00".repeat(47), HEX.formatHex(zero.toPointBytes()));
        assertTrue(PEDERSEN.verifyBytes(zero, new byte[0], BigInteger.ZERO));
    }

    @Test
    @DisplayName("Zero and q − 1 are valid blindings; −1, q, q + 1 and 2^300 are NON_CANONICAL_SCALAR, never reduced or echoed")
    void blindingRange() {
        G1PedersenBytesCommitment zero = PEDERSEN.commitBytes(DOC, BigInteger.ZERO);
        assertTrue(PEDERSEN.verifyBytes(zero, DOC, BigInteger.ZERO));
        BigInteger max = Q.subtract(BigInteger.ONE);
        G1PedersenBytesCommitment top = PEDERSEN.commitBytes(DOC, max);
        assertTrue(PEDERSEN.verifyBytes(top, DOC, max));

        BigInteger ten = BigInteger.TEN;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(DOC, ten);
        for (BigInteger bad : new BigInteger[]{BigInteger.ONE.negate(), Q, Q.add(BigInteger.ONE), Q.add(ten), BigInteger.TWO.pow(300)}) {
            CommitmentFormatException e = assertThrows(CommitmentFormatException.class, () -> PEDERSEN.commitBytes(DOC, bad));
            assertEquals(CommitmentError.NON_CANONICAL_SCALAR, e.reason());
            assertFalse(e.getMessage().contains(bad.toString(16)) || e.getMessage().contains(bad.toString()),
                    "the blinding must not appear in the message");
            CommitmentFormatException v = assertThrows(CommitmentFormatException.class, () -> PEDERSEN.verifyBytes(c, DOC, bad));
            assertEquals(CommitmentError.NON_CANONICAL_SCALAR, v.reason());
        }
        // q + 10 ≡ 10 is rejected, not reduced to the valid opening.
        assertTrue(PEDERSEN.verifyBytes(c, DOC, ten));
    }

    @Test
    @DisplayName("Null arguments throw NullPointerException, before the blinding range")
    void nulls() {
        BigInteger r = BigInteger.ONE;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(DOC, r);
        assertThrows(NullPointerException.class, () -> PEDERSEN.commitBytes((byte[]) null, r));
        assertThrows(NullPointerException.class, () -> PEDERSEN.commitBytes(DOC, null));
        assertThrows(NullPointerException.class, () -> PEDERSEN.commitBytes((byte[]) null, Q));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytes(null, DOC, r));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytes(c, (byte[]) null, r));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytes(c, DOC, null));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytes(null, DOC, Q));
        assertThrows(NullPointerException.class, () -> G1PedersenBytesCommitment.decode(null));
        assertThrows(NullPointerException.class, () -> G1PedersenBytesCommitment.CODEC.decodePoint(null));
    }

    @Test
    @DisplayName("The caller's payload array is read, never modified")
    void payloadUntouched() {
        byte[] payload = G1PedersenBytesStreamTest.pattern(3000);
        byte[] copy = payload.clone();
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
        assertArrayEquals(copy, payload);
        assertTrue(PEDERSEN.verifyBytes(c, payload, r));
        assertArrayEquals(copy, payload);
    }

    // ---- relation to the scalar profile (spec §3) ----

    @Test
    @DisplayName("Spec §3: the bytes commitment to B with r is the scalar commitment to s = HashBytesToScalarG1(B) with r; the types stay distinct")
    void sameMapAsScalarProfile() {
        for (Vector v : VECTORS) {
            BigInteger r = G1Pedersen.randomBlinding(RANDOM);
            BigInteger s = new BigInteger(v.s());
            G1PedersenBytesCommitment bytes = PEDERSEN.commitBytes(v.payload(), r);
            G1PedersenCommitment scalar = PEDERSEN.commitScalar(s, r);
            assertArrayEquals(scalar.toPointBytes(), bytes.toPointBytes(), v.name());
            assertTrue(PEDERSEN.verifyScalar(G1PedersenCommitment.decode(bytes.toPointBytes()), s, r),
                    "the scalar opening (s, r) opens the same point");

            // The point carries no profile, but the Java types and descriptors are distinct.
            assertNotEquals(bytes, scalar);
            assertNotEquals(scalar, bytes);
            assertSame(CommitmentProfiles.PEDERSEN_BLS12_381_G1_BYTES_V1, bytes.profile());
            assertSame(CommitmentProfiles.PEDERSEN_BLS12_381_G1_V1, scalar.profile());
            assertNotEquals(bytes.profile(), scalar.profile());
            assertEquals(bytes, G1PedersenBytesCommitment.decode(scalar.toPointBytes()));
        }
    }

    @Test
    @DisplayName("G1PedersenBytesCommitment has no arithmetic and no public constructor")
    void noArithmetic() {
        Class<G1PedersenBytesCommitment> type = G1PedersenBytesCommitment.class;
        assertTrue(Modifier.isFinal(type.getModifiers()));
        assertFalse(type.isRecord());
        assertEquals(0, type.getConstructors().length, "no public constructor");
        Set<String> names = new HashSet<>();
        for (Method m : type.getMethods()) {
            if (m.getDeclaringClass() != Object.class) {
                names.add(m.getName());
            }
        }
        for (String forbidden : new String[]{"add", "subtract", "negate", "withPublicDelta", "multiply", "scale"}) {
            assertFalse(names.contains(forbidden), "no " + forbidden);
        }
        assertEquals(Set.of("decode", "profile", "toPointBytes", "equals", "hashCode", "toString"), names,
                "the exact public surface of spec §8");
    }

    @Test
    @DisplayName("Point bytes round-trip through decode and CODEC; toPointBytes returns a fresh 48-octet copy")
    void encodingRoundTrip() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(DOC, r);
        byte[] wire = c.toPointBytes();
        assertEquals(48, wire.length);
        assertEquals(0x80, wire[0] & 0x80, "compressed flag");
        assertNotSame(wire, c.toPointBytes());
        wire[0] ^= 1;
        assertFalse(Arrays.equals(wire, c.toPointBytes()), "mutating the copy must not change the commitment");
        wire[0] ^= 1;

        G1PedersenBytesCommitment decoded = G1PedersenBytesCommitment.decode(wire);
        assertEquals(c, decoded);
        assertEquals(c.hashCode(), decoded.hashCode());
        assertArrayEquals(wire, decoded.toPointBytes());
        assertEquals(c, G1PedersenBytesCommitment.CODEC.decodePoint(wire));
        assertSame(G1PedersenBytesCommitment.PROFILE, decoded.profile());
        assertSame(CommitmentProfiles.PEDERSEN_BLS12_381_G1_BYTES_V1, G1PedersenBytesCommitment.PROFILE);
        assertSame(G1PedersenBytesCommitment.PROFILE, G1PedersenBytesCommitment.CODEC.profile());
        assertSame(G1PedersenBytesCommitment.class, G1PedersenBytesCommitment.CODEC.commitmentType());
        assertTrue(c.toString().contains(HEX.formatHex(wire)));
        // A decoded commitment opens like the original.
        assertTrue(PEDERSEN.verifyBytes(decoded, DOC, r));

        // Identity decodes; accepting the point accepts no opening.
        byte[] identity = HEX.parseHex("c0" + "00".repeat(47));
        G1PedersenBytesCommitment id = G1PedersenBytesCommitment.decode(identity);
        assertArrayEquals(identity, id.toPointBytes());
        assertFalse(PEDERSEN.verifyBytes(id, new byte[0], BigInteger.ZERO));
        // Wrong lengths are MALFORMED_ENCODING.
        for (int len : new int[]{0, 47, 49, 96}) {
            CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                    () -> G1PedersenBytesCommitment.decode(new byte[len]));
            assertEquals(CommitmentError.MALFORMED_ENCODING, e.reason());
        }
    }

    @Test
    @DisplayName("s is never range-checked: payloads whose s ≥ 2^254 (failing a 254-bit check 2) still commit and verify")
    void derivedScalarNeverRangeChecked() {
        int found = 0;
        for (int i = 0; found < 3 && i < 200; i++) {
            byte[] payload = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(payload);
            BigInteger s = G1PedersenBytesHash.hashToScalar(payload);
            assertTrue(s.signum() >= 0 && s.compareTo(Q) < 0, "s in [0, q) by construction");
            if (s.bitLength() < 255) {
                continue;
            }
            found++;
            BigInteger r = G1Pedersen.randomBlinding(RANDOM);
            G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
            assertTrue(PEDERSEN.verifyBytes(c, payload, r));
            // The same s fails a requested 254-bit amount bound on the scalar profile.
            G1PedersenCommitment asScalar = G1PedersenCommitment.decode(c.toPointBytes());
            CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                    () -> PEDERSEN.verifyScalar(asScalar, s, r, 254));
            assertEquals(CommitmentError.OUT_OF_RANGE, e.reason());
            assertTrue(PEDERSEN.verifyScalar(asScalar, s, r));
        }
        assertEquals(3, found, "about 44% of scalars are at least 2^254");
    }

    // ---- independent oracle (RFC 9380 §5.3.1, written from the RFC) ----

    /** {@code msg = B ‖ I2OSP(n, 8)} (spec §5). */
    private static byte[] frame(byte[] payload) {
        return concat(payload, i2osp8(payload.length));
    }

    private static byte[] i2osp8(long n) {
        return ByteBuffer.allocate(8).putLong(n).array();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] last(byte[][] arrays) {
        return arrays[arrays.length - 1];
    }

    /**
     * RFC 9380 §5.3.1 {@code expand_message_xmd} with SHA-256, materialising {@code msg_prime}.
     * Returns {@code {b0, b1, …, b_ell, uniform_bytes}}.
     */
    private static byte[][] expandXmd(byte[] msg, byte[] dst, int lenInBytes) throws Exception {
        int bInBytes = 32;
        int sInBytes = 64;
        int ell = (lenInBytes + bInBytes - 1) / bInBytes;
        assertTrue(ell <= 255 && lenInBytes <= 65535 && dst.length <= 255);
        byte[] dstPrime = concat(dst, new byte[]{(byte) dst.length});
        ByteArrayOutputStream msgPrime = new ByteArrayOutputStream();
        msgPrime.write(new byte[sInBytes]);
        msgPrime.write(msg);
        msgPrime.write(new byte[]{(byte) (lenInBytes >>> 8), (byte) lenInBytes});
        msgPrime.write(0);
        msgPrime.write(dstPrime);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[][] b = new byte[ell + 2][];
        b[0] = sha.digest(msgPrime.toByteArray());
        b[1] = sha.digest(concat(concat(b[0], new byte[]{1}), dstPrime));
        for (int i = 2; i <= ell; i++) {
            byte[] x = new byte[bInBytes];
            for (int j = 0; j < bInBytes; j++) {
                x[j] = (byte) (b[0][j] ^ b[i - 1][j]);
            }
            b[i] = sha.digest(concat(concat(x, new byte[]{(byte) i}), dstPrime));
        }
        ByteArrayOutputStream uniform = new ByteArrayOutputStream();
        for (int i = 1; i <= ell; i++) {
            uniform.write(b[i]);
        }
        b[ell + 1] = Arrays.copyOf(uniform.toByteArray(), lenInBytes);
        return b;
    }
}
