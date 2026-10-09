package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.zeroj.circuit.lib.jubjub.JubjubCurve.BASE_FIELD_PRIME;
import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * ADR-0055 M2: {@code confidential-note-jubjub-v1} through the public API, one nested class per
 * invariant group (I1–I11). I13 is in {@link NoteScheduleTest}; the independent reference's
 * vectors are replayed in {@code ConfidentialNoteReferenceVectorsTest}.
 */
class ConfidentialNotesTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private static NoteViewingKey key() {
        return NoteViewingKey.generate(RANDOM);
    }

    private static List<NoteReaderKey> readers(NoteViewingKey... keys) {
        List<NoteReaderKey> out = new ArrayList<>();
        for (NoteViewingKey k : keys) out.add(k.readerKey());
        return out;
    }

    /** A delivery whose plaintext is chosen by the test (for steps 6 and 7). */
    private static byte[] sealCrafted(byte[] pt, NoteReaderKey reader) {
        return ConfidentialNotes.sealOne(pt, reader, BigInteger.valueOf(987654321L));
    }

    @Nested
    @DisplayName("Round trip and reader order (D1, D6)")
    class RoundTrip {

        @Test
        @DisplayName("1–4 readers: each reader opens exactly its own position, to the same opening")
        void eachReaderOwnPosition() {
            for (int k = 1; k <= 4; k++) {
                NoteViewingKey[] keys = new NoteViewingKey[k];
                for (int i = 0; i < k; i++) keys[i] = key();
                NoteOpening opening = NoteOpening.random(BigInteger.valueOf(1000L + k), RANDOM);
                JubjubPoint c = opening.commitment();
                List<byte[]> deliveries = ConfidentialNotes.seal(opening, readers(keys), RANDOM);
                assertEquals(k, deliveries.size());
                for (int i = 0; i < k; i++) {
                    assertEquals(ConfidentialNotes.DELIVERY_LENGTH, deliveries.get(i).length);
                    NoteScanner scanner = NoteScanner.of(keys[i]);
                    for (int j = 0; j < k; j++) {
                        Optional<NoteOpening> result = scanner.open(deliveries.get(j), c);
                        if (i == j) {
                            assertEquals(opening.value(), result.orElseThrow().value());
                            assertEquals(opening.blinding(), result.orElseThrow().blinding());
                        } else {
                            assertTrue(result.isEmpty(), "reader " + i + " must not open position " + j);
                        }
                    }
                }
            }
        }

        @Test
        @DisplayName("Values at the boundaries 0 and 2^64 − 1, and blinding 0, round-trip")
        void boundaries() {
            NoteViewingKey k = key();
            for (NoteOpening o : List.of(NoteOpening.of(BigInteger.ZERO, BigInteger.ZERO),
                    NoteOpening.of(NoteOpening.MAX_VALUE, SUBGROUP_ORDER.subtract(BigInteger.ONE)),
                    NoteOpening.random(NoteOpening.MAX_VALUE, RANDOM))) {
                byte[] d = ConfidentialNotes.seal(o, readers(k), RANDOM).get(0);
                NoteOpening opened = NoteScanner.of(k).open(d, o.commitment()).orElseThrow();
                assertEquals(o.value(), opened.value());
                assertEquals(o.blinding(), opened.blinding());
            }
        }
    }

    @Nested
    @DisplayName("I1, I3, I7, I8: acceptance is all-or-nothing and every input failure is the same empty result")
    class Acceptance {

        private final NoteViewingKey k = key();
        private final NoteOpening opening = NoteOpening.random(BigInteger.valueOf(77), RANDOM);
        private final JubjubPoint c = opening.commitment();
        private final byte[] delivery = ConfidentialNotes.seal(opening, readers(k), RANDOM).get(0);
        private final NoteScanner scanner = NoteScanner.of(k);

        @Test
        @DisplayName("Step 1: any length other than 89 bytes")
        void lengths() {
            for (int len : new int[]{0, 32, 57, 88, 90, 178}) {
                byte[] d = new byte[len];
                System.arraycopy(delivery, 0, d, 0, Math.min(len, delivery.length));
                assertTrue(scanner.open(d, c).isEmpty(), "length " + len);
            }
        }

        @Test
        @DisplayName("Step 2: E the identity, small order, mixed order, non-canonical, not on the curve")
        void ephemeralKey() {
            JubjubPoint order2 = JubjubPoint.fromAffine(BigInteger.ZERO, BASE_FIELD_PRIME.subtract(BigInteger.ONE));
            List<byte[]> bad = new ArrayList<>();
            bad.add(JubjubPoint.IDENTITY.toBytes());
            bad.add(order2.toBytes());
            bad.add(JubjubPoint.FULL_GENERATOR.toBytes());
            byte[] e = SaplingNoteCrypto.decodeKey(Arrays.copyOf(delivery, 32)).add(order2).toBytes();
            bad.add(e); // the genuine E plus a small-order component
            byte[] zeroUSign = JubjubPoint.IDENTITY.toBytes();
            zeroUSign[31] |= (byte) 0x80;
            bad.add(zeroUSign);
            byte[] allOnes = new byte[32];
            Arrays.fill(allOnes, (byte) 0xff);
            bad.add(allOnes);
            for (byte[] eBytes : bad) {
                byte[] d = delivery.clone();
                System.arraycopy(eBytes, 0, d, 0, 32);
                assertTrue(scanner.open(d, c).isEmpty(), HEX.formatHex(eBytes));
            }
        }

        @Test
        @DisplayName("Step 5: every flipped bit of E (that still decodes) or of ct is refused")
        void tampering() {
            for (int bit = 0; bit < ConfidentialNotes.DELIVERY_LENGTH * 8; bit++) {
                byte[] d = delivery.clone();
                d[bit / 8] ^= (byte) (1 << (bit % 8));
                assertTrue(scanner.open(d, c).isEmpty(), "bit " + bit);
            }
        }

        @Test
        @DisplayName("Step 5: a wrong reader key")
        void wrongKey() {
            assertTrue(NoteScanner.of(key()).open(delivery, c).isEmpty());
        }

        @Test
        @DisplayName("Step 6: a wrong version byte or r ≥ l under a valid tag; r = l − 1 is accepted")
        void plaintextRules() {
            byte[] pt = ConfidentialNotes.plaintext(opening);
            byte[] v2 = pt.clone();
            v2[0] = 0x02;
            assertTrue(scanner.open(sealCrafted(v2, k.readerKey()), c).isEmpty(), "version 0x02");
            NoteOpening top = NoteOpening.of(BigInteger.TEN, SUBGROUP_ORDER.subtract(BigInteger.ONE));
            byte[] topPt = ConfidentialNotes.plaintext(top);
            assertTrue(scanner.open(sealCrafted(topPt, k.readerKey()), top.commitment()).isPresent(), "r = l − 1");
            byte[] rIsL = topPt.clone();
            System.arraycopy(DkgMessage.i2osp32(SUBGROUP_ORDER), 0, rIsL, 9, 32);
            // [10]G + [l]H = [10]G = top's commitment with r = 0: the r < l check must refuse it first.
            assertTrue(scanner.open(sealCrafted(rIsL, k.readerKey()), PedersenCommitment.commit(BigInteger.TEN, BigInteger.ZERO)).isEmpty(),
                    "r = l is refused even though it would open [10]G");
        }

        @Test
        @DisplayName("Step 7: a delivery that decrypts but does not open C is refused (A2)")
        void wrongCommitment() {
            JubjubPoint otherC = NoteOpening.random(BigInteger.valueOf(77), RANDOM).commitment();
            assertTrue(scanner.open(delivery, otherC).isEmpty());
            NoteOpening liar = NoteOpening.of(BigInteger.valueOf(78), opening.blinding());
            assertTrue(scanner.open(sealCrafted(ConfidentialNotes.plaintext(liar), k.readerKey()), c).isEmpty(),
                    "an opening of a different value under a valid tag");
        }

        @Test
        @DisplayName("Step 7: commitment coordinates must be canonical and on the curve, with no reduction")
        void canonicalCommitmentCoordinates() {
            JubjubPoint n = c.normalized();
            BigInteger p = BASE_FIELD_PRIME;
            assertTrue(scanner.open(delivery, n.affineU(), n.affineV()).isPresent(), "canonical coordinates");
            assertTrue(scanner.open(delivery, n.affineU().add(p), n.affineV()).isEmpty(), "u + p");
            assertTrue(scanner.open(delivery, n.affineU(), n.affineV().add(p)).isEmpty(), "v + p");
            assertTrue(scanner.open(delivery, n.affineU().negate(), n.affineV()).isEmpty(), "negative u");
            assertTrue(scanner.open(delivery, n.affineU(), n.affineV().add(BigInteger.ONE)).isEmpty(), "off the curve");
            NoteScanner.Scan scan = scanner.scan(List.of(
                    NoteScanner.Candidate.of(delivery, n.affineU(), n.affineV(), true),
                    NoteScanner.Candidate.of(delivery, n.affineU().add(p), n.affineV(), true)));
            assertEquals(1, scan.opened().size());
            assertEquals(List.of(1), scan.unopenableOwned());
        }

        @Test
        @DisplayName("The copied note: the same delivery and C in another output open cryptographically; the owner check is the wallet's (spec §5)")
        void copiedNote() {
            assertTrue(scanner.open(delivery.clone(), c).isPresent());
        }
    }

    @Nested
    @DisplayName("I2, I5, D7: fresh ephemeral keys, distinct and valid readers")
    class Sealing {

        @Test
        @DisplayName("Every delivery has its own E: across readers of one note and across repeated seals")
        void freshEphemerals() {
            NoteViewingKey a = key(), b = key();
            NoteOpening o = NoteOpening.random(BigInteger.ONE, RANDOM);
            Set<String> es = new HashSet<>();
            for (int round = 0; round < 5; round++) {
                for (byte[] d : ConfidentialNotes.seal(o, readers(a, b), RANDOM)) {
                    assertTrue(es.add(HEX.formatHex(d, 0, 32)), "E repeated");
                }
            }
        }

        @Test
        @DisplayName("Negative control: a repeated ephemeral toward one reader leaks the XOR of the plaintexts (why I2 matters)")
        void repeatedEphemeralLeaks() {
            NoteReaderKey r = key().readerKey();
            byte[] pt1 = ConfidentialNotes.plaintext(NoteOpening.random(BigInteger.ONE, RANDOM));
            byte[] pt2 = ConfidentialNotes.plaintext(NoteOpening.random(BigInteger.TWO, RANDOM));
            byte[] d1 = sealCrafted(pt1, r);
            byte[] d2 = sealCrafted(pt2, r);
            for (int i = 0; i < 41; i++) {
                assertEquals((byte) (pt1[i] ^ pt2[i]), (byte) (d1[32 + i] ^ d2[32 + i]));
            }
        }

        @Test
        @DisplayName("Readers must be non-empty and pairwise distinct")
        void readerRules() {
            NoteViewingKey a = key();
            NoteOpening o = NoteOpening.random(BigInteger.ONE, RANDOM);
            assertThrows(IllegalArgumentException.class, () -> ConfidentialNotes.seal(o, List.of(), RANDOM));
            assertThrows(IllegalArgumentException.class, () -> ConfidentialNotes.seal(o, readers(a, a), RANDOM));
            NoteReaderKey same = NoteReaderKey.decode(a.readerKey().encode());
            assertThrows(IllegalArgumentException.class, () -> ConfidentialNotes.seal(o, List.of(a.readerKey(), same), RANDOM));
        }

        @Test
        @DisplayName("I5: a reader key must be canonical, in the subgroup and not the identity")
        void readerKeyValidation() {
            JubjubPoint order2 = JubjubPoint.fromAffine(BigInteger.ZERO, BASE_FIELD_PRIME.subtract(BigInteger.ONE));
            assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.decode(JubjubPoint.IDENTITY.toBytes()));
            assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.decode(order2.toBytes()));
            assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.decode(JubjubPoint.FULL_GENERATOR.toBytes()));
            assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.decode(new byte[31]));
            NoteReaderKey ok = NoteReaderKey.decode(JubjubPoint.SUBGROUP_GENERATOR.toBytes());
            assertArrayEquals(JubjubPoint.SUBGROUP_GENERATOR.toBytes(), ok.encode());
        }
    }

    @Nested
    @DisplayName("D2, I6, Q6: viewing keys, possession and destroy")
    class Keys {

        @Test
        @DisplayName("Possession: the statement is the §3.3 form over the reader key; a rejecting verifier refuses registration")
        void possession() {
            NoteViewingKey k = key();
            DleqStatement s = k.possessionStatement();
            assertEquals(DleqStatement.Kind.POSSESSION, s.kind());
            List<BigInteger> in = s.publicInputs();
            JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR.normalized();
            assertEquals(List.of(g.affineU(), g.affineV(), k.readerKey().affineU(), k.readerKey().affineV(),
                    k.readerKey().affineU(), k.readerKey().affineV()), in);
            byte[] enc = k.readerKey().encode();
            assertEquals(k.readerKey(), NoteReaderKey.verified(enc, st -> st.kind() == DleqStatement.Kind.POSSESSION));
            assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.verified(enc, st -> false));
        }

        @Test
        @DisplayName("Destroy: wipes the secret, and every later use throws (never \"not mine\")")
        void destroy() {
            NoteViewingKey k = key();
            NoteOpening o = NoteOpening.random(BigInteger.ONE, RANDOM);
            byte[] d = ConfidentialNotes.seal(o, readers(k), RANDOM).get(0);
            NoteScanner scanner = NoteScanner.of(k);
            k.destroy();
            assertTrue(k.isDestroyed());
            assertThrows(IllegalStateException.class, () -> scanner.open(d, o.commitment()));
            assertThrows(IllegalStateException.class, () -> NoteScanner.of(k));
            assertTrue(k.toString().contains("destroyed"));
            k.destroy(); // idempotent
        }

        @Test
        @DisplayName("Secrets are redacted in toString")
        void redaction() {
            NoteViewingKey k = NoteViewingKey.fromSecret(BigInteger.valueOf(0x5ec7e7L));
            assertFalse(k.toString().contains("5ec7e7"));
            assertTrue(k.toString().contains("redacted"));
            NoteOpening o = NoteOpening.of(BigInteger.valueOf(31337), BigInteger.valueOf(0xb11dL));
            assertFalse(o.toString().contains("31337"));
            assertFalse(o.toString().contains("b11d"));
        }

        @Test
        @DisplayName("Opening ranges: 0 ≤ v < 2^64, 0 ≤ r < l")
        void openingRanges() {
            assertThrows(IllegalArgumentException.class, () -> NoteOpening.of(BigInteger.valueOf(-1), BigInteger.ONE));
            assertThrows(IllegalArgumentException.class, () -> NoteOpening.of(BigInteger.ONE.shiftLeft(64), BigInteger.ONE));
            assertThrows(IllegalArgumentException.class, () -> NoteOpening.of(BigInteger.ONE, SUBGROUP_ORDER));
            assertThrows(IllegalArgumentException.class, () -> NoteOpening.of(BigInteger.ONE, BigInteger.valueOf(-1)));
            assertThrows(IllegalArgumentException.class, () -> NoteViewingKey.fromSecret(BigInteger.ZERO));
            assertThrows(IllegalArgumentException.class, () -> NoteViewingKey.fromSecret(SUBGROUP_ORDER));
        }
    }

    @Nested
    @DisplayName("I9: scanning reports unopenable owned notes")
    class Scanning {

        @Test
        @DisplayName("scan(): opened notes, unopenable owned notes reported, unowned failures silent")
        void classify() {
            NoteViewingKey k = key();
            NoteOpening a = NoteOpening.random(BigInteger.valueOf(5), RANDOM);
            NoteOpening b = NoteOpening.random(BigInteger.valueOf(6), RANDOM);
            byte[] da = ConfidentialNotes.seal(a, readers(k), RANDOM).get(0);
            byte[] dOther = ConfidentialNotes.seal(b, readers(key()), RANDOM).get(0);
            byte[] garbage = da.clone();
            garbage[60] ^= 1;
            NoteScanner.Scan scan = NoteScanner.of(k).scan(List.of(
                    NoteScanner.Candidate.of(da, a.commitment(), true),       // 0: mine, opens
                    NoteScanner.Candidate.of(dOther, b.commitment(), false),  // 1: not mine, silent
                    NoteScanner.Candidate.of(garbage, a.commitment(), true),  // 2: mine, unopenable
                    NoteScanner.Candidate.of(dOther, b.commitment(), true))); // 3: owned but sent to another key
            assertEquals(1, scan.opened().size());
            assertEquals(0, scan.opened().get(0).index());
            assertEquals(a.value(), scan.opened().get(0).opening().value());
            assertEquals(List.of(2, 3), scan.unopenableOwned());
        }
    }

    @Nested
    @DisplayName("Platform faults fail closed (spec §5)")
    class Faults {

        @Test
        @DisplayName("Without an AEAD provider: creating a scanner, sealing and opening all throw IllegalStateException")
        void missingProvider() {
            NoteViewingKey k = key();
            NoteOpening o = NoteOpening.random(BigInteger.ONE, RANDOM);
            byte[] d = ConfidentialNotes.seal(o, readers(k), RANDOM).get(0);
            NoteScanner scanner = NoteScanner.of(k);
            JubjubPoint c = o.commitment();
            DkgEncryptedHarness.withoutProvider("SunJCE", () -> {
                assertThrows(IllegalStateException.class, () -> NoteScanner.of(k));
                assertThrows(IllegalStateException.class, () -> ConfidentialNotes.seal(o, readers(k), RANDOM));
                assertThrows(IllegalStateException.class, () -> scanner.open(d, c), "a fault is never \"not mine\"");
            });
            assertTrue(scanner.open(d, c).isPresent(), "the same delivery opens once the provider is back");
        }
    }

    @Test
    @DisplayName("API surface: final classes, no public constructors, no public ephemeral seam, primitives package-private")
    void apiSurface() throws Exception {
        for (Class<?> type : List.of(NoteViewingKey.class, NoteReaderKey.class, NoteOpening.class, ConfidentialNotes.class,
                NoteScanner.class, NoteScanner.Candidate.class, NoteScanner.Opened.class, NoteScanner.Scan.class)) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type + " is final");
            assertFalse(type.isRecord(), type + " is not a record");
            for (Constructor<?> ctor : type.getDeclaredConstructors()) {
                assertFalse(Modifier.isPublic(ctor.getModifiers()) || Modifier.isProtected(ctor.getModifiers()),
                        type + " has a public constructor");
            }
        }
        for (Class<?> hidden : List.of(SaplingNoteCrypto.class, Aead.class, NoteAeadSelfTest.class)) {
            assertFalse(Modifier.isPublic(hidden.getModifiers()), hidden + " must stay package-private");
        }
        for (Method m : ConfidentialNotes.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())) {
                for (Class<?> p : m.getParameterTypes()) {
                    assertNotEquals("IntFunction", p.getSimpleName(), "no public ephemeral seam: " + m);
                    assertNotEquals(BigInteger.class, p, "no public seal with a caller-chosen ephemeral: " + m);
                }
            }
        }
        assertFalse(Modifier.isPublic(NoteViewingKey.class.getDeclaredMethod("fromSecret", BigInteger.class).getModifiers()));
        assertFalse(Modifier.isPublic(NoteViewingKey.class.getDeclaredMethod("secretScalar").getModifiers()));
    }
}
