package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 D1/D3/D4 contract of {@code pedersen-jubjub-bytes-v1}: canonical blinding, argument
 * validation, strict decoding, opening checks, and the honest limits of the profile type.
 */
class PedersenBytesCommitmentTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final byte[] DOC = "contract v3, signed 2026-10-16".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("A fresh commitment opens with its payload and blinding, and with nothing else")
    void opensOnlyWithItsOpening() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, r);

        assertTrue(PedersenCommitment.verifyBytes(c, DOC, r));

        byte[] flipped = DOC.clone();
        flipped[3] ^= 0x01;
        assertFalse(PedersenCommitment.verifyBytes(c, flipped, r), "modified byte");
        assertFalse(PedersenCommitment.verifyBytes(c, java.util.Arrays.copyOf(DOC, DOC.length - 1), r), "shorter");
        assertFalse(PedersenCommitment.verifyBytes(c, java.util.Arrays.copyOf(DOC, DOC.length + 1), r), "trailing zero");
        assertFalse(PedersenCommitment.verifyBytes(c, DOC, r.add(BigInteger.ONE).mod(L)), "other blinding");

        PedersenBytesCommitment other = PedersenCommitment.commitBytes(DOC, PedersenCommitment.randomBlinding(RANDOM));
        assertFalse(PedersenCommitment.verifyBytes(other, DOC, r), "other commitment");
    }

    @Test
    @DisplayName("Fresh blindings hide equal payloads; equal openings give equal commitments")
    void hidingAndDeterminism() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        assertEquals(PedersenCommitment.commitBytes(DOC, r), PedersenCommitment.commitBytes(DOC, r));
        assertNotEquals(PedersenCommitment.commitBytes(DOC, PedersenCommitment.randomBlinding(RANDOM)),
                PedersenCommitment.commitBytes(DOC, PedersenCommitment.randomBlinding(RANDOM)));
    }

    @Test
    @DisplayName("New APIs reject non-canonical blindings; the numeric API keeps its modular acceptance")
    void canonicalBlindingOnly() {
        for (BigInteger bad : new BigInteger[]{BigInteger.ONE.negate(), L, L.add(BigInteger.ONE), L.shiftLeft(3)}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PedersenCommitment.commitBytes(DOC, bad));
            assertFalse(e.getMessage().contains(bad.toString(16)) || e.getMessage().contains(bad.toString()),
                    "the blinding must not appear in the message");
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytes(
                    new ByteArrayInputStream(DOC), DOC.length, bad));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytesToEnd(
                    new ByteArrayInputStream(DOC), DOC.length, bad));
        }
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, BigInteger.TEN);
        assertThrows(IllegalArgumentException.class,
                () -> PedersenCommitment.verifyBytes(c, DOC, BigInteger.TEN.add(L)));
        assertThrows(IllegalArgumentException.class,
                () -> PedersenCommitment.verifyBytes(c, DOC, BigInteger.ONE.negate()));

        // I4: the numeric profile is unchanged.
        assertEquals(PedersenCommitment.commit(BigInteger.TWO, BigInteger.TEN),
                PedersenCommitment.commit(BigInteger.TWO, BigInteger.TEN.add(L)));
        assertEquals(PedersenCommitment.commit(BigInteger.TWO, L.subtract(BigInteger.ONE)),
                PedersenCommitment.commit(BigInteger.TWO, BigInteger.ONE.negate()));
    }

    @Test
    @DisplayName("All six entry points reject every non-canonical blinding before reading the stream")
    void everyEntryPointRejectsNonCanonicalBlinding() {
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, BigInteger.ONE);
        for (BigInteger bad : new BigInteger[]{BigInteger.ONE.negate(), L, L.add(BigInteger.ONE), BigInteger.TWO.pow(300)}) {
            PedersenBytesStreamTest.RecordingStream s = new PedersenBytesStreamTest.RecordingStream(new ByteArrayInputStream(DOC));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytes(DOC, bad));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytes(s, DOC.length, bad));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytesToEnd(s, DOC.length, bad));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.verifyBytes(c, DOC, bad));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.verifyBytes(c, s, DOC.length, bad));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.verifyBytesToEnd(c, s, DOC.length, bad));
            assertEquals(0, s.calls, "no stream read before blinding validation, r=" + bad.bitLength() + " bits");
        }
    }

    @Test
    @DisplayName("Zero and l − 1 are valid blindings; zero gives no hiding but is algebraically valid")
    void boundaryBlindings() {
        PedersenBytesCommitment zero = PedersenCommitment.commitBytes(DOC, BigInteger.ZERO);
        assertTrue(PedersenCommitment.verifyBytes(zero, DOC, BigInteger.ZERO));
        BigInteger max = L.subtract(BigInteger.ONE);
        assertTrue(PedersenCommitment.verifyBytes(PedersenCommitment.commitBytes(DOC, max), DOC, max));
    }

    @Test
    @DisplayName("Null arguments throw NullPointerException")
    void nulls() {
        BigInteger r = BigInteger.ONE;
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, r);
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitBytes((byte[]) null, r));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitBytes(DOC, null));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitBytes(null, 0, r));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitBytesToEnd(null, 0, r));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyBytes(null, DOC, r));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyBytes(c, (byte[]) null, r));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyBytes(c, DOC, null));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyBytes(c, null, 0, r));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyBytesToEnd(c, null, 0, r));
        assertThrows(NullPointerException.class, () -> PedersenBytesCommitment.decode(null));
    }

    @Test
    @DisplayName("Null is reported before an out-of-range blinding")
    void nullCheckedBeforeRange() {
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitBytes((byte[]) null, L));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitBytes(null, -1, L));
    }

    @Test
    @DisplayName("Point bytes round-trip through decode; toPointBytes returns a fresh copy")
    void encodingRoundTrip() {
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, PedersenCommitment.randomBlinding(RANDOM));
        byte[] wire = c.toPointBytes();
        assertEquals(32, wire.length);
        assertNotSame(wire, c.toPointBytes());
        wire[0] ^= 1;
        assertFalse(java.util.Arrays.equals(wire, c.toPointBytes()), "mutating the copy must not change the commitment");
        wire[0] ^= 1;

        PedersenBytesCommitment decoded = PedersenBytesCommitment.decode(wire);
        assertEquals(c, decoded);
        assertEquals(c.hashCode(), decoded.hashCode());
        assertEquals(PedersenBytesCommitment.PROFILE_ID, decoded.profileId());
        assertEquals("pedersen-jubjub-bytes-v1", PedersenBytesCommitment.PROFILE_ID);
        assertTrue(c.toString().contains(java.util.HexFormat.of().formatHex(wire)));
    }

    @Test
    @DisplayName("decode rejects wrong lengths, off-subgroup and non-canonical points; identity decodes")
    void strictDecode() {
        assertThrows(IllegalArgumentException.class, () -> PedersenBytesCommitment.decode(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> PedersenBytesCommitment.decode(new byte[33]));
        assertThrows(IllegalArgumentException.class, () -> PedersenBytesCommitment.decode(new byte[0]));

        // Mixed order: the full-group generator has order 8·l.
        assertThrows(IllegalArgumentException.class,
                () -> PedersenBytesCommitment.decode(JubjubPoint.FULL_GENERATOR.toBytes()));
        // Small order 2: (0, −1).
        JubjubPoint order2 = JubjubPoint.fromAffine(BigInteger.ZERO, JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
        assertThrows(IllegalArgumentException.class, () -> PedersenBytesCommitment.decode(order2.toBytes()));
        // Identity with the sign bit set (ZIP 216 alias).
        byte[] alias = JubjubPoint.IDENTITY.toBytes();
        alias[31] |= (byte) 0x80;
        assertThrows(IllegalArgumentException.class, () -> PedersenBytesCommitment.decode(alias));

        PedersenBytesCommitment identity = PedersenBytesCommitment.decode(JubjubPoint.IDENTITY.toBytes());
        assertArrayEquals(JubjubPoint.IDENTITY.toBytes(), identity.toPointBytes());
        // Accepting the point accepts no opening: the empty payload with r = 0 is not the identity.
        assertFalse(PedersenCommitment.verifyBytes(identity, new byte[0], BigInteger.ZERO));
        assertFalse(PedersenCommitment.verifyBytes(identity, DOC, BigInteger.ONE));
    }

    @Test
    @DisplayName("D4: a byte commitment also has a numeric opening (s, r); the profiles are not disjoint")
    void numericOpeningExists() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, r);
        BigInteger s = PedersenBytesHash.hashToScalar(DOC);
        JubjubPoint numeric = PedersenCommitment.commit(s, r);
        assertArrayEquals(numeric.toBytes(), c.toPointBytes());
        assertTrue(PedersenCommitment.verify(PedersenCommitment.decode(c.toPointBytes()), s, r),
                "the bare numeric equation passes for the derived scalar");
        // The byte decoder accepts the numeric commitment's bytes: the point carries no profile.
        assertEquals(c, PedersenBytesCommitment.decode(numeric.toBytes()));
    }

    @Test
    @DisplayName("D4/I10: an example consumer rejects an authenticated record whose profile or context differs")
    void consumerAuthenticatesProfileAndContext() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(DOC, r);
        // Stand-in for an issuer-signed record keyed by the exact point bytes.
        Map<String, IssuedRecord> registry = Map.of(
                java.util.HexFormat.of().formatHex(c.toPointBytes()),
                new IssuedRecord("pedersen-jubjub-v1", "invoice-42"));
        ExampleConsumer consumer = new ExampleConsumer(registry, PedersenBytesCommitment.PROFILE_ID, "invoice-42");

        // The opening is valid, but the authenticated record says the point was issued as numeric.
        assertTrue(PedersenCommitment.verifyBytes(c, DOC, r));
        assertFalse(consumer.accept(c.toPointBytes(), DOC, r), "profile mismatch must be rejected");

        Map<String, IssuedRecord> wrongContext = Map.of(
                java.util.HexFormat.of().formatHex(c.toPointBytes()),
                new IssuedRecord(PedersenBytesCommitment.PROFILE_ID, "invoice-43"));
        assertFalse(new ExampleConsumer(wrongContext, PedersenBytesCommitment.PROFILE_ID, "invoice-42")
                .accept(c.toPointBytes(), DOC, r), "context mismatch must be rejected");
        assertFalse(new ExampleConsumer(Map.of(), PedersenBytesCommitment.PROFILE_ID, "invoice-42")
                .accept(c.toPointBytes(), DOC, r), "missing association must be rejected");

        Map<String, IssuedRecord> good = Map.of(
                java.util.HexFormat.of().formatHex(c.toPointBytes()),
                new IssuedRecord(PedersenBytesCommitment.PROFILE_ID, "invoice-42"));
        assertTrue(new ExampleConsumer(good, PedersenBytesCommitment.PROFILE_ID, "invoice-42")
                .accept(c.toPointBytes(), DOC, r));
    }

    private record IssuedRecord(String profile, String context) {}

    /** Selects its profile from configuration and requires an authenticated association. */
    private record ExampleConsumer(Map<String, IssuedRecord> authenticated, String expectedProfile,
                                   String expectedContext) {
        boolean accept(byte[] pointBytes, byte[] payload, BigInteger blinding) {
            Optional<IssuedRecord> record = Optional.ofNullable(
                    authenticated.get(java.util.HexFormat.of().formatHex(pointBytes)));
            if (record.isEmpty()
                    || !record.get().profile().equals(expectedProfile)
                    || !record.get().context().equals(expectedContext)) {
                return false;
            }
            return PedersenCommitment.verifyBytes(PedersenBytesCommitment.decode(pointBytes), payload, blinding);
        }
    }
}
