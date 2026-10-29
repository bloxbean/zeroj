package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.FakeProfiles.FakeCodec;
import org.zeroj.api.commitment.FakeProfiles.FakeCommitment;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zeroj.api.commitment.FakeProfiles.FAKE;
import static org.zeroj.api.commitment.FakeProfiles.OTHER;
import static org.zeroj.api.commitment.FakeProfiles.bytes;
import static org.zeroj.api.commitment.FakeProfiles.concat;
import static org.zeroj.api.commitment.FakeProfiles.withByte;

/** {@code commitment-profiles-v1} §9: layout, the six decoding steps in order, and their classes. */
class CommitmentEnvelopeTest {

    private static final byte[] FAKE_ID = FAKE.id().toAsciiBytes();
    private static final byte[] POINT = bytes(1, 2, 3, 4);
    private static final byte[] ENVELOPE = concat(bytes(0x01, FAKE_ID.length), FAKE_ID, POINT);

    @Test
    @DisplayName("encode writes 0x01 ‖ u8(len) ‖ id ‖ point, and decode round-trips under the expected codec")
    void roundTrip() {
        FakeCommitment c = FakeProfiles.commitment(1, 2, 3, 4);
        assertArrayEquals(ENVELOPE, CommitmentEnvelope.encode(c));
        FakeCommitment back = CommitmentEnvelope.decode(ENVELOPE, new FakeCodec(FAKE, (byte) 0));
        assertSame(FAKE, back.profile());
        assertArrayEquals(POINT, back.toPointBytes());
    }

    @Test
    @DisplayName("Step 1: empty, one octet, and versions 0x00 and 0x02 are MALFORMED_ENCODING")
    void step1() {
        assertRejected(new byte[0], CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(bytes(0x01), CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(withByte(ENVELOPE, 0, 0x00), CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(withByte(ENVELOPE, 0, 0x02), CommitmentError.MALFORMED_ENCODING, false);
    }

    @Test
    @DisplayName("Step 2: a declared identifier longer than the envelope is MALFORMED_ENCODING")
    void step2() {
        assertRejected(concat(bytes(0x01, FAKE_ID.length + 1), FAKE_ID), CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(bytes(0x01, 0xFF, 'a'), CommitmentError.MALFORMED_ENCODING, false);
    }

    @Test
    @DisplayName("Step 3: another profile's identifier, a one-octet change, a prefix or an empty id are PROFILE_MISMATCH")
    void step3() {
        byte[] other = OTHER.id().toAsciiBytes();
        assertRejected(concat(bytes(0x01, other.length), other, POINT), CommitmentError.PROFILE_MISMATCH, false);
        assertRejected(withByte(ENVELOPE, 2, 'Z'), CommitmentError.PROFILE_MISMATCH, false);
        assertRejected(withByte(ENVELOPE, 2 + FAKE_ID.length - 1, '2'), CommitmentError.PROFILE_MISMATCH, false);
        byte[] prefix = Arrays.copyOf(FAKE_ID, FAKE_ID.length - 1);
        assertRejected(concat(bytes(0x01, prefix.length), prefix, POINT, bytes(0)), CommitmentError.PROFILE_MISMATCH, false);
        assertRejected(concat(bytes(0x01, 0), POINT), CommitmentError.PROFILE_MISMATCH, false);
    }

    @Test
    @DisplayName("Step 4: a truncated point, a missing point or a trailing octet is MALFORMED_ENCODING")
    void step4() {
        assertRejected(Arrays.copyOf(ENVELOPE, ENVELOPE.length - 1), CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(concat(bytes(0x01, FAKE_ID.length), FAKE_ID), CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(concat(ENVELOPE, bytes(0)), CommitmentError.MALFORMED_ENCODING, false);
    }

    @Test
    @DisplayName("Step 5: the codec's point decoder classes pass through unchanged")
    void step5() {
        assertRejected(concat(bytes(0x01, FAKE_ID.length), FAKE_ID, bytes(0xFF, 0, 0, 0)), CommitmentError.MALFORMED_ENCODING, true);
        assertRejected(concat(bytes(0x01, FAKE_ID.length), FAKE_ID, bytes(0xEE, 0, 0, 0)), CommitmentError.NOT_IN_SUBGROUP, true);
    }

    @Test
    @DisplayName("Step 6: a codec returning another class, another descriptor or another context is PROFILE_MISMATCH")
    void step6() {
        CommitmentCodec<FakeCommitment> wrongDescriptor = new FakeCodec(FAKE, (byte) 0) {
            @Override
            public FakeCommitment decodePoint(byte[] pointBytes) {
                return new FakeCommitment(OTHER, pointBytes, (byte) 0);
            }
        };
        assertMismatch(ENVELOPE, wrongDescriptor);
        CommitmentCodec<FakeCommitment> wrongContext = new FakeCodec(FAKE, (byte) 7) {
            @Override
            public FakeCommitment decodePoint(byte[] pointBytes) {
                return new FakeCommitment(FAKE, pointBytes, (byte) 8);
            }
        };
        assertMismatch(ENVELOPE, wrongContext);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    @DisplayName("Step 6: a decoder returning a foreign class is PROFILE_MISMATCH without calling any of its methods")
    void step6ForeignClass() {
        FakeProfiles.ForeignCommitment foreign = new FakeProfiles.ForeignCommitment();
        CommitmentCodec raw = new CommitmentCodec() {
            @Override
            public CommitmentProfile profile() {
                return FAKE;
            }

            @Override
            public Class commitmentType() {
                return FakeCommitment.class;
            }

            @Override
            public Commitment decodePoint(byte[] pointBytes) {
                return foreign;
            }
        };
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                () -> CommitmentEnvelope.decode(ENVELOPE, raw));
        assertEquals(CommitmentError.PROFILE_MISMATCH, e.reason());
        assertEquals(0, foreign.calls.get(), "a method of the foreign commitment ran before the class check");
    }

    @Test
    @DisplayName("Multi-defect: the first failing step decides (version before identifier before length)")
    void multiDefect() {
        byte[] badVersionAndId = withByte(withByte(ENVELOPE, 0, 0x02), 2, 'Z');
        assertRejected(badVersionAndId, CommitmentError.MALFORMED_ENCODING, false);
        byte[] badIdAndLength = concat(withByte(ENVELOPE, 2, 'Z'), bytes(0));
        assertRejected(badIdAndLength, CommitmentError.PROFILE_MISMATCH, false);
        byte[] badLengthAndPoint = concat(bytes(0x01, FAKE_ID.length), FAKE_ID, bytes(0xEE, 0, 0, 0, 0));
        assertRejected(badLengthAndPoint, CommitmentError.MALFORMED_ENCODING, false);
    }

    @Test
    @DisplayName("Nulls are NullPointerException; encode rejects a point of the wrong length")
    void nullsAndEncodeLength() {
        assertThrows(NullPointerException.class, () -> CommitmentEnvelope.decode(null, new FakeCodec(FAKE, (byte) 0)));
        assertThrows(NullPointerException.class, () -> CommitmentEnvelope.decode(ENVELOPE, null));
        assertThrows(NullPointerException.class, () -> CommitmentEnvelope.encode(null));
        FakeCommitment shortPoint = new FakeCommitment(FAKE, bytes(1, 2, 3), (byte) 0);
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, () -> CommitmentEnvelope.encode(shortPoint));
        assertEquals(CommitmentError.MALFORMED_ENCODING, e.reason());
    }

    @Test
    @DisplayName("Fuzz: random and mutated envelopes either decode to the exact point or throw CommitmentFormatException")
    void fuzz() {
        Random random = new Random(0x5EED);
        FakeCodec codec = new FakeCodec(FAKE, (byte) 0);
        for (int i = 0; i < 20_000; i++) {
            byte[] candidate;
            if (i % 2 == 0) {
                candidate = ENVELOPE.clone();
                candidate[random.nextInt(candidate.length)] ^= (byte) (1 << random.nextInt(8));
                if (random.nextInt(4) == 0) {
                    candidate = Arrays.copyOf(candidate, random.nextInt(candidate.length + 3));
                }
            } else {
                candidate = new byte[random.nextInt(40)];
                random.nextBytes(candidate);
            }
            try {
                FakeCommitment c = CommitmentEnvelope.decode(candidate, codec);
                assertArrayEquals(candidate, CommitmentEnvelope.encode(c), "accepted envelope must be canonical");
            } catch (CommitmentFormatException expected) {
                // the only permitted failure
            }
        }
    }

    private static void assertRejected(byte[] envelope, CommitmentError reason, boolean reachesDecoder) {
        FakeCodec codec = new FakeCodec(FAKE, (byte) 0);
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                () -> CommitmentEnvelope.decode(envelope, codec));
        assertEquals(reason, e.reason());
        assertEquals(reachesDecoder ? 1 : 0, codec.decodes.get(), "point decoder reached: " + reachesDecoder);
    }

    private static void assertMismatch(byte[] envelope, CommitmentCodec<FakeCommitment> codec) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                () -> CommitmentEnvelope.decode(envelope, codec));
        assertEquals(CommitmentError.PROFILE_MISMATCH, e.reason());
    }
}
