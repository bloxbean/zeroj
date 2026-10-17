package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code commitment-profiles-v1} §2.1 grammar, §11 exception rules and §12.1 descriptors. */
class CommitmentProfileIdTest {

    @ParameterizedTest
    @ValueSource(strings = {"a-v1", "pedersen-jubjub-v1", "pedersen-jubjub-bytes-v1", "pedersen-bls12-381-g1-v1",
            "x9-v10", "a-b-c-v123", "0-v1"})
    @DisplayName("Valid identifiers are accepted unchanged")
    void valid(String id) {
        assertEquals(id, CommitmentProfileId.of(id).value());
        assertArrayEquals(id.getBytes(StandardCharsets.US_ASCII), CommitmentProfileId.of(id).toAsciiBytes());
    }

    @Test
    @DisplayName("Lengths 4 and 64 are accepted; 65 is rejected even when the grammar matches")
    void lengthBounds() {
        String sixtyFour = "a".repeat(61) + "-v1";
        assertEquals(64, sixtyFour.length());
        CommitmentProfileId.of(sixtyFour);
        assertInvalid("a".repeat(62) + "-v1");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "v1", "-v1", "av1", "A-v1", "a-V1", "a-v0", "a-v01", "a--b-v1", "-a-v1", "a-v1-",
            "a_b-v1", "a.b-v1", "a b-v1", "a-v1\n", "\na-v1", "a-v1 ", "é-v1", "a-v", "a-1", "pedersen-jubjub"})
    @DisplayName("Malformed identifiers are INVALID_CONFIGURATION (whole-string match, no folding)")
    void invalid(String id) {
        assertInvalid(id);
    }

    @Test
    @DisplayName("A null identifier is a NullPointerException")
    void nullId() {
        assertThrows(NullPointerException.class, () -> CommitmentProfileId.of(null));
    }

    @Test
    @DisplayName("Identifiers have value equality; toAsciiBytes returns a fresh copy")
    void equalityAndCopy() {
        CommitmentProfileId a = CommitmentProfileId.of("a-v1");
        assertEquals(a, CommitmentProfileId.of("a-v1"));
        assertEquals(a.hashCode(), CommitmentProfileId.of("a-v1").hashCode());
        assertNotEquals(a, CommitmentProfileId.of("a-v2"));
        byte[] first = a.toAsciiBytes();
        first[0] = 'z';
        assertEquals('a', a.toAsciiBytes()[0]);
        assertNotSame(a.toAsciiBytes(), a.toAsciiBytes());
    }

    @Test
    @DisplayName("define rejects a duplicate identifier and an out-of-range point length, reserving nothing on failure")
    void defineRules() {
        CommitmentProfileId id = CommitmentProfileId.of("zeroj-test-define-v1");
        assertInvalidConfig(() -> CommitmentProfile.define(id, CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, 0));
        assertInvalidConfig(() -> CommitmentProfile.define(id, CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, 256));
        CommitmentProfile defined = CommitmentProfile.define(id, CommitmentKind.VECTOR, CommitmentGroup.BLS12_381_G1, 255);
        assertSame(id, defined.id());
        assertEquals(CommitmentKind.VECTOR, defined.kind());
        assertEquals(CommitmentGroup.BLS12_381_G1, defined.group());
        assertEquals(255, defined.pointEncodingLength());
        assertInvalidConfig(() -> CommitmentProfile.define(CommitmentProfileId.of("zeroj-test-define-v1"),
                CommitmentKind.VECTOR, CommitmentGroup.BLS12_381_G1, 255));
        assertInvalidConfig(() -> CommitmentProfile.define(FakeProfiles.FAKE.id(),
                CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, 4));
    }

    @Test
    @DisplayName("define rejects null arguments")
    void defineNulls() {
        CommitmentProfileId id = CommitmentProfileId.of("zeroj-test-never-defined-v1");
        assertThrows(NullPointerException.class, () -> CommitmentProfile.define(null, CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, 1));
        assertThrows(NullPointerException.class, () -> CommitmentProfile.define(id, null, CommitmentGroup.JUBJUB, 1));
        assertThrows(NullPointerException.class, () -> CommitmentProfile.define(id, CommitmentKind.SCALAR, null, 1));
    }

    @Test
    @DisplayName("CommitmentFormatException carries only the seven format classes and is an IllegalArgumentException")
    void formatExceptionClasses() {
        for (CommitmentError e : CommitmentError.values()) {
            boolean format = e.ordinal() <= CommitmentError.INVALID_CONFIGURATION.ordinal();
            if (format) {
                CommitmentFormatException ex = new CommitmentFormatException(e, "m");
                assertSame(e, ex.reason());
                assertTrue(ex instanceof IllegalArgumentException);
            } else {
                IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                        () -> new CommitmentFormatException(e, "m"));
                assertTrue(!(ex instanceof CommitmentFormatException));
            }
        }
        assertThrows(NullPointerException.class, () -> new CommitmentFormatException(null, "m"));
        assertEquals(10, CommitmentError.values().length);
        assertEquals(CommitmentError.OPENING_MISMATCH, CommitmentError.values()[7]);
    }

    private static void assertInvalid(String id) {
        assertInvalidConfig(() -> CommitmentProfileId.of(id));
    }

    private static void assertInvalidConfig(Executable op) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, op);
        assertEquals(CommitmentError.INVALID_CONFIGURATION, e.reason());
    }
}
