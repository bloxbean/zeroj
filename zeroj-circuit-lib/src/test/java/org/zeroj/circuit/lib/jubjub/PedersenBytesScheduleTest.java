package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 D5/I7: byte-commitment generation multiplies both secret scalars ({@code s} and
 * {@code r}) only through the blinded fixed schedule, and never through a variable-time
 * multiplication. Disclosed verification visibly uses the public path. Invalid arguments cause
 * no curve work at all.
 */
class PedersenBytesScheduleTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] PAYLOAD = NoteScheduleTestBridge.payload();

    @Test
    @DisplayName("commitBytes (array and both stream modes) uses exactly two blinded schedules and no public multiplication")
    void generationIsBlinded() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        assertBlinded(NoteScheduleTest.observe(() -> PedersenCommitment.commitBytes(PAYLOAD, r)));
        assertBlinded(NoteScheduleTest.observe(() -> io(() ->
                PedersenCommitment.commitBytes(new ByteArrayInputStream(PAYLOAD), PAYLOAD.length, r))));
        assertBlinded(NoteScheduleTest.observe(() -> io(() ->
                PedersenCommitment.commitBytesToEnd(new ByteArrayInputStream(PAYLOAD), 1 << 20, r))));
    }

    @Test
    @DisplayName("Control: verifyBytes is the disclosed path and is visible as public multiplications")
    void verificationIsPublic() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(PAYLOAD, r);
        for (Supplier<?> op : java.util.List.<Supplier<?>>of(
                () -> PedersenCommitment.verifyBytes(c, PAYLOAD, r),
                () -> io(() -> PedersenCommitment.verifyBytes(c, new ByteArrayInputStream(PAYLOAD), PAYLOAD.length, r)),
                () -> io(() -> PedersenCommitment.verifyBytesToEnd(c, new ByteArrayInputStream(PAYLOAD), PAYLOAD.length, r)))) {
            NoteScheduleTest.Counter counter = NoteScheduleTest.observe(op);
            assertTrue(counter.publicMultiplications >= 2, "disclosed verification uses the public path");
            assertEquals(0, counter.schedules.size(), "no secret schedule on the disclosed path");
        }
    }

    @Test
    @DisplayName("Invalid blinding or bound fails before any curve work")
    void validationBeforeCurveWork() {
        NoteScheduleTest.Counter counter = NoteScheduleTest.observe(() -> {
            assertThrows(IllegalArgumentException.class,
                    () -> PedersenCommitment.commitBytes(PAYLOAD, JubjubCurve.SUBGROUP_ORDER));
            assertThrows(IllegalArgumentException.class,
                    () -> PedersenCommitment.commitBytes(new ByteArrayInputStream(PAYLOAD), -1, BigInteger.ONE));
            assertThrows(java.io.IOException.class,
                    () -> PedersenCommitment.commitBytes(new ByteArrayInputStream(PAYLOAD), PAYLOAD.length + 1L, BigInteger.ONE));
            return null;
        });
        assertEquals(0, counter.schedules.size());
        assertEquals(0, counter.publicMultiplications);
    }

    private static void assertBlinded(NoteScheduleTest.Counter counter) {
        assertEquals(2, counter.schedules.size(), "one blinded schedule for s and one for r");
        assertTrue(counter.schedules.stream().allMatch(bits -> bits == JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS),
                "unblinded or variable-length schedule: " + counter.schedules);
        assertEquals(0, counter.publicMultiplications, "a secret reached a variable-time multiplication");
    }

    private interface IoSupplier<T> {
        T get() throws IOException;
    }

    private static <T> T io(IoSupplier<T> op) {
        try {
            return op.get();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Small deterministic payload shared with the other byte tests. */
    private static final class NoteScheduleTestBridge {
        static byte[] payload() {
            return PedersenBytesStreamTest.pattern(10_000);
        }
    }
}
