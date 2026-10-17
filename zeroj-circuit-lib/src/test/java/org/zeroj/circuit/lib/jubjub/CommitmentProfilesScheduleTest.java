package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0059 M1 execution properties: strict generation multiplies both secrets only through the
 * blinded fixed schedule (never a variable-time multiplication); disclosed verification is the
 * public path; and every strict-path rejection happens before any curve work
 * ({@code commitment-profiles-v1} §12.3).
 */
class CommitmentProfilesScheduleTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.test.sched", 1, List.of(
            new PedersenVectorSchema.Entry("a", 8), new PedersenVectorSchema.Entry("b", 8)));

    @Test
    @DisplayName("commitScalar uses exactly two blinded 316-iteration schedules and no public multiplication")
    void commitScalarIsBlinded() {
        BigInteger m = PedersenCommitment.randomBlinding(RANDOM), r = PedersenCommitment.randomBlinding(RANDOM);
        NoteScheduleTest.Counter counter = NoteScheduleTest.observe(() -> PedersenCommitment.commitScalar(m, r));
        assertEquals(2, counter.schedules.size());
        assertTrue(counter.schedules.stream().allMatch(bits -> bits == JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS),
                counter.schedules.toString());
        assertEquals(0, counter.publicMultiplications, "a secret reached a variable-time multiplication");
        NoteScheduleTest.Counter zero = NoteScheduleTest.observe(() -> PedersenCommitment.commitScalar(BigInteger.ZERO, BigInteger.ZERO));
        assertEquals(2, zero.schedules.size(), "zero scalars take the same schedule");
        assertEquals(0, zero.publicMultiplications);
    }

    @Test
    @DisplayName("Control: verifyScalar and vector verifyOpening are the disclosed public path, with no secret schedule")
    void verificationIsPublic() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.TEN, r);
        NoteScheduleTest.Counter scalar = NoteScheduleTest.observe(() -> PedersenCommitment.verifyScalar(c, BigInteger.TEN, r));
        assertTrue(scalar.publicMultiplications >= 2);
        assertEquals(0, scalar.schedules.size());
        PedersenVectorCommitment v = PedersenVectorCommitment.commit(SCHEMA, List.of(BigInteger.ONE, BigInteger.TWO), r);
        NoteScheduleTest.Counter vector = NoteScheduleTest.observe(() -> v.verifyOpening(List.of(BigInteger.ONE, BigInteger.TWO), r,
                PedersenVectorBoundPolicy.residueOnly(SCHEMA)));
        assertEquals(3, vector.publicMultiplications, "[r]·H_V and one per component");
        assertEquals(0, vector.schedules.size());
    }

    @Test
    @DisplayName("Every strict-path rejection happens before any curve work")
    void validationBeforeCurveWork() {
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.ONE, BigInteger.ONE);
        PedersenVectorCommitment v = PedersenVectorCommitment.commit(SCHEMA, List.of(BigInteger.ONE, BigInteger.TWO), BigInteger.ONE);
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(SCHEMA);
        NoteScheduleTest.Counter counter = NoteScheduleTest.observe(() -> {
            assertThrows(CommitmentFormatException.class, () -> PedersenCommitment.commitScalar(L, BigInteger.ONE));
            assertThrows(CommitmentFormatException.class, () -> PedersenCommitment.commitScalar(BigInteger.ONE, L));
            assertThrows(CommitmentFormatException.class, () -> PedersenCommitment.verifyScalar(c, BigInteger.ONE.negate(), BigInteger.ONE));
            assertThrows(CommitmentFormatException.class, () -> PedersenCommitment.verifyScalar(c, BigInteger.TEN, BigInteger.ONE, 2));
            assertThrows(CommitmentFormatException.class, () -> PedersenCommitment.verifyScalar(c, BigInteger.ONE, BigInteger.ONE, 0));
            assertThrows(CommitmentFormatException.class, () -> v.verifyOpening(List.of(BigInteger.ONE, BigInteger.valueOf(256)), BigInteger.ONE, widths));
            assertThrows(CommitmentFormatException.class, () -> v.verifyOpening(List.of(BigInteger.ONE), BigInteger.ONE, widths));
            assertThrows(CommitmentFormatException.class, () -> v.verifyOpening(List.of(BigInteger.ONE, BigInteger.TWO), L, widths));
            assertThrows(CommitmentFormatException.class, () -> v.verifyOpening(List.of(BigInteger.ONE, BigInteger.TWO), BigInteger.ONE,
                    PedersenVectorBoundPolicy.schemaWidths(PedersenVectorSchema.of("zeroj.test.other", 1,
                            List.of(new PedersenVectorSchema.Entry("a", 8), new PedersenVectorSchema.Entry("b", 8))))));
            assertThrows(CommitmentFormatException.class, () -> PedersenScalarOpening.decode(new byte[64 + 1]));
            assertThrows(CommitmentFormatException.class, () -> PedersenVectorOpening.decode(new byte[3], widths));
            assertThrows(CommitmentFormatException.class, () -> PedersenBlinding.decode(new byte[31]));
            assertThrows(CommitmentFormatException.class, () -> PedersenScalarCommitment.decode(new byte[31]));
            return null;
        });
        assertEquals(0, counter.schedules.size());
        assertEquals(0, counter.publicMultiplications);
    }
}
