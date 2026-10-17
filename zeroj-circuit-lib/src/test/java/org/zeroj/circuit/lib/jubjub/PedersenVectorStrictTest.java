package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentError;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.zeroj.circuit.lib.jubjub.CommitmentTestPoints.L;
import static org.zeroj.circuit.lib.jubjub.PedersenScalarCommitmentTest.assertError;
import static org.zeroj.circuit.lib.jubjub.PedersenScalarCommitmentTest.concat;
import static org.zeroj.circuit.lib.jubjub.PedersenScalarCommitmentTest.i2osp;

/**
 * {@code commitment-profiles-v1} §7 check 3, §8.3 and §12.3 for {@code pedersen-jubjub-vector-v1}:
 * the three bound policies, the strict {@code verifyOpening} (which must not delegate to the legacy
 * width-checked {@code verify}) and the opening codec, each paired with the unchanged legacy result.
 */
class PedersenVectorStrictTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final PedersenVectorSchema BYTE_PAIR = PedersenVectorSchema.of("zeroj.test.pair", 1, List.of(
            new PedersenVectorSchema.Entry("amount", 8), new PedersenVectorSchema.Entry("asset", 8)));
    /** Different widths per component, so a check against the wrong index's width is caught. */
    private static final PedersenVectorSchema MIXED = PedersenVectorSchema.of("zeroj.test.mixed", 1, List.of(
            new PedersenVectorSchema.Entry("amount", 16), new PedersenVectorSchema.Entry("asset", 8)));
    private static final PedersenVectorSchema BYTE_PAIR_V2 = PedersenVectorSchema.of("zeroj.test.pair", 2, List.of(
            new PedersenVectorSchema.Entry("amount", 8), new PedersenVectorSchema.Entry("asset", 8)));

    @Test
    @DisplayName("Codex counterexample: C([200]) + C([200]) opens to [400] under residue-only and widened(2), not schema-widths; legacy verify says false")
    void overWidthSum() {
        BigInteger r1 = PedersenCommitment.randomBlinding(RANDOM), r2 = PedersenCommitment.randomBlinding(RANDOM);
        List<BigInteger> v = List.of(BigInteger.valueOf(200), BigInteger.valueOf(3));
        PedersenVectorCommitment sum = PedersenVectorCommitment.commit(BYTE_PAIR, v, r1)
                .add(PedersenVectorCommitment.commit(BYTE_PAIR, v, r2));
        List<BigInteger> opened = List.of(BigInteger.valueOf(400), BigInteger.valueOf(6));
        BigInteger r = r1.add(r2).mod(L);

        assertTrue(sum.verifyOpening(opened, r, PedersenVectorBoundPolicy.residueOnly(BYTE_PAIR)));
        assertTrue(sum.verifyOpening(opened, r, PedersenVectorBoundPolicy.widened(BYTE_PAIR, 2)));
        assertError(CommitmentError.OUT_OF_RANGE,
                () -> sum.verifyOpening(opened, r, PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR)));
        assertFalse(sum.verify(opened, r), "legacy verify keeps its width check");
        // widened(2) adds exactly one bit: 511 passes, 512 does not.
        assertTrue(PedersenVectorBoundPolicy.widened(BYTE_PAIR, 2).admits(0, BigInteger.valueOf(511)));
        assertFalse(PedersenVectorBoundPolicy.widened(BYTE_PAIR, 2).admits(0, BigInteger.valueOf(512)));
        assertTrue(PedersenVectorBoundPolicy.widened(BYTE_PAIR, 3).admits(0, BigInteger.valueOf(1023)));
        assertFalse(PedersenVectorBoundPolicy.widened(BYTE_PAIR, 4).admits(0, BigInteger.valueOf(1024)));
        assertTrue(PedersenVectorBoundPolicy.widened(BYTE_PAIR, 5).admits(0, BigInteger.valueOf(2047)));
    }

    @Test
    @DisplayName("Mixed widths [16, 8]: each component is held to its own width under schema-widths and widened")
    void perComponentWidths() {
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(MIXED);
        assertTrue(widths.admits(0, BigInteger.valueOf(65535)));
        assertTrue(widths.admits(0, BigInteger.valueOf(256)), "component 0 has width 16");
        assertFalse(widths.admits(0, BigInteger.valueOf(65536)));
        assertTrue(widths.admits(1, BigInteger.valueOf(255)));
        assertFalse(widths.admits(1, BigInteger.valueOf(256)), "component 1 has width 8");
        PedersenVectorBoundPolicy widened = PedersenVectorBoundPolicy.widened(MIXED, 2);
        assertTrue(widened.admits(0, BigInteger.valueOf(131071)));
        assertFalse(widened.admits(0, BigInteger.valueOf(131072)));
        assertTrue(widened.admits(1, BigInteger.valueOf(511)));
        assertFalse(widened.admits(1, BigInteger.valueOf(512)));

        BigInteger r1 = PedersenCommitment.randomBlinding(RANDOM), r2 = PedersenCommitment.randomBlinding(RANDOM);
        PedersenVectorCommitment one = PedersenVectorCommitment.commit(MIXED, values(300, 200), r1);
        assertTrue(one.verifyOpening(values(300, 200), r1, widths));
        PedersenVectorCommitment sum = one.add(PedersenVectorCommitment.commit(MIXED, values(300, 200), r2));
        BigInteger r = r1.add(r2).mod(L);
        assertError(CommitmentError.OUT_OF_RANGE, () -> sum.verifyOpening(values(600, 400), r, widths));
        assertTrue(sum.verifyOpening(values(600, 400), r, widened));
        PedersenVectorCommitment wideFirst = PedersenVectorCommitment.commit(MIXED, values(256, 1), r1);
        assertTrue(wideFirst.verifyOpening(values(256, 1), r1, widths), "256 fits component 0");
        PedersenVectorCommitment c = PedersenVectorCommitment.commit(MIXED, values(1, 2), r1);
        assertError(CommitmentError.OUT_OF_RANGE, () -> c.verifyOpening(values(1, 256), r1, widths));

        assertError(CommitmentError.OUT_OF_RANGE, () -> PedersenVectorOpening.of(widths, values(1, 256), r1));
        assertEquals(values(256, 1), PedersenVectorOpening.of(widths, values(256, 1), r1).values());
        byte[] secondOver = concat(new byte[]{2}, i2osp(BigInteger.ONE), i2osp(BigInteger.valueOf(256)), i2osp(r1));
        assertError(CommitmentError.OUT_OF_RANGE, () -> PedersenVectorOpening.decode(secondOver, widths));
        byte[] firstWide = concat(new byte[]{2}, i2osp(BigInteger.valueOf(256)), i2osp(BigInteger.ONE), i2osp(r1));
        assertEquals(BigInteger.valueOf(256), PedersenVectorOpening.decode(firstWide, widths).values().get(0));
    }

    @Test
    @DisplayName("widened is rejected when only a later component's bound would exceed l")
    void widenedRejectsLaterComponent() {
        PedersenVectorSchema narrowThenWide = PedersenVectorSchema.of("zeroj.test.nw", 1, List.of(
                new PedersenVectorSchema.Entry("a", 8), new PedersenVectorSchema.Entry("b", 251)));
        PedersenVectorSchema wideThenNarrow = PedersenVectorSchema.of("zeroj.test.wn", 1, List.of(
                new PedersenVectorSchema.Entry("a", 251), new PedersenVectorSchema.Entry("b", 8)));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(narrowThenWide, 2));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(wideThenNarrow, 2));
        PedersenVectorBoundPolicy.schemaWidths(narrowThenWide);
        PedersenVectorBoundPolicy.residueOnly(narrowThenWide);
    }

    @Test
    @DisplayName("A difference with a negative component opens to the residue l − x under residue-only only")
    void difference() {
        BigInteger r1 = PedersenCommitment.randomBlinding(RANDOM), r2 = PedersenCommitment.randomBlinding(RANDOM);
        PedersenVectorCommitment diff = PedersenVectorCommitment.commit(BYTE_PAIR, values(5, 9), r1)
                .subtract(PedersenVectorCommitment.commit(BYTE_PAIR, values(7, 1), r2));
        List<BigInteger> opened = List.of(L.subtract(BigInteger.TWO), BigInteger.valueOf(8));
        BigInteger r = r1.subtract(r2).mod(L);
        assertTrue(diff.verifyOpening(opened, r, PedersenVectorBoundPolicy.residueOnly(BYTE_PAIR)));
        assertError(CommitmentError.OUT_OF_RANGE,
                () -> diff.verifyOpening(opened, r, PedersenVectorBoundPolicy.widened(BYTE_PAIR, 2)));
        assertFalse(diff.verify(opened, r), "legacy");
        assertFalse(diff.verifyOpening(List.of(BigInteger.TWO.negate().mod(L), BigInteger.valueOf(9)), r,
                PedersenVectorBoundPolicy.residueOnly(BYTE_PAIR)), "wrong component is OPENING_MISMATCH (false)");
    }

    @Test
    @DisplayName("Policy for another schema is PROFILE_MISMATCH, before dimension and scalar checks")
    void policySchema() {
        PedersenVectorCommitment c = PedersenVectorCommitment.commit(BYTE_PAIR, values(1, 2), BigInteger.ONE);
        assertError(CommitmentError.PROFILE_MISMATCH,
                () -> c.verifyOpening(values(1, 2), BigInteger.ONE, PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR_V2)));
        assertError(CommitmentError.PROFILE_MISMATCH,
                () -> c.verifyOpening(List.of(L), L, PedersenVectorBoundPolicy.residueOnly(BYTE_PAIR_V2)));
    }

    @Test
    @DisplayName("§12.3 order: dimension (MALFORMED), each v_i then r (NON_CANONICAL), then check 3 (OUT_OF_RANGE); nulls first")
    void checkOrder() {
        PedersenVectorCommitment c = PedersenVectorCommitment.commit(BYTE_PAIR, values(1, 2), BigInteger.ONE);
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR);
        assertError(CommitmentError.MALFORMED_ENCODING, () -> c.verifyOpening(values(1), BigInteger.ONE, widths));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> c.verifyOpening(List.of(L), L, widths));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> c.verifyOpening(values(1, 2, 3), BigInteger.ONE, widths));
        for (BigInteger bad : new BigInteger[]{L, L.add(BigInteger.ONE), BigInteger.ONE.negate()}) {
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> c.verifyOpening(List.of(BigInteger.ONE, bad), BigInteger.ONE, widths));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> c.verifyOpening(values(1, 2), bad, widths));
        }
        // A non-canonical blinding is reported before an over-width component (check 1 before check 3).
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> c.verifyOpening(values(256, 2), L, widths));
        assertError(CommitmentError.OUT_OF_RANGE, () -> c.verifyOpening(values(1, 256), BigInteger.ONE, widths));
        List<BigInteger> withNull = new ArrayList<>(values(1, 2));
        withNull.set(1, null);
        assertThrows(NullPointerException.class, () -> c.verifyOpening(withNull, BigInteger.ONE, widths));
        // The snapshot (which rejects null elements) precedes the policy-schema comparison.
        assertThrows(NullPointerException.class, () -> c.verifyOpening(withNull, BigInteger.ONE,
                PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR_V2)));
        assertThrows(NullPointerException.class, () -> c.verifyOpening(null, BigInteger.ONE, widths));
        assertThrows(NullPointerException.class, () -> c.verifyOpening(values(1, 2), null, widths));
        assertThrows(NullPointerException.class, () -> c.verifyOpening(values(1, 2), BigInteger.ONE, null));
        assertTrue(c.verifyOpening(values(1, 2), BigInteger.ONE, widths));
        // Paired legacy: malformed input is false, not an exception.
        assertFalse(c.verify(values(1), BigInteger.ONE));
        assertFalse(c.verify(withNull, BigInteger.ONE));
    }

    @Test
    @DisplayName("The list is snapshotted: mutating it after the checks cannot change the verdict")
    void snapshot() {
        PedersenVectorCommitment c = PedersenVectorCommitment.commit(BYTE_PAIR, values(1, 2), BigInteger.ONE);
        List<BigInteger> mutating = new ArrayList<>(values(1, 2)) {
            private int reads;

            @Override
            public BigInteger get(int index) {
                // Returns other contents after the first size() reads through get(). List.copyOf reads
                // through toArray(), so only an implementation that re-reads the caller's list sees 99.
                return reads++ < size() ? super.get(index) : BigInteger.valueOf(99);
            }
        };
        assertTrue(c.verifyOpening(mutating, BigInteger.ONE, PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR)));
    }

    @Test
    @DisplayName("A BigInteger subclass that misreports its range is checked by its copied value on every vector path")
    void lyingSubclass() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenVectorCommitment c = PedersenVectorCommitment.commit(BYTE_PAIR, values(1, 2), r);
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR);
        // Stores l but claims (signum, compareTo) to be canonical. Under residue-only only check 1
        // applies, so only a check on the copied value reports NON_CANONICAL_SCALAR.
        BigInteger lyingL = new PedersenScalarCommitmentTest.LyingBigInteger(L);
        PedersenVectorBoundPolicy residue = PedersenVectorBoundPolicy.residueOnly(BYTE_PAIR);
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> c.verifyOpening(List.of(lyingL, BigInteger.TWO), r, residue));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenVectorOpening.of(residue, List.of(lyingL, BigInteger.TWO), r));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> c.verifyOpening(values(1, 2), lyingL, residue));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenVectorOpening.of(residue, values(1, 2), lyingL));
        PedersenVectorOpening fine = PedersenVectorOpening.of(widths,
                List.of(new PedersenScalarCommitmentTest.RecordingBigInteger(BigInteger.ONE), BigInteger.TWO), r);
        assertEquals(BigInteger.class, fine.values().get(0).getClass());
        assertTrue(c.verifyOpening(fine.values(), fine.blinding(), widths));
    }

    @Test
    @DisplayName("widened: addedTerms 1 and 65537 rejected, 65536 accepted for narrow widths; any bound above l rejected")
    void widenedConfiguration() {
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(BYTE_PAIR, 1));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(BYTE_PAIR, 0));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(BYTE_PAIR, 65537));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(BYTE_PAIR, Integer.MIN_VALUE));
        PedersenVectorBoundPolicy.widened(BYTE_PAIR, 65536);
        // 2^251 < l < 2^252: width + ⌈log₂ n⌉ must stay at most 251.
        assertEquals(schema(250), PedersenVectorBoundPolicy.widened(schema(250), 2).schema());
        PedersenVectorBoundPolicy.widened(schema(235), 65536);
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(schema(251), 2));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(schema(252), 2));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(schema(236), 65536));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenVectorBoundPolicy.widened(schema(249), 5));
        PedersenVectorBoundPolicy.widened(schema(249), 4);
        assertThrows(NullPointerException.class, () -> PedersenVectorBoundPolicy.widened(null, 2));
        assertThrows(NullPointerException.class, () -> PedersenVectorBoundPolicy.schemaWidths(null));
        assertThrows(NullPointerException.class, () -> PedersenVectorBoundPolicy.residueOnly(null));
    }

    @Test
    @DisplayName("schema-widths at width 252 is min(2^252, l) = l: l − 1 accepted")
    void widthAboveL() {
        PedersenVectorSchema wide = schema(252);
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(wide);
        assertTrue(widths.admits(0, L.subtract(BigInteger.ONE)));
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenVectorCommitment c = PedersenVectorCommitment.commit(wide, List.of(L.subtract(BigInteger.ONE)), r);
        assertTrue(c.verifyOpening(List.of(L.subtract(BigInteger.ONE)), r, widths));
    }

    @Test
    @DisplayName("§8.3 opening codec: round trip, layout, length and dimension MALFORMED, then check 1, then check 3")
    void openingCodec() {
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR);
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenVectorOpening opening = PedersenVectorOpening.of(widths, values(17, 255), r);
        byte[] encoded = opening.encode();
        assertEquals(33 + 64, encoded.length);
        assertArrayEquals(concat(new byte[]{2}, i2osp(BigInteger.valueOf(17)), i2osp(BigInteger.valueOf(255)), i2osp(r)), encoded);
        PedersenVectorOpening back = PedersenVectorOpening.decode(encoded, widths);
        assertEquals(values(17, 255), back.values());
        assertEquals(r, back.blinding());
        assertSame(widths, back.policy());
        assertThrows(UnsupportedOperationException.class, () -> back.values().set(0, BigInteger.ZERO));

        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenVectorOpening.decode(new byte[0], widths));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenVectorOpening.decode(Arrays.copyOf(encoded, encoded.length - 1), widths));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenVectorOpening.decode(concat(encoded, new byte[1]), widths));
        byte[] wrongN = encoded.clone();
        wrongN[0] = 1;
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenVectorOpening.decode(wrongN, widths));
        byte[] n3 = concat(new byte[]{3}, i2osp(BigInteger.ONE), i2osp(BigInteger.ONE), i2osp(BigInteger.ONE), i2osp(r));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenVectorOpening.decode(n3, widths));

        byte[] v1AtL = concat(new byte[]{2}, i2osp(BigInteger.ONE), i2osp(L), i2osp(L));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenVectorOpening.decode(v1AtL, widths));
        byte[] rAtLAndOverWidth = concat(new byte[]{2}, i2osp(BigInteger.valueOf(256)), i2osp(BigInteger.ONE), i2osp(L));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenVectorOpening.decode(rAtLAndOverWidth, widths));
        byte[] overWidth = concat(new byte[]{2}, i2osp(BigInteger.ONE), i2osp(BigInteger.valueOf(256)), i2osp(r));
        assertError(CommitmentError.OUT_OF_RANGE, () -> PedersenVectorOpening.decode(overWidth, widths));
        assertEquals(BigInteger.valueOf(256),
                PedersenVectorOpening.decode(overWidth, PedersenVectorBoundPolicy.residueOnly(BYTE_PAIR)).values().get(1));

        assertError(CommitmentError.OUT_OF_RANGE, () -> PedersenVectorOpening.of(widths, values(1, 256), r));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenVectorOpening.of(widths, values(1), r));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenVectorOpening.of(widths, values(1, 2), L));
        assertThrows(NullPointerException.class, () -> PedersenVectorOpening.decode(null, widths));
        assertThrows(NullPointerException.class, () -> PedersenVectorOpening.decode(encoded, null));
        assertFalse(opening.toString().contains("17") || opening.toString().contains(r.toString()));
    }

    @Test
    @DisplayName("Strict verifyOpening and legacy verify agree on every schema-width opening")
    void agreesWithLegacyOnIssuedOpenings() {
        PedersenVectorBoundPolicy widths = PedersenVectorBoundPolicy.schemaWidths(BYTE_PAIR);
        for (int i = 0; i < 20; i++) {
            BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
            List<BigInteger> v = values(RANDOM.nextInt(256), RANDOM.nextInt(256));
            PedersenVectorCommitment c = PedersenVectorCommitment.commit(BYTE_PAIR, v, r);
            assertTrue(c.verifyOpening(v, r, widths));
            assertTrue(c.verify(v, r));
            List<BigInteger> wrong = values(v.get(0).intValue() ^ 1, v.get(1).intValue());
            assertEquals(c.verify(wrong, r), c.verifyOpening(wrong, r, widths));
        }
    }

    private static List<BigInteger> values(int... v) {
        List<BigInteger> out = new ArrayList<>();
        for (int x : v) out.add(BigInteger.valueOf(x));
        return List.copyOf(out);
    }

    private static PedersenVectorSchema schema(int width) {
        return PedersenVectorSchema.of("zeroj.test.w" + width, 1, List.of(new PedersenVectorSchema.Entry("x", width)));
    }
}
