package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.ProofProtocols;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;
import org.zeroj.bls12381.spi.Bls12381Provider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M1: completeness (I5), strict decoding (I3), rejection of tampering and of a proof under
 * another width, context, commitment or protocol (I6), zero challenges (I4) and the prover's refusals
 * and restarts (D6).
 */
class G1RangeProofTest {

    static final byte[] CTX = "https://example.com/zeroj/range-test/v1".getBytes(StandardCharsets.US_ASCII);
    static final BigInteger Q = PointCodec.Q;
    private static final G1RangeProver PROVER = G1RangeProver.pureJava();
    private static final G1RangeVerifier VERIFIER = G1RangeVerifier.pureJava();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();

    static byte[] seed(int tag) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) tag);
        s[0] = (byte) 0x5e;
        return s;
    }

    static G1PedersenOpening opening(BigInteger value, BigInteger blinding) {
        return G1PedersenOpening.of(value, blinding);
    }

    // ---- completeness (I5) ----

    @ParameterizedTest(name = "n = {0}")
    @ValueSource(ints = {16, 32, 64})
    @DisplayName("Honest proofs verify for v = 0, 1 and 2^n − 1 with a non-zero blinding, at each width")
    void completenessEdges(int bits) {
        BigInteger max = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
        for (BigInteger v : List.of(BigInteger.ZERO, BigInteger.ONE, max)) {
            BigInteger gamma = BigInteger.valueOf(0xC0FFEE).add(v);
            G1PedersenOpening o = opening(v, gamma);
            G1RangeProof proof = PROVER.prove(o, bits, CTX);
            assertEquals(G1RangeProof.length(bits), proof.toBytes().length);
            G1PedersenCommitment c = PEDERSEN.commitScalar(v, gamma);
            assertTrue(VERIFIER.verify(c, proof, bits, CTX), "v = " + v);
            if (v.equals(max)) {
                // The two octet overloads decode first; once per width is enough.
                assertTrue(VERIFIER.verify(c, proof.toBytes(), bits, CTX), "v = " + v);
                assertTrue(VERIFIER.verify(c.toPointBytes(), proof.toBytes(), bits, CTX), "v = " + v);
            }
        }
    }

    @Test
    @DisplayName("Random values and blindings verify at every width (system nonces)")
    void completenessRandom() {
        SecureRandom random = new SecureRandom();
        for (int bits : new int[] {16, 32, 64}) {
            BigInteger v = new BigInteger(bits, random);
            BigInteger gamma = G1Pedersen.randomBlinding(random);
            G1RangeProof proof = PROVER.prove(opening(v, gamma), bits, CTX);
            assertTrue(VERIFIER.verify(PEDERSEN.commitScalar(v, gamma), proof, bits, CTX), "n = " + bits);
        }
    }

    @Test
    @DisplayName("Two proofs of one opening differ (fresh nonces) and both verify")
    void freshNonces() {
        G1PedersenOpening o = opening(BigInteger.valueOf(77), BigInteger.valueOf(99));
        G1RangeProof a = PROVER.prove(o, 16, CTX);
        G1RangeProof b = PROVER.prove(o, 16, CTX);
        assertFalse(Arrays.equals(a.toBytes(), b.toBytes()));
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(77), BigInteger.valueOf(99));
        assertTrue(VERIFIER.verify(c, a, 16, CTX));
        assertTrue(VERIFIER.verify(c, b, 16, CTX));
    }

    @Test
    @DisplayName("(0, γ ≠ 0) is a valid statement: it proves v = 0")
    void zeroValueNonZeroBlinding() {
        G1RangeProof proof = PROVER.prove(opening(BigInteger.ZERO, BigInteger.TWO), 16, CTX);
        assertTrue(VERIFIER.verify(PEDERSEN.commitScalar(BigInteger.ZERO, BigInteger.TWO), proof, 16, CTX));
    }

    // ---- prover refusals (spec §7.1) ----

    @Test
    @DisplayName("Refusals, in order: configuration, then v ≥ 2^n; all before any curve work")
    void refusals() {
        CountingProvider counting = new CountingProvider();
        G1RangeProver prover = G1RangeProver.withProvider(counting);
        counting.calls.clear();
        G1PedersenOpening ok = opening(BigInteger.ONE, BigInteger.ONE);
        G1PedersenOpening big = opening(BigInteger.ONE.shiftLeft(16), BigInteger.ONE);

        for (int bits : new int[] {0, 1, 8, 15, 17, 24, 63, 65, 128, -16}) {
            assertClass(CommitmentError.INVALID_CONFIGURATION, () -> prover.prove(ok, bits, CTX));
        }
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> prover.prove(ok, 16, new byte[0]));
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> prover.prove(ok, 16, new byte[1025]));
        // Configuration comes before the range refusal.
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> prover.prove(big, 8, CTX));
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> prover.prove(big, 16, new byte[0]));
        assertClass(CommitmentError.OUT_OF_RANGE, () -> prover.prove(big, 16, CTX));
        assertClass(CommitmentError.OUT_OF_RANGE, () -> prover.prove(opening(BigInteger.ONE.shiftLeft(32), BigInteger.ONE), 32, CTX));
        assertClass(CommitmentError.OUT_OF_RANGE, () -> prover.prove(opening(BigInteger.ONE.shiftLeft(64), BigInteger.ONE), 64, CTX));
        assertClass(CommitmentError.OUT_OF_RANGE, () -> prover.prove(opening(Q.subtract(BigInteger.ONE), BigInteger.ONE), 64, CTX));
        assertEquals(0, counting.calls.size(), "a refusal makes no scalar multiplication");

        assertThrows(NullPointerException.class, () -> prover.prove(null, 16, CTX));
        assertThrows(NullPointerException.class, () -> prover.prove(ok, 16, null));
        // A 1,024-octet context is accepted; 1 octet too.
        assertTrue(VERIFIER.verify(PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE),
                PROVER.prove(ok, 16, new byte[1024]), 16, new byte[1024]));
    }

    @Test
    @DisplayName("The identity commitment (0, 0) is INVALID_STATEMENT, after computing V and before any proof work")
    void identityStatement() {
        CountingProvider counting = new CountingProvider();
        G1RangeProver prover = G1RangeProver.withProvider(counting);
        counting.calls.clear();
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                () -> prover.prove(opening(BigInteger.ZERO, BigInteger.ZERO), 16, CTX));
        assertEquals(CommitmentError.INVALID_STATEMENT, e.reason());
        assertEquals(2, counting.calls.size(), "only V = [v]·G + [γ]·H was computed");
        assertEquals(2, counting.count(CountingProvider.Kind.SECRET));
    }

    @Test
    @DisplayName("A provider without a secret-scalar multiplication cannot prove")
    void unsupportedProvider() {
        CountingProvider base = new CountingProvider();
        Bls12381Provider noSecret = new NoSecretProvider(base);
        G1RangeProver prover = G1RangeProver.withProvider(noSecret);
        assertFalse(prover.supportsProving());
        assertThrows(UnsupportedOperationException.class,
                () -> prover.prove(opening(BigInteger.ONE, BigInteger.ONE), 16, CTX));
        assertTrue(PROVER.supportsProving());
        assertSame(PROVER, G1RangeProver.pureJava());
    }

    // ---- restarts (spec §7.3) and zero challenges (I4) ----

    @Test
    @DisplayName("A zero challenge restarts the prover with fresh nonces, at most 8 attempts, then IllegalStateException")
    void restartBound() {
        for (G1RangeProver.Challenge which : G1RangeProver.Challenge.values()) {
            CountingNonces nonces = new CountingNonces();
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> PROVER.proveChecked(
                    BigInteger.ONE, BigInteger.ONE, 16, CTX, nonces, (w, value) -> w == which ? BigInteger.ZERO : value));
            assertTrue(e.getMessage().contains("8 attempts"), e.getMessage());
            assertEquals(7, nonces.restarts, which.name());
            assertEquals(8 * (2 + 2 * 16 + 2), nonces.drawn, which.name());
        }
    }

    @Test
    @DisplayName("A single zero challenge costs one restart, and the proof from the next attempt verifies")
    void restartOnce() {
        CountingNonces nonces = new CountingNonces();
        int[] seen = {0};
        G1RangeProof proof = PROVER.proveChecked(BigInteger.TEN, BigInteger.TWO, 16, CTX, nonces,
                (w, value) -> w == G1RangeProver.Challenge.X && seen[0]++ == 0 ? BigInteger.ZERO : value);
        assertEquals(1, nonces.restarts);
        assertTrue(VERIFIER.verify(PEDERSEN.commitScalar(BigInteger.TEN, BigInteger.TWO), proof, 16, CTX));
    }

    @Test
    @DisplayName("The test-nonce source fails closed on a restart")
    void testNoncesFailClosed() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> PROVER.proveChecked(BigInteger.ONE,
                BigInteger.ONE, 16, CTX, TestNonceProver.source(seed(1)),
                (w, value) -> w == G1RangeProver.Challenge.Y ? BigInteger.ZERO : value));
        assertTrue(e.getMessage().contains("pick another seed"), e.getMessage());
    }

    @Test
    @DisplayName("The verifier rejects any zero challenge (checks driven with chosen challenges)")
    void verifierZeroChallenge() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.TEN, BigInteger.TWO);
        G1RangeProof proof = PROVER.prove(opening(BigInteger.TEN, BigInteger.TWO), 16, CTX);
        G1Point v = PointCodec.point(c);
        G1RangeVerifier.Challenges real = VERIFIER.evaluate(v, proof, CTX).challenges();
        assertEquals(G1RangeVerifier.Layer.ACCEPT, VERIFIER.checks(v, proof, real));
        for (int which = 0; which < 4 + real.xj().length; which++) {
            BigInteger[] xj = real.xj().clone();
            BigInteger y = real.y(), z = real.z(), x = real.x(), xu = real.xu();
            switch (which) {
                case 0 -> y = BigInteger.ZERO;
                case 1 -> z = BigInteger.ZERO;
                case 2 -> x = BigInteger.ZERO;
                case 3 -> xu = BigInteger.ZERO;
                default -> xj[which - 4] = BigInteger.ZERO;
            }
            G1RangeVerifier.Challenges zeroed = new G1RangeVerifier.Challenges(real.sessionId(), real.instance(), y, z, x, xu, xj);
            assertEquals(G1RangeVerifier.Layer.CHALLENGE, VERIFIER.checks(v, proof, zeroed), "challenge " + which);
        }
    }

    // ---- out-of-range values forced through the prover (I6) ----

    @Test
    @DisplayName("A value at or above 2^n forced past the refusals yields a proof that fails check 1")
    void forcedOutOfRange() {
        for (BigInteger v : List.of(BigInteger.ONE.shiftLeft(16), BigInteger.ONE.shiftLeft(16).add(BigInteger.ONE),
                Q.subtract(BigInteger.ONE), Q.subtract(BigInteger.valueOf(5)))) {
            G1RangeProof proof = PROVER.proveChecked(v, BigInteger.valueOf(3), 16, CTX, SystemNonceSource.create(),
                    G1RangeProver.ChallengeTap.NONE);
            G1Point point = PointCodec.point(PEDERSEN.commitScalar(v, BigInteger.valueOf(3)));
            G1RangeVerifier.Outcome outcome = VERIFIER.evaluate(point, proof, CTX);
            assertEquals(G1RangeVerifier.Layer.CHECK1, outcome.layer(), "v = " + v);
            assertFalse(VERIFIER.verify(PEDERSEN.commitScalar(v, BigInteger.valueOf(3)), proof, 16, CTX));
        }
    }

    // ---- binding: width, context, commitment, protocol (I2, I6) ----

    @Test
    @DisplayName("A proof is rejected under another context, commitment or width")
    void binding() {
        BigInteger v = BigInteger.valueOf(1000), gamma = BigInteger.valueOf(4242);
        G1PedersenCommitment c = PEDERSEN.commitScalar(v, gamma);
        G1RangeProof proof = PROVER.prove(opening(v, gamma), 16, CTX);
        assertTrue(VERIFIER.verify(c, proof, 16, CTX));

        byte[] otherCtx = CTX.clone();
        otherCtx[otherCtx.length - 1] ^= 1;
        assertFalse(VERIFIER.verify(c, proof, 16, otherCtx));
        assertFalse(VERIFIER.verify(c, proof, 16, Arrays.copyOf(CTX, CTX.length + 1)));
        assertFalse(VERIFIER.verify(c, proof, 16, Arrays.copyOf(CTX, CTX.length - 1)));
        assertFalse(VERIFIER.verify(PEDERSEN.commitScalar(v, gamma.add(BigInteger.ONE)), proof, 16, CTX));
        assertFalse(VERIFIER.verify(PEDERSEN.commitScalar(v.add(BigInteger.ONE), gamma), proof, 16, CTX));
        assertFalse(VERIFIER.verify(c.negate(), proof, 16, CTX));
        // Another width: a decoded proof is never reinterpreted, and the octets have the wrong length.
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, proof, 32, CTX));
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, proof.toBytes(), 32, CTX));
        // The same statement proved at 32 bits does not verify at 16 even if re-encoded.
        G1RangeProof wide = PROVER.prove(opening(v, gamma), 32, CTX);
        assertTrue(VERIFIER.verify(c, wide, 32, CTX));
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, wide.toBytes(), 16, CTX));
    }

    @Test
    @DisplayName("The context is snapshotted: mutating the caller's array afterwards changes nothing")
    void contextSnapshot() {
        byte[] ctx = CTX.clone();
        G1RangeProof proof = PROVER.prove(opening(BigInteger.ONE, BigInteger.ONE), 16, ctx);
        ctx[0] ^= 1;
        assertTrue(VERIFIER.verify(PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE), proof, 16, CTX));
    }

    // ---- tampering (I6) and decoding (I3) ----

    @Test
    @DisplayName("Every single-element tamper is rejected: each point replaced by another valid point, each scalar +1")
    void elementTamper() {
        BigInteger v = BigInteger.valueOf(31337), gamma = BigInteger.valueOf(271828);
        G1PedersenCommitment c = PEDERSEN.commitScalar(v, gamma);
        byte[] good = PROVER.prove(opening(v, gamma), 16, CTX).toBytes();
        assertTrue(VERIFIER.verify(c, good, 16, CTX));
        int k = 4;
        byte[] replacement = PointCodec.encode(BulletproofGenerators.u());
        int offset = 0;
        for (int i = 0; i < 4; i++, offset += 48) assertFalse(VERIFIER.verify(c, withPoint(good, offset, replacement), 16, CTX), "point " + i);
        for (int i = 0; i < 3; i++, offset += 32) assertFalse(VERIFIER.verify(c, plusOne(good, offset), 16, CTX), "scalar " + i);
        for (int i = 0; i < 2 * k; i++, offset += 48) assertFalse(VERIFIER.verify(c, withPoint(good, offset, replacement), 16, CTX), "L/R " + i);
        for (int i = 0; i < 2; i++, offset += 32) assertFalse(VERIFIER.verify(c, plusOne(good, offset), 16, CTX), "a/b " + i);
        assertEquals(good.length, offset);
    }

    @Test
    @DisplayName("Random single-bit flips are rejected, either as a format error or as false")
    void randomBitFlips() {
        BigInteger v = BigInteger.valueOf(65535), gamma = BigInteger.valueOf(17);
        G1PedersenCommitment c = PEDERSEN.commitScalar(v, gamma);
        byte[] good = PROVER.prove(opening(v, gamma), 16, CTX).toBytes();
        Random random = new Random(0x0061);
        for (int trial = 0; trial < 48; trial++) {
            byte[] bad = good.clone();
            int bit = random.nextInt(8 * bad.length);
            bad[bit >>> 3] ^= (byte) (1 << (bit & 7));
            boolean accepted;
            try {
                accepted = VERIFIER.verify(c, bad, 16, CTX);
            } catch (CommitmentFormatException e) {
                accepted = false;
            }
            assertFalse(accepted, "bit " + bit);
        }
    }

    @Test
    @DisplayName("Decoding order: configuration, length (before anything is read), then fields in proof order")
    void decodingOrder() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE);
        byte[] good = PROVER.prove(opening(BigInteger.ONE, BigInteger.ONE), 16, CTX).toBytes();
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        byte[] badScalar = new byte[32];
        Arrays.fill(badScalar, (byte) 0xFF);

        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> VERIFIER.verify(c, new byte[3], 8, CTX));
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> VERIFIER.verify(c, good, 16, new byte[0]));
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> VERIFIER.verify(new byte[1], good, 16, new byte[1025]));
        for (int len : new int[] {0, 1, 735, 737, 832, 928, 2000}) {
            assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, new byte[len], 16, CTX));
        }
        // Length precedes V: a malformed V with a wrong-length proof is the length class.
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(new byte[48], new byte[5], 16, CTX));
        // The identity as a proof point is malformed, wherever it is.
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, withPoint(good, 0, identity), 16, CTX));
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, withPoint(good, 4 * 48 + 3 * 32, identity), 16, CTX));
        // Non-canonical scalars.
        assertClass(CommitmentError.NON_CANONICAL_SCALAR, () -> VERIFIER.verify(c, withBytes(good, 4 * 48, badScalar), 16, CTX));
        byte[] qBytes = new byte[32];
        PointCodec.writeScalar(Q.subtract(BigInteger.ONE), qBytes, 0);
        BigInteger qValue = new BigInteger(1, qBytes).add(BigInteger.ONE);
        byte[] exactlyQ = toBytes32(qValue);
        assertClass(CommitmentError.NON_CANONICAL_SCALAR, () -> VERIFIER.verify(c, withBytes(good, good.length - 32, exactlyQ), 16, CTX));
        // First failure in proof order wins: a bad scalar at t̂ and an identity at L_1 → scalar class.
        byte[] two = withPoint(withBytes(good, 4 * 48, badScalar), 4 * 48 + 3 * 32, identity);
        assertClass(CommitmentError.NON_CANONICAL_SCALAR, () -> VERIFIER.verify(c, two, 16, CTX));
        // An identity at A and a bad final scalar → the point class.
        byte[] three = withBytes(withPoint(good, 0, identity), good.length - 32, badScalar);
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, three, 16, CTX));
        // V is decoded after the proof's fields: bad V with a bad field → the field's class.
        assertClass(CommitmentError.NON_CANONICAL_SCALAR, () -> VERIFIER.verify(new byte[48], withBytes(good, 4 * 48, badScalar), 16, CTX));
        // Then V's own classes.
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(new byte[48], good, 16, CTX));
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(new byte[47], good, 16, CTX));
    }

    @Test
    @DisplayName("A longer or shorter L/R list is a length failure, even when every added element is valid")
    void wrongRoundCount() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(3), BigInteger.valueOf(4));
        byte[] good = PROVER.prove(opening(BigInteger.valueOf(3), BigInteger.valueOf(4)), 16, CTX).toBytes();
        int lrStart = 4 * 48 + 3 * 32;
        int abStart = good.length - 64;
        // One extra (L, R) pair, a copy of (L_1, R_1), inserted before a and b.
        byte[] longer = new byte[good.length + 96];
        System.arraycopy(good, 0, longer, 0, abStart);
        System.arraycopy(good, lrStart, longer, abStart, 96);
        System.arraycopy(good, abStart, longer, abStart + 96, 64);
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, longer, 16, CTX));
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> G1RangeProof.decode(longer, 16));
        // One pair removed.
        byte[] shorter = new byte[good.length - 96];
        System.arraycopy(good, 0, shorter, 0, abStart - 96);
        System.arraycopy(good, abStart, shorter, abStart - 96, 64);
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, shorter, 16, CTX));
        // Trailing octets after a valid proof.
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(c, Arrays.copyOf(good, good.length + 1), 16, CTX));
    }

    @Test
    @DisplayName("An identity V is a well-formed statement that no proof satisfies: verification returns false, last")
    void identityCommitment() {
        byte[] good = PROVER.prove(opening(BigInteger.ONE, BigInteger.ONE), 16, CTX).toBytes();
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        assertFalse(VERIFIER.verify(identity, good, 16, CTX));
        G1PedersenCommitment zero = G1PedersenCommitment.decode(identity);
        assertFalse(VERIFIER.verify(zero, good, 16, CTX));
        assertEquals(G1RangeVerifier.Layer.STATEMENT,
                VERIFIER.evaluate(G1Point.INFINITY, G1RangeProof.decode(good, 16), CTX).layer());
        // Format checks still come first.
        assertClass(CommitmentError.MALFORMED_ENCODING, () -> VERIFIER.verify(identity, new byte[1], 16, CTX));
    }

    @Test
    @DisplayName("A V outside the subgroup is NOT_IN_SUBGROUP, never a verdict (spec §8.1, Codex M0 F1)")
    void nonSubgroupCommitment() {
        // (0, 2) has order 3; [7]·G + [11]·H + (0, 2) has no Pedersen opening.
        G1Point torsion = new G1Point(Fp.ZERO, Fp.of(2));
        assertTrue(torsion.isOnCurve());
        assertFalse(torsion.isInSubgroup());
        G1Point bad = PointCodec.point(PEDERSEN.commitScalar(BigInteger.valueOf(7), BigInteger.valueOf(11))).add(torsion);
        byte[] badBytes = Bls12381Codecs.g1ToCompressed(bad);
        byte[] good = PROVER.prove(opening(BigInteger.valueOf(7), BigInteger.valueOf(11)), 16, CTX).toBytes();
        assertClass(CommitmentError.NOT_IN_SUBGROUP, () -> VERIFIER.verify(badBytes, good, 16, CTX));
        assertClass(CommitmentError.NOT_IN_SUBGROUP, () -> G1PedersenCommitment.decode(badBytes));
        // A torsion point as a proof element is also NOT_IN_SUBGROUP.
        assertClass(CommitmentError.NOT_IN_SUBGROUP, () -> VERIFIER.verify(
                PEDERSEN.commitScalar(BigInteger.valueOf(7), BigInteger.valueOf(11)), withPoint(good, 48, badBytes), 16, CTX));
    }

    @Test
    @DisplayName("Adversarial but well-formed inputs never make the checks throw: zero scalars, repeated bases")
    void degenerateInputs() {
        byte[] g = PointCodec.encode(BulletproofGenerators.g());
        for (int bits : new int[] {16, 32, 64}) {
            int k = RangeTranscript.rounds(bits);
            byte[] proof = new byte[G1RangeProof.length(bits)];
            int offset = 0;
            for (int i = 0; i < 4; i++, offset += 48) System.arraycopy(g, 0, proof, offset, 48);
            offset += 3 * 32;
            for (int i = 0; i < 2 * k; i++, offset += 48) System.arraycopy(g, 0, proof, offset, 48);
            offset += 2 * 32;
            assertEquals(proof.length, offset);
            G1PedersenCommitment c = G1PedersenCommitment.decode(g);
            assertFalse(VERIFIER.verify(c, proof, bits, CTX), "n = " + bits);
        }
    }

    @Test
    @DisplayName("Verification is deterministic: the same inputs give the same outcome and challenges")
    void determinism() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(8), BigInteger.valueOf(9));
        G1RangeProof proof = PROVER.prove(opening(BigInteger.valueOf(8), BigInteger.valueOf(9)), 16, CTX);
        G1RangeVerifier.Outcome a = VERIFIER.evaluate(PointCodec.point(c), proof, CTX);
        G1RangeVerifier.Outcome b = G1RangeVerifier.withProvider(new CountingProvider()).evaluate(PointCodec.point(c), proof, CTX);
        assertEquals(a.layer(), b.layer());
        assertArrayEquals(a.challenges().sessionId(), b.challenges().sessionId());
        assertEquals(a.challenges().y(), b.challenges().y());
        assertArrayEquals(a.challenges().xj(), b.challenges().xj());
    }

    @Test
    @DisplayName("The proof type: PROTOCOL constant, length table, equality on octets, defensive copies")
    void proofType() {
        assertSame(ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1, G1RangeProof.PROTOCOL);
        assertEquals(736, G1RangeProof.length(16));
        assertEquals(832, G1RangeProof.length(32));
        assertEquals(928, G1RangeProof.length(64));
        assertClass(CommitmentError.INVALID_CONFIGURATION, () -> G1RangeProof.length(8));
        byte[] bytes = PROVER.prove(opening(BigInteger.ONE, BigInteger.ONE), 16, CTX).toBytes();
        G1RangeProof a = G1RangeProof.decode(bytes, 16);
        bytes[0] ^= 1;
        G1RangeProof b = G1RangeProof.decode(a.toBytes(), 16);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(HexFormat.of().formatHex(bytes), HexFormat.of().formatHex(a.toBytes()));
        assertEquals(16, a.bits());
        assertTrue(a.toString().contains("736 octets"));
        assertThrows(NullPointerException.class, () -> G1RangeProof.decode(null, 16));
    }

    // ---- helpers ----

    static void assertClass(CommitmentError expected, Executable op) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, op);
        assertEquals(expected, e.reason(), e.getMessage());
    }

    static byte[] withPoint(byte[] in, int offset, byte[] point) {
        return withBytes(in, offset, point);
    }

    static byte[] withBytes(byte[] in, int offset, byte[] part) {
        byte[] out = in.clone();
        System.arraycopy(part, 0, out, offset, part.length);
        return out;
    }

    static byte[] plusOne(byte[] in, int offset) {
        BigInteger s = new BigInteger(1, in, offset, 32).add(BigInteger.ONE).mod(Q);
        byte[] out = in.clone();
        PointCodec.writeScalar(s, out, offset);
        return out;
    }

    static byte[] toBytes32(BigInteger x) {
        byte[] raw = x.toByteArray();
        byte[] out = new byte[32];
        int skip = raw.length > 32 ? raw.length - 32 : 0;
        System.arraycopy(raw, skip, out, 32 - (raw.length - skip), raw.length - skip);
        return out;
    }

    /** Counts draws and restarts; draws fresh system nonces. */
    static final class CountingNonces implements NonceSource {
        private final NonceSource delegate = SystemNonceSource.create();
        int drawn;
        int restarts;

        @Override
        public BigInteger next() {
            drawn++;
            return delegate.next();
        }

        @Override
        public void beforeRestart() {
            restarts++;
        }
    }

    /** A provider without a secret-scalar multiplication. */
    static final class NoSecretProvider implements Bls12381Provider {
        private final Bls12381Provider delegate;

        NoSecretProvider(Bls12381Provider delegate) {
            this.delegate = delegate;
        }

        @Override public String id() { return "zeroj-test-no-secret"; }
        @Override public G1Point g1Generator() { return delegate.g1Generator(); }
        @Override public G2Point g2Generator() { return delegate.g2Generator(); }
        @Override public G1Point g1ScalarMul(G1Point point, BigInteger scalar) { return delegate.g1ScalarMul(point, scalar); }
        @Override public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
            return delegate.g2ScalarMul(point, scalar);
        }
        @Override public boolean pairingProductIsIdentity(G1Point[] g1, G2Point[] g2) {
            return delegate.pairingProductIsIdentity(g1, g2);
        }
    }
}
