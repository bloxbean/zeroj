package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 I10 and spec §8.3–§8.4: the verifier's curve work is fixed by {@code n}. Every proof that
 * reaches the checks costs exactly {@code 5 + (2n + 2k + 4)} public multiplications, whether it is
 * accepted or fails check 1 or check 2 (both checks are always evaluated); a format failure or an
 * identity {@code V} costs none (reviewer (c), M1 F3).
 */
class VerifierWorkTest {

    private static final byte[] CTX = "https://example.com/zeroj/work/v1".getBytes(StandardCharsets.US_ASCII);

    @ParameterizedTest(name = "n = {0}")
    @ValueSource(ints = {16, 32, 64})
    @DisplayName("Accepted, check-1 failure and check-2 failure all cost exactly 5 + 2n + 2k + 4 multiplications")
    void fixedWork(int n) {
        int k = RangeTranscript.rounds(n);
        long expected = 5 + (2L * n + 2L * k + 4);
        BigInteger v = BigInteger.valueOf(9), gamma = BigInteger.valueOf(10);
        G1PedersenCommitment c = G1Pedersen.pureJava().commitScalar(v, gamma);
        G1RangeProof good = G1RangeProver.pureJava().prove(G1PedersenOpening.of(v, gamma), n, CTX);

        CountingProvider counting = new CountingProvider();
        G1RangeVerifier verifier = G1RangeVerifier.withProvider(counting);
        assertTrue(verifier.verify(c, good, n, CTX));
        assertEquals(expected, counting.count(CountingProvider.Kind.PUBLIC), "accepted");
        assertEquals(0, counting.count(CountingProvider.Kind.SECRET));

        // Check 1 fails: a value of 2^n forced past the prover's refusal.
        BigInteger big = BigInteger.ONE.shiftLeft(n);
        G1RangeProof outOfRange = G1RangeProver.pureJava().proveChecked(big, gamma, n, CTX, SystemNonceSource.create(),
                G1RangeProver.ChallengeTap.NONE);
        G1PedersenCommitment cBig = G1Pedersen.pureJava().commitScalar(big, gamma);
        counting.calls.clear();
        assertEquals(G1RangeVerifier.Layer.CHECK1, verifier.evaluate(PointCodec.point(cBig), outOfRange, CTX).layer());
        assertEquals(expected, counting.count(CountingProvider.Kind.PUBLIC), "check 1 failure");

        // Check 2 fails: a + 1 (a is not absorbed, so the challenges and check 1 are unchanged).
        byte[] bytes = good.toBytes();
        byte[] tampered = G1RangeProofTest.plusOne(bytes, bytes.length - 64);
        counting.calls.clear();
        assertEquals(G1RangeVerifier.Layer.CHECK2,
                verifier.evaluate(PointCodec.point(c), G1RangeProof.decode(tampered, n), CTX).layer());
        assertEquals(expected, counting.count(CountingProvider.Kind.PUBLIC), "check 2 failure");
    }

    @Test
    @DisplayName("Format failures and an identity V cost no multiplication")
    void noWorkOnRejection() {
        int n = 16;
        BigInteger v = BigInteger.valueOf(9), gamma = BigInteger.valueOf(10);
        G1PedersenCommitment c = G1Pedersen.pureJava().commitScalar(v, gamma);
        byte[] good = G1RangeProver.pureJava().prove(G1PedersenOpening.of(v, gamma), n, CTX).toBytes();
        CountingProvider counting = new CountingProvider();
        G1RangeVerifier verifier = G1RangeVerifier.withProvider(counting);
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        byte[] badScalar = new byte[32];
        Arrays.fill(badScalar, (byte) 0xFF);
        reject(() -> verifier.verify(c, good, 8, CTX));
        reject(() -> verifier.verify(c, good, n, new byte[0]));
        reject(() -> verifier.verify(c, Arrays.copyOf(good, good.length + 1), n, CTX));
        reject(() -> verifier.verify(c, G1RangeProofTest.withBytes(good, 0, identity), n, CTX));
        reject(() -> verifier.verify(c, G1RangeProofTest.withBytes(good, 4 * 48, badScalar), n, CTX));
        reject(() -> verifier.verify(new byte[48], good, n, CTX));
        assertFalse(verifier.verify(identity, good, n, CTX));
        assertEquals(0, counting.calls.size());
    }

    private static void reject(Executable op) {
        assertThrows(CommitmentFormatException.class, op);
    }
}
