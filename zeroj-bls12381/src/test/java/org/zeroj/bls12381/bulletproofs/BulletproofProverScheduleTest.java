package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 I8: every multiplication involving a secret scalar ({@code V}, {@code A}, {@code S},
 * {@code T₁}, {@code T₂}) goes through {@code g1SecretScalarMul}; the public entry point sees only
 * the inner-product rounds; and the sequence of secret calls, by base, does not depend on the bits of
 * {@code v}. This is a schedule property, not a constant-time guarantee (spec §7.4).
 */
class BulletproofProverScheduleTest {

    private static final byte[] CTX = "https://example.com/zeroj/schedule/v1".getBytes();
    private static final int N = 16;

    @Test
    @DisplayName("Secret calls: 2 for V, then 2n + 1 for each of A and S, then 2 for each of T₁ and T₂, on fixed bases in a fixed order")
    void secretSchedule() {
        List<List<G1Point>> schedules = new ArrayList<>();
        SecureRandom random = new SecureRandom();
        for (BigInteger v : List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(0xFFFF), BigInteger.valueOf(0xA5A5),
                new BigInteger(N, random))) {
            CountingProvider counting = new CountingProvider();
            G1RangeProver prover = G1RangeProver.withProvider(counting);
            counting.calls.clear();
            G1RangeProof proof = prover.prove(G1PedersenOpening.of(v, BigInteger.valueOf(77)), N, CTX);
            assertTrue(G1RangeVerifier.pureJava().verify(
                    G1Pedersen.pureJava().commitScalar(v, BigInteger.valueOf(77)), proof, N, CTX));

            List<G1Point> secretBases = new ArrayList<>();
            int firstPublic = -1;
            for (int i = 0; i < counting.calls.size(); i++) {
                CountingProvider.Call c = counting.calls.get(i);
                if (c.kind() == CountingProvider.Kind.SECRET) {
                    assertEquals(-1, firstPublic, "a secret call after the first public call, at " + i);
                    secretBases.add(c.base());
                } else if (firstPublic < 0) {
                    firstPublic = i;
                }
            }
            assertEquals(2 + 2 * (2 * N + 1) + 4, secretBases.size(), "v = " + v);
            schedules.add(secretBases);
        }
        for (List<G1Point> s : schedules) assertEquals(schedules.get(0), s, "the secret schedule depends on v");

        List<G1Point> expected = new ArrayList<>();
        expected.add(BulletproofGenerators.g());
        expected.add(BulletproofGenerators.h());
        for (int rep = 0; rep < 2; rep++) {
            expected.add(BulletproofGenerators.h());
            for (int i = 0; i < N; i++) expected.add(BulletproofGenerators.gVec(i));
            for (int i = 0; i < N; i++) expected.add(BulletproofGenerators.hVec(i));
        }
        for (int rep = 0; rep < 2; rep++) {
            expected.add(BulletproofGenerators.g());
            expected.add(BulletproofGenerators.h());
        }
        assertEquals(expected, schedules.get(0));
    }

    @Test
    @DisplayName("A is a full sum over all 2n generators: scalars 0 or 1 on G_i and 0 or q − 1 on H_i, for every bit pattern")
    void aCoversAllGenerators() {
        for (BigInteger v : List.of(BigInteger.ZERO, BigInteger.valueOf(0xFFFF))) {
            CountingProvider counting = new CountingProvider();
            G1RangeProver prover = G1RangeProver.withProvider(counting);
            counting.calls.clear();
            prover.prove(G1PedersenOpening.of(v, BigInteger.ONE), N, CTX);
            // Calls 2 … 2 + 2n are A's: [α]·H, then G_0 … G_{n−1}, then H_0 … H_{n−1}.
            List<CountingProvider.Call> a = counting.calls.subList(3, 3 + 2 * N);
            for (int i = 0; i < N; i++) {
                assertTrue(Set.of("0", "1").contains(a.get(i).scalarClass()), "G_" + i);
                assertTrue(Set.of("0", "-1").contains(a.get(N + i).scalarClass()), "H_" + i);
            }
        }
    }
}
