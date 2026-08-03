package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FastPoseidonBls12381T3Test {
    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;

    @Test
    void foldAndCapacitySpongeMatchBigIntegerReference() {
        Random random = new Random(0x5a4a4d54L);
        for (int arity = 1; arity <= 12; arity++) {
            for (int vector = 0; vector < 16; vector++) {
                BigInteger[] fields = new BigInteger[arity];
                for (int index = 0; index < arity; index++) {
                    fields[index] = signed(random, 320);
                }
                assertEquals(
                        PoseidonHash.hashN(PARAMS, fields),
                        FastPoseidonBls12381T3.hashN(fields));
            }
        }

        for (int vector = 0; vector < 128; vector++) {
            BigInteger capacity = signed(random, 320);
            BigInteger left = signed(random, 320);
            BigInteger right = signed(random, 320);
            assertEquals(
                    PoseidonHash.spongeHash(PARAMS, capacity, left, right),
                    FastPoseidonBls12381T3.spongeHash(capacity, left, right));
        }
    }

    @Test
    void perThreadWorkspacesAreIsolated() throws Exception {
        List<BigInteger[]> vectors = new ArrayList<>();
        Random random = new Random(381L);
        for (int vector = 0; vector < 64; vector++) {
            vectors.add(new BigInteger[]{
                    signed(random, 300), signed(random, 300), signed(random, 300)});
        }
        List<BigInteger> expected = vectors.stream()
                .map(fields -> PoseidonHash.hashN(PARAMS, fields))
                .toList();

        try (var executor = Executors.newFixedThreadPool(8)) {
            List<Future<List<BigInteger>>> futures = new ArrayList<>();
            for (int task = 0; task < 16; task++) {
                futures.add(executor.submit(() -> vectors.stream()
                        .map(FastPoseidonBls12381T3::hashN)
                        .toList()));
            }
            for (Future<List<BigInteger>> future : futures) {
                assertEquals(expected, future.get());
            }
        }
    }

    private static BigInteger signed(Random random, int bits) {
        BigInteger value = new BigInteger(bits, random);
        return random.nextBoolean() ? value : value.negate();
    }
}
