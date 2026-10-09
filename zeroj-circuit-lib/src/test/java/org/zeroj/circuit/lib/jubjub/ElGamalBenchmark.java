package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.Supplier;

/**
 * ADR-0052 M1 host performance matrix: decoding, admission-side checks, encryption, sums,
 * shares and the bounded discrete-log search. Records numbers; asserts nothing. Results are
 * evidence for the JVM and CPU that ran them only.
 *
 * <p>Run: {@code ./gradlew :zeroj-circuit-lib:elgamalBenchmark}
 */
@EnabledIfSystemProperty(named = "zeroj.elgamalBench", matches = "true")
class ElGamalBenchmark {

    private static final SecureRandom RNG = new SecureRandom();
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    private static double microsPerOp(int ops, Runnable body) {
        for (int i = 0; i < Math.max(1, ops / 4); i++) body.run(); // warm-up
        long start = System.nanoTime();
        for (int i = 0; i < ops; i++) body.run();
        return (System.nanoTime() - start) / 1_000.0 / ops;
    }

    private static <T> T timed(String label, Supplier<T> body) {
        long start = System.nanoTime();
        T result = body.get();
        System.out.printf("| %s | %.1f ms |%n", label, (System.nanoTime() - start) / 1e6);
        return result;
    }

    @Test
    void matrix() {
        ElGamalSecretKey sk = ElGamalSecretKey.generate(RNG);
        NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
        ElGamalCiphertext sample = ElGamal.encrypt(ctx, 1, 1, RNG);
        byte[] pointBytes = sample.handle().toBytes();
        byte[] ctBytes = sample.encode();
        JubjubPoint a = sample.handle();

        System.out.println("| Operation | µs/op |");
        System.out.println("|---|---:|");
        System.out.printf("| Point decode (`JubjubPoint.fromBytes`, no subgroup check) | %.1f |%n",
                microsPerOp(400, () -> JubjubPoint.fromBytes(pointBytes)));
        System.out.printf("| Subgroup check, BigInteger (`isInSubgroup`) | %.1f |%n",
                microsPerOp(100, a::isInSubgroup));
        System.out.printf("| Subgroup check, Montgomery fast path | %.1f |%n",
                microsPerOp(400, () -> FastJubjubPoint.isInPrimeOrderSubgroup(a)));
        System.out.printf("| Ciphertext decode (64 bytes, two subgroup checks) | %.1f |%n",
                microsPerOp(200, () -> RawElGamalCiphertext.decode(ctBytes)));
        System.out.printf("| Encrypt (3 blinded secret multiplications) | %.1f |%n",
                microsPerOp(40, () -> ElGamal.encrypt(ctx, 1, 1, RNG)));
        System.out.printf("| Decryption share (1 blinded secret multiplication) | %.1f |%n",
                microsPerOp(80, () -> ElGamal.decryptionShare(sk, sample)));

        List<ElGamalCiphertext> many = new ArrayList<>();
        for (int i = 0; i < 2_000; i++) many.add(ElGamal.encrypt(ctx, i & 1, 1, RNG));
        System.out.printf("| Homomorphic sum, per ciphertext (2,000-term `sum`) | %.2f |%n",
                microsPerOp(5, () -> ElGamalCiphertext.sum(many)) / many.size());
        System.out.println();

        System.out.println("| Discrete log | Time |");
        System.out.println("|---|---:|");
        Random rnd = new Random(58);
        for (int bits : new int[]{16, 24, 32, 40}) {
            long bound = (1L << bits) - 1;
            JubjubDiscreteLog table = timed("table build, bound 2^" + bits,
                    () -> JubjubDiscreteLog.forBound(bound));
            long t = rnd.nextLong() & bound;
            JubjubPoint target = G.scalarMul(BigInteger.valueOf(t));
            timed("solve (random t), bound 2^" + bits, () -> table.solve(target, bound));
            JubjubPoint worst = G.scalarMul(BigInteger.valueOf(bound));
            timed("solve (t = bound, worst case), bound 2^" + bits, () -> table.solve(worst, bound));
        }
    }

    @Test
    void dkg() {
        System.out.println();
        System.out.println("| DKG (t, n) | Whole run, all n participants | Per participant |");
        System.out.println("|---|---:|---:|");
        for (int[] tn : new int[][]{{1, 3}, {2, 5}, {3, 7}, {5, 11}, {10, 21}}) {
            DkgConfig config = DkgHarness.config(tn[0], tn[1], "bench", tn[1]);
            DkgHarness.random(config, DkgHarness.HONEST).run(); // warm-up
            long start = System.nanoTime();
            DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
            double ms = (System.nanoTime() - start) / 1e6;
            if (!h.aborted.isEmpty()) throw new AssertionError("aborted: " + h.aborted);
            System.out.printf("| (%d, %d) | %.0f ms | %.0f ms |%n", tn[0], tn[1], ms, ms / tn[1]);
        }
    }

    @Test
    void dkgShareDelivery() throws Exception {
        // ADR-0054: HPKE seal/open per envelope, then whole encrypted runs against plain runs.
        DkgConfig config = DkgHarness.config(2, 5, "bench-delivery", 1);
        byte[] skR = new byte[32];
        RNG.nextBytes(skR);
        byte[] pkR = X25519Bytes.publicFromPrivate(skR);
        byte[] info = DkgShareDeliveryCodec.info(config, 1, 2);
        byte[] share = new byte[DkgShareDeliveryCodec.SHARE_LENGTH];
        for (int i = 0; i < 3_000; i++) { // warm-up
            Hpke.Sealed w = Hpke.sealBase(pkR, info, new byte[0], share, RNG);
            Hpke.openBase(w.enc(), skR, info, new byte[0], w.ct());
        }
        Hpke.Sealed sealed = Hpke.sealBase(pkR, info, new byte[0], share, RNG);
        double seal = microsPerOp(5_000, () -> {
            try {
                Hpke.sealBase(pkR, info, new byte[0], share, RNG);
            } catch (Hpke.HpkeException e) {
                throw new IllegalStateException(e);
            }
        });
        double open = microsPerOp(5_000, () -> {
            try {
                Hpke.openBase(sealed.enc(), skR, pkR, info, new byte[0], sealed.ct());
            } catch (Hpke.HpkeException e) {
                throw new IllegalStateException(e);
            }
        });
        double probe = microsPerOp(5_000, () -> X25519Bytes.passesSmallOrderProbe(pkR));
        System.out.println();
        System.out.println("| HPKE (DHKEM X25519, HKDF-SHA256, ChaCha20Poly1305), 100-byte SHARE | µs/op |");
        System.out.println("|---|---:|");
        System.out.printf("| SealBase (one envelope) | %.0f |%n", seal);
        System.out.printf("| OpenBase (one envelope) | %.0f |%n", open);
        System.out.printf("| Announcement small-order probe | %.0f |%n", probe);
        System.out.println();
        System.out.println("| DKG (t, n) | Plain run | Encrypted run | Added per participant |");
        System.out.println("|---|---:|---:|---:|");
        for (int[] tn : new int[][]{{1, 3}, {2, 5}, {3, 7}, {5, 11}, {10, 21}}) {
            DkgConfig c = DkgHarness.config(tn[0], tn[1], "bench-delivery", tn[1]);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(tn[0], tn[1], tn[1]);
            DkgHarness.fixed(c, d, DkgHarness.HONEST).run();
            DkgEncryptedHarness.fixed(c, d, DkgEncryptedHarness.HONEST).run(); // warm-up
            long a = System.nanoTime();
            DkgHarness.fixed(c, d, DkgHarness.HONEST).run();
            double plainMs = (System.nanoTime() - a) / 1e6;
            long b = System.nanoTime();
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(c, d, DkgEncryptedHarness.HONEST).run();
            double encMs = (System.nanoTime() - b) / 1e6;
            if (!h.aborted.isEmpty()) throw new AssertionError("aborted: " + h.aborted);
            System.out.printf("| (%d, %d) | %.0f ms | %.0f ms | %.1f ms |%n", tn[0], tn[1], plainMs, encMs, (encMs - plainMs) / tn[1]);
        }
    }
}
