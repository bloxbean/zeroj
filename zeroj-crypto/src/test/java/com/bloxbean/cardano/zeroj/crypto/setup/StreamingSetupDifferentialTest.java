package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0035 M2/M3: the streaming setup ({@code setupToStore} — CSR in, mmap'd PkStore layout out,
 * flat Montgomery QAP internals) must produce a <b>byte-identical</b> key store to the legacy
 * in-memory path ({@code setup} + {@code Groth16PkStore.save}) for the same fixed randomness —
 * the compatibility-contract gate for both key provenances.
 */
class StreamingSetupDifferentialTest {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allowDevSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    /** Squaring chain with multi-term A rows + zero-scalar wires (infinity coverage). */
    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            cons.add(new R1CSConstraint(
                    Map.of(2 + i, one, 0, BigInteger.valueOf(3 + i % 5)),
                    Map.of(2 + i, one),
                    Map.of(3 + i, one)));
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return cons;
    }

    private static R1CSFlat toFlat(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    @Test
    void streamingSetup_byteEqualsLegacySavedStore(@TempDir Path dir) throws Exception {
        int n = 100, numWires = n + 2, numPublic = 1;
        var cons = chain(n);
        var flat = toFlat(cons);

        BigInteger tau = BigInteger.valueOf(0xC0FFEE);
        BigInteger alpha = BigInteger.valueOf(1234567).mod(FR);
        BigInteger beta = BigInteger.valueOf(7654321).mod(FR);
        BigInteger gamma = BigInteger.valueOf(1111111).mod(FR);
        BigInteger delta = BigInteger.valueOf(9999991).mod(FR);

        Path legacyDir = dir.resolve("legacy");
        Path streamDir = dir.resolve("stream");
        Files.createDirectories(legacyDir);

        var legacy = Groth16SetupBLS381.setup(cons, numWires, numPublic, tau, alpha, beta, gamma, delta);
        Groth16PkStore.save(legacy, legacyDir);

        var stream = Groth16SetupBLS381.setupToStore(flat, numWires, numPublic, tau,
                alpha, beta, gamma, delta, streamDir);

        for (String f : new String[]{"pointsA.bin", "pointsB1.bin", "pointsB2.bin",
                "pointsH.bin", "pointsL.bin", "aux.bin"}) {
            assertArrayEquals(Files.readAllBytes(legacyDir.resolve(f)),
                    Files.readAllBytes(streamDir.resolve(f)), f + " must be byte-identical");
        }
        // manifest: compare as properties (Properties.store embeds a timestamp comment)
        var mLegacy = new Properties();
        var mStream = new Properties();
        try (var in = Files.newInputStream(legacyDir.resolve("manifest.properties"))) { mLegacy.load(in); }
        try (var in = Files.newInputStream(streamDir.resolve("manifest.properties"))) { mStream.load(in); }
        assertEquals(mLegacy, mStream, "manifest properties must match");

        // VK bits returned by the streaming path must match the legacy result
        assertEquals(legacy.provingKey().alphaG1().xBigInt(), stream.provingKey().alphaG1().xBigInt());
        assertEquals(legacy.gammaG2().x().reBigInt(), stream.gammaG2().x().reBigInt());
        assertEquals(legacy.ic().length, stream.ic().length);
        for (int i = 0; i < legacy.ic().length; i++)
            assertEquals(legacy.ic()[i].xBigInt(), stream.ic()[i].xBigInt(), "ic[" + i + "]");
    }

    /**
     * ADR-0035 M6a: the sparse store must load into readers that are point-for-point identical
     * to the dense store's, and produce the identical deterministic proof.
     */
    @Test
    void sparseStore_readersAndProof_equalDense(@TempDir Path dir) throws Exception {
        int n = 300, numWires = n + 2, numPublic = 1;
        var cons = chain(n);
        var flat = toFlat(cons);
        BigInteger tau = BigInteger.valueOf(0xBEEF);
        BigInteger a = BigInteger.valueOf(11111), b = BigInteger.valueOf(22222),
                g = BigInteger.valueOf(33333), d = BigInteger.valueOf(44444);

        Path dense = dir.resolve("dense"), sparse = dir.resolve("sparse");
        Groth16SetupBLS381.setupToStore(flat, numWires, numPublic, tau, a, b, g, d, dense, false);
        Groth16SetupBLS381.setupToStore(flat, numWires, numPublic, tau, a, b, g, d, sparse, true);

        // sparse must actually be smaller (the chain circuit has infinity points in A/B1/B2/L)
        long denseBytes = Files.size(dense.resolve("pointsB1.bin"));
        long sparseBytes = Files.size(sparse.resolve("pointsB1.bin"));
        assertTrue(sparseBytes < denseBytes, "sparse B1 should be smaller: " + sparseBytes + " vs " + denseBytes);

        try (var dl = Groth16PkStore.load(dense); var sl = Groth16PkStore.load(sparse)) {
            long[] db = new long[12], sb = new long[12];
            for (int i = 0; i < numWires; i++) {
                dl.readers().a().readInto(i, db);
                sl.readers().a().readInto(i, sb);
                assertArrayEquals(db, sb, "A[" + i + "]");
                dl.readers().b1().readInto(i, db);
                sl.readers().b1().readInto(i, sb);
                assertArrayEquals(db, sb, "B1[" + i + "]");
            }
            for (int i = 0; i < dl.readers().h().count(); i++) {
                dl.readers().h().readInto(i, db);
                sl.readers().h().readInto(i, sb);
                assertArrayEquals(db, sb, "H[" + i + "]");
            }
            for (int i = 0; i < dl.readers().l().count(); i++) {
                dl.readers().l().readInto(i, db);
                sl.readers().l().readInto(i, sb);
                assertArrayEquals(db, sb, "L[" + i + "]");
            }
            byte[] dbe = new byte[192], sbe = new byte[192];
            for (int i = 0; i < numWires; i++) {
                dl.readers().b2().readBE(i, dbe, 0);
                sl.readers().b2().readBE(i, sbe, 0);
                assertArrayEquals(dbe, sbe, "B2[" + i + "]");
                assertEquals(dl.readers().b2().get(i).x().reBigInt(), sl.readers().b2().get(i).x().reBigInt(), "B2.get[" + i + "]");
            }

            // identical deterministic proof from both stores
            BigInteger[] w = witness(n);
            var pd = com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381.proveUnblindedWithReaders(
                    dl.pk(), dl.readers(), com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend.PURE_JAVA,
                    w, cons, dl.domain());
            var ps = com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381.proveUnblindedWithReaders(
                    sl.pk(), sl.readers(), com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend.PURE_JAVA,
                    w, cons, sl.domain());
            assertEquals(pd.a().x().toBigInteger(), ps.a().x().toBigInteger(), "piA");
            assertEquals(pd.b().x().re().toBigInteger(), ps.b().x().re().toBigInteger(), "piB");
            assertEquals(pd.c().x().toBigInteger(), ps.c().x().toBigInteger(), "piC");
        }
    }

    private static BigInteger[] witness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1];
        return w;
    }
}
