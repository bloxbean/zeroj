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
}
