package com.bloxbean.cardano.zeroj.mpf.load;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonMpfLoadIntegrationTest {

    @Test
    void deterministicRocksDbLoadResumesAndRealProofsVerify(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 100, 17, 8, 8, "none", false);

        IllegalStateException interruption = assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfLoadRunner(options, (completed, root) -> {
                    if (completed == 34) throw new IllegalStateException("injected interruption");
                }).run());
        assertEquals("injected interruption", interruption.getMessage());

        var resumed = new PoseidonMpfLoadRunner(options).run();
        var reopened = new PoseidonMpfLoadRunner(options).run();

        assertEquals(100, resumed.entries());
        assertEquals(34, resumed.resumedFrom());
        assertEquals(100, reopened.resumedFrom());
        assertEquals(0, reopened.checkpointsWritten());
        assertEquals(resumed.rootHex(), reopened.rootHex());
        assertEquals("04cca47225056a86865086a40252278686c71c1fda50382f256f3b8a0e2bff8f",
                resumed.rootHex(), "ADR-0041 deterministic 100-entry golden root");
        assertTrue(resumed.databaseBytesAfter() > 0);
        assertTrue(resumed.pairCache().hits() > 0);

        var proofs = new PoseidonMpfProofRunner(options).run();
        assertEquals(8, proofs.artifacts().size());
        assertTrue(proofs.artifacts().stream().allMatch(proof -> proof.steps() <= options.maxSteps()));
        assertTrue(proofs.result().samples().stream().allMatch(sample -> sample.proofBytes() > 0));
        assertArrayEquals(java.util.HexFormat.of().parseHex(resumed.rootHex()), proofs.root());

        assertTrue(Files.isRegularFile(directory.resolve("manifest.json")));
        assertTrue(Files.isRegularFile(directory.resolve("report.json")));
    }

    @Test
    void oneEntryCircuitGeneratesAndIndependentlyVerifiesGroth16Proof(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 1, 1, 1, 0, "in-memory", true);
        new PoseidonMpfLoadRunner(options).run();
        var proofs = new PoseidonMpfProofRunner(options).run();

        var result = new PoseidonMpfCircuitBenchmark(options).run(proofs);

        assertEquals(0, result.observedProofSteps());
        assertTrue(result.constraints() > 0);
        assertEquals(1, result.publicInputs());
        assertEquals(Boolean.TRUE, result.positiveVerified());
        assertEquals(Boolean.TRUE, result.negativeInputRejected());
        assertEquals(192, result.compressedProofBytes());
        assertEquals(432, result.cardanoVerificationKeyBytes());
        assertTrue(Files.isRegularFile(directory.resolve("cardano-artifacts/proof-a.g1")));
        assertTrue(Files.isRegularFile(directory.resolve("cardano-artifacts/public-input-root.bin")));
    }

    @Test
    void proofDistributionIsReportedBeforeCircuitBoundIsEnforced(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 3, 3, 3, 0, "none", false);
        new PoseidonMpfLoadRunner(options).run();

        var proofs = new PoseidonMpfProofRunner(options).run();

        assertTrue(proofs.artifacts().stream().anyMatch(proof -> proof.steps() > options.maxSteps()));
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfCircuitBenchmark(options).run(proofs));
        assertTrue(error.getMessage().contains("exceeding MAX_STEPS=0"));
    }

    @Test
    void deterministicDatasetHasUniqueKeysAndExercisesRawValueFallback() {
        byte[][] keys = new byte[1_000][];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = DeterministicDataset.key(25L, i);
            assertEquals(DeterministicDataset.KEY_BYTES, keys[i].length);
            byte[] value = DeterministicDataset.value(25L, i);
            assertEquals(DeterministicDataset.VALUE_BYTES, value.length);
            assertEquals(0xff, value[0] & 0xff);
        }
        for (int i = 1; i < keys.length; i++) assertFalse(Arrays.equals(keys[i - 1], keys[i]));
    }

    @Test
    void fullDepthScanMatchesEveryDecodedInclusionProof(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 100, 20, 100, 8, "none", false);
        new PoseidonMpfLoadRunner(options).run();
        var proofs = new PoseidonMpfProofRunner(options).run();

        var scan = new PoseidonMpfDepthScanRunner(options).run();
        var proofHistogram = proofs.artifacts().stream().collect(java.util.stream.Collectors.groupingBy(
                PoseidonMpfProofRunner.ProofArtifact::steps,
                java.util.TreeMap::new,
                java.util.stream.Collectors.counting()));

        assertEquals(100, scan.entries());
        assertEquals(proofHistogram, scan.stepHistogram());
        assertEquals(proofs.artifacts().stream().mapToInt(
                PoseidonMpfProofRunner.ProofArtifact::steps).max().orElseThrow(), scan.maxProofSteps());
    }

    private static LoadOptions options(
            Path directory,
            long entries,
            int batch,
            int samples,
            int maxSteps,
            String setup,
            boolean allowInsecureSetup) {
        return LoadOptions.parse(new String[]{
                "--stage=all",
                "--work-dir=" + directory,
                "--entries=" + entries,
                "--batch=" + batch,
                "--samples=" + samples,
                "--max-steps=" + maxSteps,
                "--progress-every=0",
                "--setup=" + setup,
                "--allow-insecure-setup=" + allowInsecureSetup
        });
    }
}
