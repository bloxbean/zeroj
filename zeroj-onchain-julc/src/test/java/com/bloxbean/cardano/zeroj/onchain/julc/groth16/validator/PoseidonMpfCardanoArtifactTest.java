package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Optional MPF-specific bridge from the load benchmark's real proof artifacts
 * to the generic Plutus V3 Groth16 verifier in the Julc VM.
 */
class PoseidonMpfCardanoArtifactTest extends ContractTest {
    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    void realPoseidonMpfProofPassesJulcVmAndMutatedRootFails() throws Exception {
        String configured = System.getProperty("zeroj.poseidonMpf.cardanoArtifacts");
        assumeTrue(configured != null && !configured.isBlank(),
                "set -Dzeroj.poseidonMpf.cardanoArtifacts=PATH to run the MPF artifact bridge");
        Path directory = Path.of(configured).toAbsolutePath().normalize();

        List<Path> icFiles;
        try (var files = Files.list(directory)) {
            icFiles = files
                    .filter(path -> path.getFileName().toString().matches("vk-ic-[0-9]+\\.g1"))
                    .sorted(Comparator.comparingInt(PoseidonMpfCardanoArtifactTest::icIndex))
                    .toList();
        }
        assumeTrue(icFiles.size() == 2, "the MPF circuit must expose exactly one public input");

        List<PlutusData> ic = new ArrayList<>();
        for (Path file : icFiles) ic.add(PlutusData.bytes(Files.readAllBytes(file)));
        var program = compileValidator(Groth16BLS12381Verifier.class).program().applyParams(
                bytes(directory, "vk-alpha.g1"),
                bytes(directory, "vk-beta.g2"),
                bytes(directory, "vk-gamma.g2"),
                bytes(directory, "vk-delta.g2"),
                PlutusData.list(ic.toArray(PlutusData[]::new)));

        BigInteger root = new BigInteger(1, Files.readAllBytes(directory.resolve("public-input-root.bin")));
        var redeemer = PlutusData.constr(0,
                bytes(directory, "proof-a.g1"),
                bytes(directory, "proof-b.g2"),
                bytes(directory, "proof-c.g1"));
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();

        var positiveContext = spendingContext(txOutRef, PlutusData.list(PlutusData.integer(root)))
                .redeemer(redeemer)
                .buildPlutusData();
        long positiveStarted = System.nanoTime();
        var positive = evaluate(program, positiveContext);
        double positiveMillis = elapsedMillis(positiveStarted);
        assertSuccess(positive);

        long warmPositiveStarted = System.nanoTime();
        var warmPositive = evaluate(program, positiveContext);
        double warmPositiveMillis = elapsedMillis(warmPositiveStarted);
        assertSuccess(warmPositive);

        BigInteger mutatedRoot = root.add(BigInteger.ONE).mod(FR);
        var negativeContext = spendingContext(txOutRef, PlutusData.list(PlutusData.integer(mutatedRoot)))
                .redeemer(redeemer)
                .buildPlutusData();
        long negativeStarted = System.nanoTime();
        var negative = evaluate(program, negativeContext);
        double negativeMillis = elapsedMillis(negativeStarted);
        assertFailure(negative);

        System.out.println("[PoseidonMpfCardano] real proof Julc VM budget: " + positive.budgetConsumed());
        System.out.printf("[PoseidonMpfCardano] Julc VM positive verify cold %.3f ms, warm %.3f ms, "
                        + "mutated-root rejection %.3f ms%n",
                positiveMillis, warmPositiveMillis, negativeMillis);
    }

    private static PlutusData bytes(Path directory, String name) throws Exception {
        return PlutusData.bytes(Files.readAllBytes(directory.resolve(name)));
    }

    private static int icIndex(Path path) {
        String name = path.getFileName().toString();
        return Integer.parseInt(name.substring("vk-ic-".length(), name.length() - ".g1".length()));
    }

    private static double elapsedMillis(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000.0;
    }
}
