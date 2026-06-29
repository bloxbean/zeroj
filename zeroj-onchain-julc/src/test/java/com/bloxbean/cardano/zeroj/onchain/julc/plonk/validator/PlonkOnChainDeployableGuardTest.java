package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlonkOnChainDeployableGuardTest {

    private static final Path MAIN_VALIDATOR_DIR = Path.of(System.getProperty("user.dir"),
            "src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/validator");
    private static final Path MAIN_LIB_DIR = Path.of(System.getProperty("user.dir"),
            "src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/lib");

    @Test
    void nonVerifyingTranscriptPrototypeIsNotDeployableMainSource() {
        assertFalse(Files.exists(MAIN_VALIDATOR_DIR.resolve("PlonkBLS12381TranscriptPrototype.java")),
                "The transcript-only PlonK prototype must stay out of main deployable sources");
    }

    @Test
    void deployablePlonkValidatorsContainPairingCheck() throws IOException {
        String librarySource = read(MAIN_LIB_DIR.resolve("PlonkBLS12381Lib.java"));
        assertTrue(librarySource.contains("bls12_381_millerLoop")
                        && librarySource.contains("bls12_381_finalVerify"),
                "Reusable PlonK library must perform a BLS12-381 pairing check");

        List<Path> validators;
        try (var files = Files.list(MAIN_VALIDATOR_DIR)) {
            validators = files
                    .filter(path -> path.getFileName().toString().endsWith(".java"))
                    .filter(path -> read(path).contains("@SpendingValidator"))
                    .toList();
        }

        assertFalse(validators.isEmpty(), "Expected at least one deployable PlonK validator");
        for (Path validator : validators) {
            String source = read(validator);
            assertTrue(source.contains("PlonkBLS12381Lib.verify"),
                    () -> validator.getFileName() + " must delegate to the reusable PlonK verifier library");
            assertFalse(source.contains("return inv1Ok && inv2Ok"),
                    () -> validator.getFileName() + " must not return transcript/inverse checks only");
        }
    }

    private static String read(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read " + path, e);
        }
    }
}
