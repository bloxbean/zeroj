package org.zeroj.onchain.julc.groth16.codec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The authenticated-state release identity names the compiler that produced the script bytes
 * (ADR-0050 I8). julcVersion lives in the root gradle.properties; bumping it without a deliberate
 * COMPILER_PROFILE bump would relabel scripts silently, so this test fails until both agree.
 */
class CompilerProfileTest {

    @Test
    void compilerProfileNamesTheJulcVersionOfThisBuild() {
        String julcVersion = System.getProperty("zeroj.julcVersion");
        assertNotNull(julcVersion, "the Gradle test task passes julcVersion as zeroj.julcVersion");
        assertEquals("julc-" + julcVersion + "/plutus-v3",
                Groth16AuthenticatedStateTransitionScriptFactory.COMPILER_PROFILE,
                "julcVersion changed: regenerate the release artifacts and bump COMPILER_PROFILE deliberately");
    }
}
