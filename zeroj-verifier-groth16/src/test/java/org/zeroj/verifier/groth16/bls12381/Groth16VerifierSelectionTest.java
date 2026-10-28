package org.zeroj.verifier.groth16.bls12381;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.verifier.core.VerifierRegistry;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0062 PR review item 2: where no {@code libblst} is bundled (Intel macOS, Windows), the
 * service-loaded registry must pick the pure-Java Groth16 verifier instead of a blst verifier that
 * can only return {@code INTERNAL_ERROR}.
 */
class Groth16VerifierSelectionTest {

    @Test
    void blstVerifierIsSelectedWhereLibblstIsBundled() {
        assumeBundledPlatform();
        assertTrue(new Groth16BLS12381Verifier().isAvailable());
        assertInstanceOf(Groth16BLS12381Verifier.class,
                VerifierRegistry.withServiceLoader().find(ProofSystemId.GROTH16, CurveId.BLS12_381).orElseThrow());
    }

    @Test
    void pureJavaVerifierIsSelectedOnIntelMacAndWindows() {
        String os = System.getProperty("os.name");
        String arch = System.getProperty("os.arch");
        try {
            for (String[] platform : new String[][]{{"Mac OS X", "x86_64"}, {"Windows 11", "amd64"}}) {
                System.setProperty("os.name", platform[0]);
                System.setProperty("os.arch", platform[1]);
                assertFalse(new Groth16BLS12381Verifier().isAvailable(), platform[0]);
                assertInstanceOf(Groth16BLS12381PureJavaVerifier.class,
                        VerifierRegistry.withServiceLoader().find(ProofSystemId.GROTH16, CurveId.BLS12_381).orElseThrow(),
                        platform[0]);
            }
        } finally {
            System.setProperty("os.name", os);
            System.setProperty("os.arch", arch);
        }
    }

    private static void assumeBundledPlatform() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch");
        boolean arm = arch.equals("aarch64") || arch.equals("arm64");
        assumeTrue(
                os.contains("linux") && (arm || arch.equals("amd64") || arch.equals("x86_64")) || os.contains("mac") && arm,
                "no libblst bundled for this platform");
    }
}
