package com.bloxbean.cardano.zeroj.it.spi;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Backend discovery from <b>packaged JARs</b>, per ADR-0044's verification gates.
 *
 * <p>ADR-0044 merged {@code zeroj-verifier-core} into {@code zeroj-backend-spi}. That merger is
 * only allowed to change packaging, so ServiceLoader discovery must produce exactly the same set of
 * backends as before. The unit tests inside {@code zeroj-backend-spi} exercise the registry against
 * hand-registered fakes; this test exercises the real thing across module boundaries, reading
 * {@code META-INF/services} out of the sibling projects' built jars rather than from loose class
 * directories.</p>
 *
 * <p>Two properties matter here and neither is covered by a same-module test:</p>
 * <ol>
 *   <li>the provider files survived the module moves and are still <em>inside the jars</em>; and</li>
 *   <li>classpath presence alone does not enable a backend that policy disables — the BN254
 *       verifiers are on this classpath and must stay unregistered.</li>
 * </ol>
 */
class VerifierServiceLoaderPackagingTest {

    private static final String PROVIDER_RESOURCE =
            "META-INF/services/com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier";

    @Test
    @DisplayName("ServiceLoader provider files are read from packaged jars, not class directories")
    void providerFilesAreLoadedFromJars() throws Exception {
        Enumeration<URL> resources = getClass().getClassLoader().getResources(PROVIDER_RESOURCE);
        List<URL> urls = Collections.list(resources);

        assertFalse(urls.isEmpty(), "no ZkVerifier provider files on the test classpath");

        List<URL> nonJar = urls.stream()
                .filter(u -> !"jar".equals(u.getProtocol()))
                .toList();
        assertTrue(nonJar.isEmpty(),
                "expected every ZkVerifier provider file to come from a packaged jar, but found: " + nonJar);
    }

    @Test
    @DisplayName("Discovery finds exactly the shipped BLS12-381 backends")
    void serviceLoaderDiscoversShippedBackends() {
        Set<String> discovered = VerifierRegistry.withServiceLoader().all().stream()
                .map(v -> v.descriptor().name())
                .collect(Collectors.toSet());

        assertEquals(
                Set.of("groth16-bls12381-blst",
                        "groth16-bls12381-java",
                        "plonk-bls12381-java",
                        "bbs-bls12381-java"),
                discovered,
                "the set of ServiceLoader-discovered backends changed");
    }

    @Test
    @DisplayName("Legacy BN254 backends stay unregistered despite being on the classpath")
    void bn254BackendsAreNotDiscovered() {
        VerifierRegistry registry = VerifierRegistry.withServiceLoader();

        assertTrue(registry.find(ProofSystemId.GROTH16, CurveId.BN254).isEmpty(),
                "Groth16 BN254 must not be discoverable by default");
        assertTrue(registry.find(ProofSystemId.PLONK, CurveId.BN254).isEmpty(),
                "PlonK BN254 must not be discoverable by default");
    }

    @Test
    @DisplayName("Each shipped proof-system/curve pair resolves to a backend")
    void everyShippedCombinationResolves() {
        VerifierRegistry registry = VerifierRegistry.withServiceLoader();

        assertTrue(registry.find(ProofSystemId.GROTH16, CurveId.BLS12_381).isPresent());
        assertTrue(registry.find(ProofSystemId.PLONK, CurveId.BLS12_381).isPresent());
        assertTrue(registry.find(ProofSystemId.BBS, CurveId.BLS12_381).isPresent());
    }

    @Test
    @DisplayName("Two Groth16 BLS12-381 backends coexist and find() is deterministic")
    void duplicateCapabilityIsRetainedAndResolutionIsStable() {
        VerifierRegistry registry = VerifierRegistry.withServiceLoader();

        List<ZkVerifier> groth16 = new ArrayList<>(registry.all().stream()
                .filter(v -> v.descriptor().supports(ProofSystemId.GROTH16, CurveId.BLS12_381))
                .toList());

        // Both the blst-backed and the pure-Java Groth16 backend are registered: discovery must not
        // silently deduplicate by capability, because the two are separately selectable providers.
        assertEquals(2, groth16.size(),
                "expected both the blst and pure-Java Groth16 BLS12-381 backends to be registered");

        String first = registry.find(ProofSystemId.GROTH16, CurveId.BLS12_381).orElseThrow()
                .descriptor().name();
        assertEquals(first,
                VerifierRegistry.withServiceLoader()
                        .find(ProofSystemId.GROTH16, CurveId.BLS12_381).orElseThrow()
                        .descriptor().name(),
                "find() must resolve the same backend across registry instances");
    }
}
