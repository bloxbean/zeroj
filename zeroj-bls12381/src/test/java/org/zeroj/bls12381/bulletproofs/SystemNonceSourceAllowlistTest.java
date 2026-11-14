package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Spec §7.3: the public prover refuses a default {@link SecureRandom} whose algorithm is not
 * allowlisted. This runs the public {@code prove} in a fresh JVM whose first provider supplies the
 * default {@code SecureRandom}, so it covers {@link SystemNonceSource#create} and not only
 * {@link SystemNonceSource#checked} (reviewer 2, R2-2; mutant MU04). The allowlist is a sanity
 * check, not an entropy proof.
 */
class SystemNonceSourceAllowlistTest {

    static final String ALGORITHM = "ZeroJTestPRNG";

    @Test
    @DisplayName("Forked JVM: a non-allowlisted default SecureRandom makes the public prove throw IllegalStateException")
    void forkedJvmRefusesDefault() throws IOException, InterruptedException {
        String java = ProcessHandle.current().info().command().orElseThrow();
        String classpath = System.getProperty("java.class.path");
        String output;
        int exitValue;
        // Output goes to a file, so the timeout applies even if the probe hangs.
        Path log = Files.createTempFile("zeroj-probe", ".log");
        try {
            Process process = new ProcessBuilder(java, "-cp", classpath, Probe.class.getName())
                    .redirectErrorStream(true).redirectOutput(log.toFile()).start();
            if (!process.waitFor(60, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                fail("probe timed out: " + Files.readString(log, StandardCharsets.UTF_8));
            }
            output = Files.readString(log, StandardCharsets.UTF_8);
            exitValue = process.exitValue();
        } finally {
            Files.deleteIfExists(log);
        }
        assertEquals(0, exitValue, output);
        // The probe is not vacuous: the substituted algorithm really is the JVM's default.
        assertTrue(output.contains("default: " + ALGORITHM), output);
        assertTrue(output.contains("prove: IllegalStateException SecureRandom algorithm " + ALGORITHM
                + " is not accepted for range-proof nonces"), output);
    }

    /** Run in a fresh JVM by {@link #forkedJvmRefusesDefault}; it installs its provider first. */
    static final class Probe {
        public static void main(String[] args) {
            Security.insertProviderAt(new TestProvider(), 1);
            System.out.println("default: " + new SecureRandom().getAlgorithm());
            try {
                G1RangeProver.pureJava().prove(G1PedersenOpening.of(BigInteger.valueOf(5), BigInteger.valueOf(7)),
                        16, new byte[] {1});
                System.out.println("prove: PROVED");
            } catch (RuntimeException e) {
                System.out.println("prove: " + e.getClass().getSimpleName() + " " + e.getMessage());
            }
        }
    }

    /** Registers {@value #ALGORITHM}, without reflection, as its only {@code SecureRandom}. */
    private static final class TestProvider extends Provider {
        TestProvider() {
            super("ZeroJTestProvider", "1.0", "a non-allowlisted SecureRandom for SystemNonceSourceAllowlistTest");
            putService(new Service(this, "SecureRandom", ALGORITHM, CounterSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return new CounterSpi();
                }
            });
        }
    }

    /**
     * A counter: predictable, so unacceptable for nonces, but non-degenerate, so a prover that
     * skipped the allowlist would complete a proof and the probe would print {@code PROVED}.
     */
    private static final class CounterSpi extends SecureRandomSpi {
        private int next = 1;

        @Override
        protected void engineSetSeed(byte[] seed) {
        }

        @Override
        protected void engineNextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) next++;
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            return new byte[numBytes];
        }
    }
}
