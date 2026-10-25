package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.blst.BlstBls12381Provider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M3 / I7 and spec §13 (the deterministic-verifier contract): the verdict and layer of every
 * positive and negative vector case are identical across repeated runs, across the pure-Java and blst
 * providers, and across fresh JVMs. The comparison is on a SHA-256 digest of the ordered outcomes, so
 * a single differing case changes it.
 */
class BulletproofDeterminismTest {

    @Test
    @DisplayName("Verdicts are identical across two in-process runs on each provider, across providers, and in a fresh JVM per provider")
    void deterministic() throws Exception {
        JsonNode file = BulletproofVectorRunner.load();
        G1RangeVerifier pure = G1RangeVerifier.pureJava();
        G1RangeVerifier blst = G1RangeVerifier.withProvider(BlstBls12381Provider.createDefault());
        String pure1 = digest(BulletproofVectorRunner.verdicts(file, pure));
        String pure2 = digest(BulletproofVectorRunner.verdicts(file, pure));
        String blst1 = digest(BulletproofVectorRunner.verdicts(file, blst));
        String blst2 = digest(BulletproofVectorRunner.verdicts(file, blst));
        assertEquals(pure1, pure2, "pure Java, repeated run");
        assertEquals(blst1, blst2, "blst, repeated run");
        assertEquals(pure1, blst1, "pure Java vs blst");
        assertEquals(pure1, forked("pure"), "pure Java, fresh JVM");
        assertEquals(pure1, forked("blst"), "blst, fresh JVM");
    }

    static String digest(Map<String, String> verdicts) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (Map.Entry<String, String> e : verdicts.entrySet()) {
            sha.update((e.getKey() + "=" + e.getValue() + "\n").getBytes(StandardCharsets.UTF_8));
        }
        return HexFormat.of().formatHex(sha.digest());
    }

    private static String forked(String provider) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                Fork.class.getName(), provider).redirectErrorStream(true).start();
        String out;
        try (InputStream in = p.getInputStream()) {
            out = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertTrue(p.waitFor(20, TimeUnit.MINUTES), "fork timed out");
        assertEquals(0, p.exitValue(), out);
        String line = out.lines().filter(l -> l.startsWith("DIGEST ")).findFirst().orElseThrow(() -> new AssertionError(out));
        return line.substring("DIGEST ".length());
    }

    /** Runs in a fresh JVM: prints the digest of the verdicts on the named provider. */
    static final class Fork {
        public static void main(String[] args) throws Exception {
            G1RangeVerifier verifier = args[0].equals("blst")
                    ? G1RangeVerifier.withProvider(BlstBls12381Provider.createDefault()) : G1RangeVerifier.pureJava();
            System.out.println("DIGEST " + digest(BulletproofVectorRunner.verdicts(BulletproofVectorRunner.load(), verifier)));
        }
    }
}
