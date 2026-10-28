package org.zeroj.blst.ffm;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 I4 / D6: every bundled libblst is in the SHA-256 manifest the loader enforces, and none
 * is the former third-party JNI binary. Before this gate the committed Linux libraries were
 * byte-identical to the ones inside {@code foundation.icon:blst-java:0.3.2}; this test fails on any
 * such regression on every platform, not only the one running the tests.
 */
class BundledLibblstProvenanceTest {
    private static final List<String> EXPECTED_TARGETS =
            List.of("linux/aarch64/libblst.so", "linux/amd64/libblst.so", "mac/aarch64/libblst.dylib");

    /** SHA-256 of the libblst binaries inside blst-java 0.3.2, which must never be bundled again. */
    private static final List<String> FORBIDDEN_SHA256 = List.of(
            "bd250731c0805cab213c1db860dbcd3bb8848955aa1da7a6fc81a11235b92817",  // Linux/amd64
            "b21d0839f21b571d68983543f98aa949f0d2e2d1673c797774eaf43966727b38"); // Linux/aarch64

    @Test
    void manifestCoversExactlyTheBundledTargets() throws IOException {
        assertEquals(EXPECTED_TARGETS, List.copyOf(manifest().keySet()));
    }

    @Test
    void everyBundledLibraryMatchesTheManifestAndIsSourceBuilt() throws Exception {
        for (Map.Entry<String, String> e : manifest().entrySet()) {
            byte[] bytes = resource(e.getKey());
            assertNotNull(bytes, "missing bundled library " + e.getKey());
            String sha = sha256(bytes);
            assertEquals(e.getValue(), sha, "manifest mismatch for " + e.getKey());
            assertFalse(FORBIDDEN_SHA256.contains(sha), e.getKey() + " is the third-party blst-java binary");
            assertFalse(contains(bytes, "Java_supranational_blst".getBytes(StandardCharsets.US_ASCII)),
                    e.getKey() + " exports JNI symbols of the former blst-java binding");
            assertTrue(contains(bytes, "blst_p1s_mult_pippenger".getBytes(StandardCharsets.US_ASCII)),
                    e.getKey() + " does not export the blst C API");
        }
    }

    @Test
    void theLoaderUsesTheManifestForThisPlatform() throws Exception {
        String library = BlstFfm.platformLibrary();
        assertEquals(manifest().get(library), BlstFfm.expectedSha256(library));
        assertThrows(IllegalStateException.class, () -> BlstFfm.expectedSha256("windows/amd64/libblst.dll"));
    }

    private static Map<String, String> manifest() throws IOException {
        byte[] raw = resource("libblst.sha256");
        assertNotNull(raw, "libblst.sha256 manifest missing");
        Map<String, String> out = new LinkedHashMap<>();
        for (String line : new String(raw, StandardCharsets.US_ASCII).split("\n")) {
            if (line.isBlank()) continue;
            String[] parts = line.trim().split("\\s+");
            assertEquals(2, parts.length, "malformed manifest line: " + line);
            assertTrue(parts[0].matches("[0-9a-f]{64}"), "malformed digest: " + line);
            out.put(parts[1], parts[0]);
        }
        return out;
    }

    private static byte[] resource(String path) throws IOException {
        try (InputStream in = BlstFfm.class.getResourceAsStream(BlstFfm.RESOURCE_ROOT + path)) {
            return in == null ? null : in.readAllBytes();
        }
    }

    private static String sha256(byte[] bytes) throws NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
