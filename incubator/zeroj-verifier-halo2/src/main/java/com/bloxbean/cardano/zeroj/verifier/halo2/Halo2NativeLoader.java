package com.bloxbean.cardano.zeroj.verifier.halo2;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Platform-aware loader for the Halo2 Rust native library.
 */
public final class Halo2NativeLoader {

    private static volatile Path extractedPath;

    private Halo2NativeLoader() {}

    /**
     * Check if the native library is available for the current platform.
     */
    public static boolean isAvailable() {
        try {
            extractLibrary();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract the native library to a temp file and return its path.
     */
    public static synchronized Path extractLibrary() throws IOException {
        if (extractedPath != null && Files.exists(extractedPath)) {
            return extractedPath;
        }

        String platform = detectPlatform();
        String libName = System.getProperty("os.name").toLowerCase().contains("mac")
                ? "libzeroj_halo2.dylib"
                : "libzeroj_halo2.so";

        String resourcePath = "/native/" + platform + "/" + libName;
        try (InputStream is = Halo2NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IOException("Native library not found: " + resourcePath);
            }
            Path tempFile = Files.createTempFile("zeroj-halo2-", libName);
            Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);
            tempFile.toFile().deleteOnExit();
            extractedPath = tempFile;
            return tempFile;
        }
    }

    static String detectPlatform() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();

        String osName = os.contains("mac") ? "macos" : os.contains("linux") ? "linux" : "unknown";
        String archName = arch.contains("aarch64") || arch.contains("arm64") ? "arm64" : "x86_64";

        return osName + "-" + archName;
    }
}
