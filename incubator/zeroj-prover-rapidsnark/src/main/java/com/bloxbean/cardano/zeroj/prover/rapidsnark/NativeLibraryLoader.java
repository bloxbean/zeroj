package com.bloxbean.cardano.zeroj.prover.rapidsnark;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Platform-aware loader for the rapidsnark native library.
 *
 * <p>Extracts the correct shared library from classpath resources
 * ({@code /native/{platform}/librapidsnark.{so,dylib}}) to a temp
 * directory and returns the path for FFM loading.</p>
 */
public final class NativeLibraryLoader {

    private static volatile Path cachedLibraryPath;

    private NativeLibraryLoader() {}

    /**
     * Supported platforms for rapidsnark native library.
     */
    public enum Platform {
        LINUX_X86_64("linux-x86_64", "librapidsnark.so"),
        LINUX_ARM64("linux-arm64", "librapidsnark.so"),
        MACOS_X86_64("macos-x86_64", "librapidsnark.dylib"),
        MACOS_ARM64("macos-arm64", "librapidsnark.dylib");

        private final String directory;
        private final String fileName;

        Platform(String directory, String fileName) {
            this.directory = directory;
            this.fileName = fileName;
        }

        public String directory() { return directory; }
        public String fileName() { return fileName; }

        /**
         * Classpath resource path for this platform's library.
         */
        public String resourcePath() {
            return "/native/" + directory + "/" + fileName;
        }
    }

    /**
     * Detect the current platform from system properties.
     *
     * @return the detected platform
     * @throws UnsupportedOperationException if the platform is not supported
     */
    public static Platform detectPlatform() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();

        boolean isLinux = os.contains("linux");
        boolean isMac = os.contains("mac") || os.contains("darwin");
        boolean isX86_64 = arch.equals("amd64") || arch.equals("x86_64");
        boolean isArm64 = arch.equals("aarch64") || arch.equals("arm64");

        if (isLinux && isX86_64) return Platform.LINUX_X86_64;
        if (isLinux && isArm64) return Platform.LINUX_ARM64;
        if (isMac && isArm64) return Platform.MACOS_ARM64;
        if (isMac && isX86_64) return Platform.MACOS_X86_64;

        throw new UnsupportedOperationException(
                "Unsupported platform: os=" + os + ", arch=" + arch
                        + ". Supported: linux x86_64/arm64, macOS x86_64/arm64");
    }

    /**
     * Extract the native library for the current platform from classpath
     * to a temporary directory.
     *
     * @return path to the extracted shared library
     * @throws IOException if extraction fails
     * @throws UnsupportedOperationException if the platform is not supported
     */
    public static Path extractLibrary() throws IOException {
        return extractLibrary(detectPlatform());
    }

    /**
     * Extract the native library for a specific platform from classpath.
     *
     * @param platform the target platform
     * @return path to the extracted shared library
     * @throws IOException if extraction fails
     */
    public static Path extractLibrary(Platform platform) throws IOException {
        Path cached = cachedLibraryPath;
        if (cached != null && Files.exists(cached)) {
            return cached;
        }

        synchronized (NativeLibraryLoader.class) {
            cached = cachedLibraryPath;
            if (cached != null && Files.exists(cached)) {
                return cached;
            }

            String resourcePath = platform.resourcePath();
            try (InputStream in = NativeLibraryLoader.class.getResourceAsStream(resourcePath)) {
                if (in == null) {
                    throw new IOException(
                            "Native library not found on classpath: " + resourcePath
                                    + ". Ensure the rapidsnark binary for " + platform.directory()
                                    + " is bundled in the JAR.");
                }

                Path tempDir = Files.createTempDirectory("zeroj-rapidsnark-");
                Path libPath = tempDir.resolve(platform.fileName());
                Files.copy(in, libPath, StandardCopyOption.REPLACE_EXISTING);
                libPath.toFile().deleteOnExit();
                tempDir.toFile().deleteOnExit();

                cachedLibraryPath = libPath;
                return libPath;
            }
        }
    }

    /**
     * Check if the native library is available on the classpath for the
     * current platform.
     *
     * @return true if the library resource exists
     */
    public static boolean isAvailable() {
        try {
            Platform platform = detectPlatform();
            return NativeLibraryLoader.class.getResource(platform.resourcePath()) != null;
        } catch (UnsupportedOperationException e) {
            return false;
        }
    }

    /**
     * Load library from an explicit path (bypasses classpath extraction).
     *
     * @param libraryPath path to the shared library file
     * @return the same path, after validation
     * @throws IOException if the file does not exist
     */
    public static Path fromPath(Path libraryPath) throws IOException {
        if (!Files.exists(libraryPath)) {
            throw new IOException("Library file not found: " + libraryPath);
        }
        return libraryPath;
    }
}
