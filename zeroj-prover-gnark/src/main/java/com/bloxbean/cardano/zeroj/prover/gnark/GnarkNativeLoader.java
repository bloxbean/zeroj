package com.bloxbean.cardano.zeroj.prover.gnark;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Platform-aware loader for the gnark native shared library.
 *
 * <p>Extracts the correct shared library from classpath resources
 * ({@code /native/{platform}/libzeroj_gnark.{so,dylib}}) to a temp
 * directory and returns the path for FFM loading.</p>
 *
 * <p>The gnark wrapper does not ship pre-built binaries. The shared
 * library must be compiled from the Go wrapper using {@code make -C gnark-wrapper build}
 * before packaging.</p>
 */
public final class GnarkNativeLoader {

    private static volatile Path cachedLibraryPath;

    private GnarkNativeLoader() {}

    /**
     * Supported platforms for the gnark shared library.
     */
    public enum Platform {
        LINUX_X86_64("linux-x86_64", "libzeroj_gnark.so"),
        LINUX_ARM64("linux-arm64", "libzeroj_gnark.so"),
        MACOS_X86_64("macos-x86_64", "libzeroj_gnark.dylib"),
        MACOS_ARM64("macos-arm64", "libzeroj_gnark.dylib");

        private final String directory;
        private final String fileName;

        Platform(String directory, String fileName) {
            this.directory = directory;
            this.fileName = fileName;
        }

        public String directory() { return directory; }
        public String fileName() { return fileName; }

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
                "Unsupported platform: os=" + os + ", arch=" + arch);
    }

    /**
     * Extract the native library for the current platform from classpath.
     *
     * @return path to the extracted shared library
     * @throws IOException if extraction fails
     */
    public static Path extractLibrary() throws IOException {
        return extractLibrary(detectPlatform());
    }

    /**
     * Extract the native library for a specific platform.
     */
    public static Path extractLibrary(Platform platform) throws IOException {
        Path cached = cachedLibraryPath;
        if (cached != null && Files.exists(cached)) {
            return cached;
        }

        synchronized (GnarkNativeLoader.class) {
            cached = cachedLibraryPath;
            if (cached != null && Files.exists(cached)) {
                return cached;
            }

            String resourcePath = platform.resourcePath();
            try (InputStream in = GnarkNativeLoader.class.getResourceAsStream(resourcePath)) {
                if (in == null) {
                    throw new IOException(
                            "Native library not found on classpath: " + resourcePath
                                    + ". Build the gnark wrapper first: make -C gnark-wrapper build");
                }

                Path tempDir = Files.createTempDirectory("zeroj-gnark-");
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
     * Check if the native library is available on the classpath for the current platform.
     */
    public static boolean isAvailable() {
        try {
            Platform platform = detectPlatform();
            return GnarkNativeLoader.class.getResource(platform.resourcePath()) != null;
        } catch (UnsupportedOperationException e) {
            return false;
        }
    }

    /**
     * Load library from an explicit path (bypasses classpath extraction).
     */
    public static Path fromPath(Path libraryPath) throws IOException {
        if (!Files.exists(libraryPath)) {
            throw new IOException("Library file not found: " + libraryPath);
        }
        return libraryPath;
    }
}
