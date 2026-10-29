package org.zeroj.blst.ffm;

import java.util.Locale;

/**
 * Which bundled {@code libblst} serves a platform (ADR-0062 D3). Kept apart from {@link BlstFfm} so
 * callers can ask whether a library is bundled without triggering the load.
 *
 * <p>Bundled platforms: linux/amd64, linux/aarch64 and mac/aarch64. Every other platform,
 * including Intel macOS and Windows, has no library and must use the pure-Java provider.</p>
 */
public final class BlstPlatform {

    private BlstPlatform() {}

    /**
     * True if a {@code libblst} is bundled for this JVM's {@code os.name} / {@code os.arch}. This
     * does not load or verify the library: a bundled library that fails its SHA-256 check still
     * makes {@link BlstFfm} throw.
     */
    public static boolean isSupported() {
        try {
            library(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }

    /** {@code <os>/<arch>/libblst.<ext>} for the given values; throws if none is bundled. */
    static String library(String osName, String osArch) {
        String os = osName.toLowerCase(Locale.ROOT);
        String arch = osArch.toLowerCase(Locale.ROOT);
        boolean arm64 = arch.equals("aarch64") || arch.equals("arm64");
        boolean x64 = arch.equals("amd64") || arch.equals("x86_64");
        if (os.contains("mac") || os.contains("darwin")) {
            if (arm64) return "mac/aarch64/libblst.dylib";
            // No Intel macOS library is built: GitHub retired the free Intel runner.
            throw new IllegalStateException("zeroj-blst has no libblst for macOS '" + arch
                    + "' (only Apple silicon is bundled); use the pure-Java provider");
        }
        if (os.contains("linux")) {
            if (arm64) return "linux/aarch64/libblst.so";
            if (x64) return "linux/amd64/libblst.so";
            throw new IllegalStateException("zeroj-blst has no libblst for arch '" + arch + "'; use the pure-Java provider");
        }
        throw new IllegalStateException("zeroj-blst has no libblst for OS '" + os + "'; use the pure-Java provider");
    }
}
