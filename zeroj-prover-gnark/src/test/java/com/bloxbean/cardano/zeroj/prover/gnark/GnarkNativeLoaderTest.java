package com.bloxbean.cardano.zeroj.prover.gnark;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GnarkNativeLoaderTest {

    @Test
    void detectPlatform_returnsValidPlatform() {
        GnarkNativeLoader.Platform platform = GnarkNativeLoader.detectPlatform();
        assertNotNull(platform);
        assertNotNull(platform.directory());
        assertNotNull(platform.fileName());
        assertTrue(platform.fileName().startsWith("libzeroj_gnark"));

        System.out.println("Detected platform: " + platform
                + " (dir=" + platform.directory()
                + ", file=" + platform.fileName() + ")");
    }

    @Test
    void resourcePath_hasCorrectFormat() {
        for (GnarkNativeLoader.Platform platform : GnarkNativeLoader.Platform.values()) {
            String path = platform.resourcePath();
            assertTrue(path.startsWith("/native/"), "Path should start with /native/: " + path);
            assertTrue(path.contains("libzeroj_gnark"),
                    "Path should contain libzeroj_gnark: " + path);
        }
    }

    @Test
    void isAvailable_doesNotThrow() {
        // gnark library won't be available until built from Go source
        boolean available = GnarkNativeLoader.isAvailable();
        System.out.println("gnark native library available: " + available);
        if (!available) {
            System.out.println("  Build with: make -C zeroj-prover-gnark/gnark-wrapper build");
        }
    }
}
