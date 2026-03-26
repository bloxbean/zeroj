package com.bloxbean.cardano.zeroj.prover.rapidsnark;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NativeLibraryLoaderTest {

    @Test
    void detectPlatform_returnsValidPlatform() {
        // Should not throw on any supported development machine
        NativeLibraryLoader.Platform platform = NativeLibraryLoader.detectPlatform();
        assertNotNull(platform);
        assertNotNull(platform.directory());
        assertNotNull(platform.fileName());
        assertNotNull(platform.resourcePath());

        System.out.println("Detected platform: " + platform
                + " (dir=" + platform.directory()
                + ", file=" + platform.fileName() + ")");
    }

    @Test
    void resourcePath_hasCorrectFormat() {
        for (NativeLibraryLoader.Platform platform : NativeLibraryLoader.Platform.values()) {
            String path = platform.resourcePath();
            assertTrue(path.startsWith("/native/"), "Path should start with /native/: " + path);
            assertTrue(path.endsWith(".so") || path.endsWith(".dylib"),
                    "Path should end with .so or .dylib: " + path);
        }
    }

    @Test
    void isAvailable_doesNotThrow() {
        // This tests that the method works without exceptions,
        // regardless of whether the library is actually bundled
        boolean available = NativeLibraryLoader.isAvailable();
        System.out.println("Native library available on classpath: " + available);
    }
}
