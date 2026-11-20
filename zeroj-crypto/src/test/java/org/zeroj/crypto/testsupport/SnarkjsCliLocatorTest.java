package org.zeroj.crypto.testsupport;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SnarkjsCliLocatorTest {

    @Test
    void explicitPropertyMissing_doesNotFallThroughToPath(@TempDir Path dir) {
        Path missing = dir.resolve("does-not-exist-snarkjs");
        var res = SnarkjsCliLocator.resolvePinned(missing.toString(), null);
        assertFalse(res.isReady(), "explicit -Dzeroj.snarkjs must be authoritative");
        assertNull(res.binary());
        assertTrue(res.reason().contains("-Dzeroj.snarkjs"), res.reason());
    }

    @Test
    void explicitEnvWrongVersion_doesNotFallThroughToPath(@TempDir Path dir) throws Exception {
        Path fake = dir.resolve("fake-snarkjs.sh");
        Files.writeString(fake, "#!/bin/sh\necho 'snarkjs@0.9.9'\nexit 99\n");
        fake.toFile().setExecutable(true);

        var res = SnarkjsCliLocator.resolvePinned(null, fake.toString());
        assertFalse(res.isReady(), "explicit SNARKJS_BIN wrong version must fail closed");
        assertEquals("snarkjs@0.9.9", res.version());
        assertTrue(res.reason().contains("SNARKJS_BIN") && res.reason().contains("0.7.6"), res.reason());
    }

    @Test
    void explicitPropertyPinnedVersion_succeeds(@TempDir Path dir) throws Exception {
        Path fake = dir.resolve("pinned-snarkjs.sh");
        Files.writeString(fake, "#!/bin/sh\necho 'snarkjs@0.7.6'\nexit 99\n");
        fake.toFile().setExecutable(true);

        var res = SnarkjsCliLocator.resolvePinned(fake.toString(), null);
        assertTrue(res.isReady(), res.reason());
        assertEquals(fake.toString(), res.binary());
        assertEquals("snarkjs@0.7.6", res.version());
    }
}
