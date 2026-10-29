package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.Normalizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 required examples for {@code pedersen-jubjub-bytes-v1}, written as executable tests so
 * the documented usage cannot drift from the library. Each example commits to exact octets; the
 * profile never decodes, normalizes or canonicalizes anything.
 */
class PedersenBytesExamplesTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    @DisplayName("Raw bytes: commit offline, publish the point, open by disclosure or check privately")
    void rawBytes() {
        byte[] payload = {0x00, 0x01, (byte) 0xfe, (byte) 0xff, 0x00};

        // Generation (offline / isolated): a fresh blinding, never derived from the payload.
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment commitment = PedersenCommitment.commitBytes(payload, r);
        byte[] published = commitment.toPointBytes(); // the whole wire format: 32 octets

        // A verifier who is shown the payload and r (disclosed opening):
        PedersenBytesCommitment received = PedersenBytesCommitment.decode(published);
        assertTrue(PedersenCommitment.verifyBytes(received, payload, r));

        // A holder re-checking a still-private payload recomputes with generation and compares points.
        assertEquals(received, PedersenCommitment.commitBytes(payload, r));
    }

    @Test
    @DisplayName("Strings: choose UTF-8 explicitly; visually equal strings can commit differently")
    void strings() {
        String composed = Normalizer.normalize("café", Normalizer.Form.NFC);
        String decomposed = Normalizer.normalize("café", Normalizer.Form.NFD);
        assertNotEquals(composed, decomposed);

        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(composed.getBytes(StandardCharsets.UTF_8), r);
        assertTrue(PedersenCommitment.verifyBytes(c, composed.getBytes(StandardCharsets.UTF_8), r));
        assertFalse(PedersenCommitment.verifyBytes(c, decomposed.getBytes(StandardCharsets.UTF_8), r),
                "NFD octets differ from NFC octets; normalize in the application if that matters");
        assertFalse(PedersenCommitment.verifyBytes(c, composed.getBytes(StandardCharsets.UTF_16BE), r),
                "the charset is part of the octets");
    }

    @Test
    @DisplayName("JSON: commit the exact serialized octets; whitespace and key order are significant")
    void json() {
        byte[] compact = "{\"amount\":10,\"to\":\"addr1\"}".getBytes(StandardCharsets.UTF_8);
        byte[] spaced = "{\"amount\": 10, \"to\": \"addr1\"}".getBytes(StandardCharsets.UTF_8);
        byte[] reordered = "{\"to\":\"addr1\",\"amount\":10}".getBytes(StandardCharsets.UTF_8);

        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(compact, r);
        assertTrue(PedersenCommitment.verifyBytes(c, compact, r));
        assertFalse(PedersenCommitment.verifyBytes(c, spaced, r));
        assertFalse(PedersenCommitment.verifyBytes(c, reordered, r));
        // Semantic JSON canonicalization is an application protocol with its own version, not an option here.
    }

    @Test
    @DisplayName("Documents: stream a file by exact length or to end with a maximum; same octets, same commitment")
    void documents(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("report.pdf");
        Files.write(file, PedersenBytesStreamTest.pattern(300_000));
        long size = Files.size(file);
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);

        PedersenBytesCommitment exact;
        try (InputStream in = Files.newInputStream(file)) { // the caller owns and closes the stream
            exact = PedersenCommitment.commitBytes(in, size, r);
        }
        PedersenBytesCommitment toEnd;
        try (InputStream in = Files.newInputStream(file)) {
            toEnd = PedersenCommitment.commitBytesToEnd(in, 10L << 20, r); // application limit: 10 MiB
        }
        assertEquals(exact, toEnd);
        assertEquals(exact, PedersenCommitment.commitBytes(Files.readAllBytes(file), r));

        // The file name or path is not committed unless the application puts it in the payload.
        Path renamed = Files.move(file, dir.resolve("renamed.bin"));
        try (InputStream in = Files.newInputStream(renamed)) {
            assertTrue(PedersenCommitment.verifyBytes(exact, in, size, r));
        }

        // A declared length that is wrong fails instead of committing to a prefix or ignoring a suffix.
        try (InputStream in = Files.newInputStream(renamed)) {
            assertThrows(IOException.class, () -> PedersenCommitment.commitBytes(in, size + 1, r));
        }
        try (InputStream in = Files.newInputStream(renamed)) {
            assertThrows(IOException.class, () -> PedersenCommitment.commitBytes(in, size - 1, r));
        }
        // A document over the application limit fails rather than being truncated.
        try (InputStream in = Files.newInputStream(renamed)) {
            assertThrows(IOException.class, () -> PedersenCommitment.commitBytesToEnd(in, size - 1, r));
        }
    }
}
