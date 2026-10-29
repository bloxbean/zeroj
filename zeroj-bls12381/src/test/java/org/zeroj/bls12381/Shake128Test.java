package org.zeroj.bls12381;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0061 I12: {@link Shake128} against outputs ZeroJ did not compute: FIPS 202's empty-message
 * value and CPython {@code hashlib.shake_128} ({@code shake128-reference/shake128-hashlib-v1.json}).
 * The CFRG duplex-sponge vectors exercise it again through {@code DuplexSponge}.
 */
class Shake128Test {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    @DisplayName("SHAKE128(\"\", 256) is the FIPS 202 known value")
    void emptyMessage() {
        assertEquals("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                HEX.formatHex(new Shake128().squeeze(32)));
    }

    @Test
    @DisplayName("Outputs equal CPython hashlib.shake_128 across the rate boundaries, absorbed whole and in pieces, squeezed whole and in pieces")
    void hashlib() throws IOException {
        JsonNode file;
        try (InputStream in = getClass().getResourceAsStream("/shake128-reference/shake128-hashlib-v1.json")) {
            assertNotNull(in, "shake128-hashlib-v1.json missing from the test classpath");
            file = new ObjectMapper().readTree(in);
        }
        assertEquals("zeroj-shake128-hashlib-v1", file.get("schema").asText());
        int outLength = Integer.parseInt(file.get("outputLength").asText());
        int cases = 0;
        for (JsonNode c : file.get("cases")) {
            int n = Integer.parseInt(c.get("messageLength").asText());
            byte[] message = new byte[n];
            for (int j = 0; j < n; j++) message[j] = (byte) ((7 * j + 3) % 256);
            byte[] expected = HEX.parseHex(c.get("outputHex").asText());
            assertEquals(outLength, expected.length);

            Shake128 whole = new Shake128();
            whole.update(message);
            assertArrayEquals(expected, whole.squeeze(outLength), "n = " + n);

            // Absorb in pieces of 1, 7, 167, ... octets; squeeze in pieces crossing the rate.
            Shake128 pieces = new Shake128();
            int[] sizes = {1, 7, 167, 168, 169, 3};
            for (int offset = 0, i = 0; offset < n; i++) {
                int len = Math.min(sizes[i % sizes.length], n - offset);
                pieces.update(message, offset, len);
                offset += len;
            }
            byte[] out = new byte[outLength];
            int[] outSizes = {0, 5, 163, 1, 168, 200};
            for (int offset = 0, i = 0; offset < outLength; i++) {
                int len = Math.min(outSizes[i % outSizes.length], outLength - offset);
                pieces.squeeze(out, offset, len);
                offset += len;
            }
            assertArrayEquals(expected, out, "pieces, n = " + n);
            cases++;
        }
        assertEquals(20, cases);
    }

    @Test
    @DisplayName("copy() is independent in both phases; absorbing after squeezing is refused")
    void copyAndPhases() {
        Shake128 a = new Shake128();
        a.update("abc".getBytes(StandardCharsets.US_ASCII));
        Shake128 b = a.copy();
        b.update("d".getBytes(StandardCharsets.US_ASCII));
        Shake128 c = a.copy();
        assertArrayEquals(c.squeeze(64), a.squeeze(64));
        Shake128 d = new Shake128();
        d.update("abcd".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(d.squeeze(40), b.squeeze(40));

        Shake128 reader = a.copy();
        byte[] next = reader.squeeze(10);
        assertArrayEquals(next, a.squeeze(10), "a copy taken while squeezing continues the same stream");
        assertThrows(IllegalStateException.class, () -> a.update(new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> a.squeeze(-1));
        assertThrows(NullPointerException.class, () -> new Shake128().update(null));
        assertThrows(IndexOutOfBoundsException.class, () -> new Shake128().update(new byte[2], 1, 2));
        assertEquals(0, new Shake128().squeeze(0).length);
        byte[] filled = new byte[4];
        Arrays.fill(filled, (byte) 9);
        new Shake128().squeeze(filled, 0, 0);
        assertArrayEquals(new byte[] {9, 9, 9, 9}, filled);
    }
}
