package com.bloxbean.cardano.zeroj.verifier.plonk;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validates that {@link GnarkFiatShamirTranscript} produces the exact same
 * challenge values as gnark's verifier.
 */
class GnarkTranscriptCompatTest {

    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    void allChallenges_matchGnark() throws Exception {
        String json = new String(getClass().getResourceAsStream(
                "/test-vectors/plonk-bls12381/plonk_cardano.json").readAllBytes(), StandardCharsets.UTF_8);

        // Parse expected values
        BigInteger expectedGamma = new BigInteger(jsonValue(json, "gamma"));
        BigInteger expectedBeta = new BigInteger(jsonValue(json, "beta"));
        BigInteger expectedAlpha = new BigInteger(jsonValue(json, "alpha"));
        BigInteger expectedZeta = new BigInteger(jsonValue(json, "zeta"));

        System.out.println("Expected gamma: " + expectedGamma);
        System.out.println("Expected beta:  " + expectedBeta);

        // Build transcript matching gnark's exact format
        var t = new GnarkFiatShamirTranscript(FR, "gamma", "beta", "alpha", "zeta");

        // Bind VK to gamma: S1, S2, S3, Ql, Qr, Qm, Qo, Qk
        // gnark uses Marshal() which returns RawBytes() = UNCOMPRESSED 96 bytes
        t.bind("gamma", hex(jsonHex(json, "s1_raw")));
        t.bind("gamma", hex(jsonHex(json, "s2_raw")));
        t.bind("gamma", hex(jsonHex(json, "s3_raw")));
        t.bind("gamma", hex(jsonHex(json, "ql_raw")));
        t.bind("gamma", hex(jsonHex(json, "qr_raw")));
        t.bind("gamma", hex(jsonHex(json, "qm_raw")));
        t.bind("gamma", hex(jsonHex(json, "qo_raw")));
        t.bind("gamma", hex(jsonHex(json, "qk_raw")));

        // Public input Z=33 as fr.Marshal() (32 bytes big-endian)
        t.bind("gamma", frMarshal(BigInteger.valueOf(33)));

        // Proof L,R,O UNCOMPRESSED (RawBytes = 96 bytes)
        t.bind("gamma", hex(jsonHex(json, "cmL_raw")));
        t.bind("gamma", hex(jsonHex(json, "cmR_raw")));
        t.bind("gamma", hex(jsonHex(json, "cmO_raw")));

        BigInteger gamma = t.computeChallenge("gamma");
        assertEquals(expectedGamma, gamma, "gamma must match gnark");

        // beta: no bindings
        BigInteger beta = t.computeChallenge("beta");
        assertEquals(expectedBeta, beta, "beta must match gnark");

        // alpha: bind Z (uncompressed)
        t.bind("alpha", hex(jsonHex(json, "cmZ_raw")));
        BigInteger alpha = t.computeChallenge("alpha");
        assertEquals(expectedAlpha, alpha, "alpha must match gnark");

        // zeta: bind H0, H1, H2 (uncompressed)
        t.bind("zeta", hex(jsonHex(json, "cmH0_raw")));
        t.bind("zeta", hex(jsonHex(json, "cmH1_raw")));
        t.bind("zeta", hex(jsonHex(json, "cmH2_raw")));
        BigInteger zeta = t.computeChallenge("zeta");
        assertEquals(expectedZeta, zeta, "zeta must match gnark");

        System.out.println("\nAll 4 challenges match gnark byte-for-byte!");
    }

    // --- Helpers ---

    private static byte[] frMarshal(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[32];
        if (raw.length <= 32)
            System.arraycopy(raw, 0, result, 32 - raw.length, raw.length);
        else
            System.arraycopy(raw, raw.length - 32, result, 0, 32);
        return result;
    }

    private static byte[] hex(String h) { return HexFormat.of().parseHex(h); }

    /** Extract a JSON string value by key (simple regex — works for flat values). */
    private static String jsonValue(String json, String key) {
        // Match: "key": "value" where value is a number string
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        if (m.find()) return m.group(1);
        throw new RuntimeException("Key not found: " + key);
    }

    /** Extract a hex string value by key. */
    private static String jsonHex(String json, String key) {
        return jsonValue(json, key);
    }
}
