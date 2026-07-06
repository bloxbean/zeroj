package com.bloxbean.cardano.zeroj.circuit.lib.hash;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Correctness tests for the in-circuit {@link HmacSha512} gadget, cross-checked byte-for-byte
 * against JCA {@code Mac("HmacSHA512")} plus a fixed RFC 4231 vector, across the key-length
 * regimes that select different code paths (short key, exact-block key, over-block key that
 * must be hashed first, and the 32-byte chain-code case BIP32-Ed25519 uses).
 */
class HmacSha512Test {

    private static byte[] jcaHmac(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, "HmacSHA512"));
            // JCA rejects an empty key; the RFC/HMAC construction itself allows it. We never
            // test an empty key (BIP32 keys are 32-byte chain codes), so this guard is unused.
            return mac.doFinal(msg);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Build a circuit that computes HMAC(key,msg) and asserts each MAC byte equals `expected`. */
    private static void assertMatches(byte[] key, byte[] msg, byte[] expected, CurveId curve) {
        var builder = CircuitBuilder.create("hmac-k" + key.length + "-m" + msg.length);
        for (int i = 0; i < key.length; i++) builder.secretVar("k" + i);
        for (int i = 0; i < msg.length; i++) builder.secretVar("m" + i);
        for (int i = 0; i < 64; i++) builder.publicVar("e" + i);

        builder.define(api -> {
            Variable[] k = new Variable[key.length];
            for (int i = 0; i < key.length; i++) k[i] = api.var("k" + i);
            Variable[] m = new Variable[msg.length];
            for (int i = 0; i < msg.length; i++) m[i] = api.var("m" + i);
            Variable[] out = HmacSha512.hmacBytes(api, k, m);
            assertEquals(64, out.length);
            for (int i = 0; i < 64; i++) api.assertEqual(out[i], api.var("e" + i));
        });

        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < key.length; i++) in.put("k" + i, List.of(BigInteger.valueOf(key[i] & 0xff)));
        for (int i = 0; i < msg.length; i++) in.put("m" + i, List.of(BigInteger.valueOf(msg[i] & 0xff)));
        for (int i = 0; i < 64; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));

        assertDoesNotThrow(() -> builder.calculateWitness(in, curve),
                "HMAC-SHA512 gadget disagreed with reference (key=" + key.length + "B, msg=" + msg.length + "B)");
    }

    private static void assertMatchesJca(byte[] key, byte[] msg, CurveId curve) {
        assertMatches(key, msg, jcaHmac(key, msg), curve);
    }

    private static byte[] filled(int n, int v) {
        byte[] b = new byte[n];
        java.util.Arrays.fill(b, (byte) v);
        return b;
    }

    // ------------------------------------------------------------------
    // Fixed RFC 4231 anchor (independent of JCA)
    // ------------------------------------------------------------------

    @Test
    void rfc4231_case1_matches() {
        // Key = 0x0b x20, Data = "Hi There"
        byte[] key = filled(20, 0x0b);
        byte[] msg = "Hi There".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hex(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
              + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
        // sanity: JCA agrees with the published vector
        assertArrayEquals(expected, jcaHmac(key, msg));
        assertMatches(key, msg, expected, CurveId.BN254);
    }

    // ------------------------------------------------------------------
    // Key-length regimes vs JCA
    // ------------------------------------------------------------------

    @Test
    void shortKey_matchesJca() {
        assertMatchesJca("key".getBytes(StandardCharsets.US_ASCII),
                "The quick brown fox".getBytes(StandardCharsets.US_ASCII), CurveId.BN254);
    }

    @Test
    void chainCodeKey_32bytes_matchesJca() {
        // The BIP32-Ed25519 case: 32-byte key, ~40-byte message (0x00 ‖ kL ‖ kR ‖ LE32(i)).
        byte[] key = new byte[32];
        byte[] msg = new byte[1 + 32 + 32 + 4];
        new Random(7).nextBytes(key);
        new Random(8).nextBytes(msg);
        assertMatchesJca(key, msg, CurveId.BN254);
    }

    @Test
    void exactBlockKey_128bytes_matchesJca() {
        byte[] key = new byte[128];
        new Random(11).nextBytes(key);
        assertMatchesJca(key, "block-sized key".getBytes(StandardCharsets.US_ASCII), CurveId.BN254);
    }

    @Test
    void overBlockKey_131bytes_hashedFirst_matchesJca() {
        // Key > 128 bytes must be SHA-512'd first — exercises the long-key path.
        byte[] key = new byte[131];
        new Random(13).nextBytes(key);
        assertMatchesJca(key, "oversized key".getBytes(StandardCharsets.US_ASCII), CurveId.BN254);
    }

    @Test
    void emptyMessage_matchesJca() {
        assertMatchesJca("somekey".getBytes(StandardCharsets.US_ASCII), new byte[0], CurveId.BN254);
    }

    @Test
    void longMessage_multiBlock_matchesJca() {
        byte[] key = new byte[32];
        byte[] msg = new byte[300];
        new Random(21).nextBytes(key);
        new Random(22).nextBytes(msg);
        assertMatchesJca(key, msg, CurveId.BN254);
    }

    @Test
    void fieldAgnostic_worksOnBls12381() {
        byte[] key = new byte[32];
        new Random(99).nextBytes(key);
        assertMatchesJca(key, "bls12-381".getBytes(StandardCharsets.US_ASCII), CurveId.BLS12_381);
    }

    // ------------------------------------------------------------------
    // Negative
    // ------------------------------------------------------------------

    @Test
    void wrongMac_fails() {
        byte[] key = "key".getBytes(StandardCharsets.US_ASCII);
        byte[] msg = "data".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = jcaHmac(key, msg);
        expected[10] ^= 0x40; // corrupt one MAC byte

        var builder = CircuitBuilder.create("hmac-neg");
        for (int i = 0; i < key.length; i++) builder.secretVar("k" + i);
        for (int i = 0; i < msg.length; i++) builder.secretVar("m" + i);
        for (int i = 0; i < 64; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] k = new Variable[key.length];
            for (int i = 0; i < key.length; i++) k[i] = api.var("k" + i);
            Variable[] m = new Variable[msg.length];
            for (int i = 0; i < msg.length; i++) m[i] = api.var("m" + i);
            Variable[] out = HmacSha512.hmacBytes(api, k, m);
            for (int i = 0; i < 64; i++) api.assertEqual(out[i], api.var("e" + i));
        });

        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < key.length; i++) in.put("k" + i, List.of(BigInteger.valueOf(key[i] & 0xff)));
        for (int i = 0; i < msg.length; i++) in.put("m" + i, List.of(BigInteger.valueOf(msg[i] & 0xff)));
        for (int i = 0; i < 64; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));

        assertThrows(ArithmeticException.class, () -> builder.calculateWitness(in, CurveId.BN254));
    }

    // ------------------------------------------------------------------
    // Constraint-count report
    // ------------------------------------------------------------------

    @Test
    void constraintCount_bip32Shape_reported() {
        int keyLen = 32, msgLen = 1 + 32 + 32 + 4;
        var builder = CircuitBuilder.create("hmac-cost");
        for (int i = 0; i < keyLen; i++) builder.secretVar("k" + i);
        for (int i = 0; i < msgLen; i++) builder.secretVar("m" + i);
        builder.define(api -> {
            Variable[] k = new Variable[keyLen];
            for (int i = 0; i < keyLen; i++) k[i] = api.var("k" + i);
            Variable[] m = new Variable[msgLen];
            for (int i = 0; i < msgLen; i++) m[i] = api.var("m" + i);
            HmacSha512.hmacBytes(api, k, m);
        });
        int c = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0027 M2] HMAC-SHA512 (BIP32 shape: 32B key, 69B msg) constraints = " + c);
        // inner block (K'^ipad ‖ msg) = 1 block; outer (K'^opad ‖ digest) = 2 blocks -> ~3 blocks.
        assertTrue(c > 200_000 && c < 700_000, "unexpected HMAC cost: " + c);
    }

    // ------------------------------------------------------------------

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }
}
