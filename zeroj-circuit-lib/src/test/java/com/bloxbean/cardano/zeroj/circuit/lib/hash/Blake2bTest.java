package com.bloxbean.cardano.zeroj.circuit.lib.hash;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Correctness tests for the in-circuit {@link Blake2b} gadget.
 *
 * <p>blake2b-224 / -256 outputs are cross-checked byte-for-byte against cardano-client's
 * {@code Blake2bUtil} — the <i>exact</i> implementation Cardano uses for key hashes, so a pass
 * proves Cardano-compatibility directly. The compression core is additionally pinned to the
 * RFC 7693 Appendix A blake2b-512("abc") vector (an oracle independent of that library).
 */
class Blake2bTest {

    private static void assertMatches(byte[] msg, int outLen, byte[] expected, CurveId curve) {
        int n = msg.length;
        var builder = CircuitBuilder.create("blake2b-" + outLen + "-" + n);
        for (int i = 0; i < n; i++) builder.secretVar("b" + i);
        for (int i = 0; i < outLen; i++) builder.publicVar("e" + i);

        builder.define(api -> {
            Variable[] bytes = new Variable[n];
            for (int i = 0; i < n; i++) bytes[i] = api.var("b" + i);
            Variable[] out = Blake2b.hash(api, bytes, outLen);
            assertEquals(outLen, out.length);
            for (int i = 0; i < outLen; i++) api.assertEqual(out[i], api.var("e" + i));
        });

        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < n; i++) in.put("b" + i, List.of(BigInteger.valueOf(msg[i] & 0xff)));
        for (int i = 0; i < outLen; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));

        assertDoesNotThrow(() -> builder.calculateWitness(in, curve),
                "blake2b-" + (outLen * 8) + " gadget disagreed with reference for msg length " + n);
    }

    // ------------------------------------------------------------------
    // vs cardano-client Blake2bUtil (the Cardano oracle)
    // ------------------------------------------------------------------

    @Test
    void blake2b224_vsCardanoClient_variousLengths() {
        for (int len : new int[]{0, 1, 3, 32, 64, 127, 128, 129, 200}) {
            byte[] msg = new byte[len];
            new Random(100 + len).nextBytes(msg);
            assertMatches(msg, 28, Blake2bUtil.blake2bHash224(msg), CurveId.BN254);
        }
    }

    @Test
    void blake2b256_vsCardanoClient_variousLengths() {
        for (int len : new int[]{0, 3, 32, 128, 130}) {
            byte[] msg = new byte[len];
            new Random(200 + len).nextBytes(msg);
            assertMatches(msg, 32, Blake2bUtil.blake2bHash256(msg), CurveId.BN254);
        }
    }

    @Test
    void blake2b224_ed25519PubKeyShape_vsCardanoClient() {
        // The Cardano payment-key-hash case: blake2b-224 of a 32-byte Ed25519 public key.
        byte[] pubkey = new byte[32];
        new Random(1852).nextBytes(pubkey);
        assertMatches(pubkey, 28, Blake2bUtil.blake2bHash224(pubkey), CurveId.BN254);
    }

    // ------------------------------------------------------------------
    // RFC 7693 fixed anchor (independent of cardano-client)
    // ------------------------------------------------------------------

    @Test
    void rfc7693_blake2b512_abc_matches() {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hex(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
              + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
        assertMatches(msg, 64, expected, CurveId.BN254);
    }

    // ------------------------------------------------------------------
    // Field-agnostic + negative
    // ------------------------------------------------------------------

    @Test
    void fieldAgnostic_worksOnBls12381() {
        byte[] pubkey = new byte[32];
        new Random(381).nextBytes(pubkey);
        assertMatches(pubkey, 28, Blake2bUtil.blake2bHash224(pubkey), CurveId.BLS12_381);
    }

    @Test
    void wrongDigest_fails() {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = Blake2bUtil.blake2bHash224(msg);
        expected[5] ^= 0x20;

        var builder = CircuitBuilder.create("blake2b-neg");
        for (int i = 0; i < msg.length; i++) builder.secretVar("b" + i);
        for (int i = 0; i < 28; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] bytes = new Variable[msg.length];
            for (int i = 0; i < msg.length; i++) bytes[i] = api.var("b" + i);
            Variable[] out = Blake2b.hash224(api, bytes);
            for (int i = 0; i < 28; i++) api.assertEqual(out[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < msg.length; i++) in.put("b" + i, List.of(BigInteger.valueOf(msg[i] & 0xff)));
        for (int i = 0; i < 28; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));
        assertThrows(ArithmeticException.class, () -> builder.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void constraintCount_keyHashShape_reported() {
        int n = 32; // Ed25519 pubkey -> blake2b-224
        var builder = CircuitBuilder.create("blake2b-cost");
        for (int i = 0; i < n; i++) builder.secretVar("b" + i);
        builder.define(api -> {
            Variable[] bytes = new Variable[n];
            for (int i = 0; i < n; i++) bytes[i] = api.var("b" + i);
            Blake2b.hash224(api, bytes);
        });
        int c = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0027 M3] blake2b-224 (32B input, one block) constraints = " + c);
        assertTrue(c > 20_000 && c < 200_000, "unexpected blake2b cost: " + c);
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }
}
