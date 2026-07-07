package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the annotation-DSL hash adapters ({@link ZkSha512}, {@link ZkHmacSha512},
 * {@link ZkBlake2b}). Each hashes a {@link ZkBytes} input via the adapter and asserts the
 * {@link ZkBytes} output equals the authoritative reference digest (JCA / cardano-client), proving
 * the adapters faithfully expose the underlying (separately JCA-validated) gadgets.
 */
class ZkHashAdaptersTest {

    private static void declare(CircuitBuilder b, String base, int n, boolean pub) {
        for (int i = 0; i < n; i++) { if (pub) b.publicVar(base + "_" + i); else b.secretVar(base + "_" + i); }
    }

    private static void putBytes(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }

    @Test
    void sha512Adapter_matchesJca() throws Exception {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = MessageDigest.getInstance("SHA-512").digest(msg);

        var circuit = CircuitBuilder.create("zk-sha512");
        declare(circuit, "m", msg.length, false);
        declare(circuit, "e", 64, true);
        circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkSha512.hash(zk, ZkBytes.secret(c, "m", msg.length)).assertEqual(ZkBytes.publicInput(c, "e", 64));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "m", msg); putBytes(in, "e", expected);
        assertDoesNotThrow(() -> circuit.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void hmacAdapter_matchesJca() throws Exception {
        byte[] key = new byte[32], msg = new byte[40];
        new Random(1).nextBytes(key); new Random(2).nextBytes(msg);
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        byte[] expected = mac.doFinal(msg);

        var circuit = CircuitBuilder.create("zk-hmac");
        declare(circuit, "k", key.length, false);
        declare(circuit, "m", msg.length, false);
        declare(circuit, "e", 64, true);
        circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkHmacSha512.hmac(zk, ZkBytes.secret(c, "k", key.length), ZkBytes.secret(c, "m", msg.length))
                    .assertEqual(ZkBytes.publicInput(c, "e", 64));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "k", key); putBytes(in, "m", msg); putBytes(in, "e", expected);
        assertDoesNotThrow(() -> circuit.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void blake2b224Adapter_matchesCardanoClient() {
        byte[] msg = new byte[32]; // Ed25519 pubkey shape
        new Random(1852).nextBytes(msg);
        byte[] expected = Blake2bUtil.blake2bHash224(msg);

        var circuit = CircuitBuilder.create("zk-blake2b224");
        declare(circuit, "m", msg.length, false);
        declare(circuit, "e", 28, true);
        circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkBlake2b.hash224(zk, ZkBytes.secret(c, "m", msg.length)).assertEqual(ZkBytes.publicInput(c, "e", 28));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "m", msg); putBytes(in, "e", expected);
        assertDoesNotThrow(() -> circuit.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void sha512Adapter_wrongDigest_fails() throws Exception {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = MessageDigest.getInstance("SHA-512").digest(msg);
        expected[0] ^= 0x01;

        var circuit = CircuitBuilder.create("zk-sha512-neg");
        declare(circuit, "m", msg.length, false);
        declare(circuit, "e", 64, true);
        circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkSha512.hash(zk, ZkBytes.secret(c, "m", msg.length)).assertEqual(ZkBytes.publicInput(c, "e", 64));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "m", msg); putBytes(in, "e", expected);
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(in, CurveId.BN254));
    }
}
