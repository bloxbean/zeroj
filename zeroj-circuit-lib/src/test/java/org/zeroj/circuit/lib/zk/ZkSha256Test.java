package org.zeroj.circuit.lib.zk;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkBytes;
import org.zeroj.circuit.annotation.ZkContext;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ZkSha256Test {
    @Test
    void standardDigestAndInvalidStatement() {
        var builder = CircuitBuilder.create("symbolic-sha256");
        for (int i = 0; i < 32; i++) builder.publicVar("digest_" + i);
        for (int i = 0; i < 3; i++) builder.secretVar("message_" + i);
        var circuit = builder.defineSignals(signals -> {
            var digest = ZkSha256.hash(new ZkContext(signals), ZkBytes.secret(signals, "message", 3));
            assertEquals(32, digest.size());
            digest.assertEqual(ZkBytes.publicInput(signals, "digest", 32));
        });
        Map<String, List<BigInteger>> input = new HashMap<>();
        byte[] expected = HexFormat.of().parseHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        for (int i = 0; i < 32; i++) input.put("digest_" + i, List.of(BigInteger.valueOf(expected[i] & 255)));
        for (int i = 0; i < 3; i++) input.put("message_" + i, List.of(BigInteger.valueOf('a' + i)));
        assertDoesNotThrow(() -> circuit.calculateWitness(input, CurveId.BLS12_381));
        input.put("digest_31", List.of(BigInteger.ZERO));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(input, CurveId.BLS12_381));
    }

    @Test
    void rejectsForeignContextAndNulls() {
        ZkBytes[] foreign = new ZkBytes[1];
        CircuitBuilder.create("foreign").secretVar("message_0")
                .defineSignals(signals -> foreign[0] = ZkBytes.secret(signals, "message", 1));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("local").secretVar("message_0")
                .defineSignals(signals -> ZkSha256.hash(new ZkContext(signals), foreign[0])));
        assertThrows(NullPointerException.class, () -> ZkSha256.hash(null, foreign[0]));
        assertThrows(NullPointerException.class, () -> CircuitBuilder.create("null-message")
                .defineSignals(signals -> ZkSha256.hash(new ZkContext(signals), null)));
    }
}
