package org.zeroj.merkle.mpf.poseidon.circuit;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkInputMap;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0068: Enforces canonical BLS12-381 scalar (< Fr) key-path constraints in ZkMpf circuits.
 */
class ZkMpfCanonicalKeyPathAndForkTest {

    @Test
    void keyPathCommitmentRejectsNonCanonicalPathsAndAcceptsExactFrMinusOne() {
        var builder = CircuitBuilder.create("mpf-keypath-canonical")
                .publicVar("commitment");
        for (int i = 0; i < ZkMpf.KEY_PATH_NIBBLES; i++) {
            builder.secretVar("key_" + i);
        }
        CircuitBuilder circuit = builder.defineSignals(c -> {
            var zk = new ZkContext(c);
            var keyPath = ZkArray.secretUInts(c, "key", ZkMpf.KEY_PATH_NIBBLES, 4);
            var expected = ZkField.publicInput(c, "commitment");
            ZkMpf.keyPathCommitment(zk, PoseidonParamsBLS12_381T3.INSTANCE, keyPath).assertEqual(expected);
        });
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        BigInteger fr = FieldConfig.BLS12_381.prime();

        // Exact canonical boundary: Fr - 1 must pass
        int[] maxCanonical = toNibbles(fr.subtract(BigInteger.ONE));
        BigInteger maxCommitment = PoseidonMpfHash.keyPathCommitment(PoseidonParamsBLS12_381T3.INSTANCE, maxCanonical);
        var validInputs = new ZkInputMap()
                .put("commitment", maxCommitment)
                .putArray("key", toBigInts(maxCanonical));
        BigInteger[] validWitness = assertDoesNotThrow(
                () -> circuit.calculateWitness(validInputs.toWitnessMap(), CurveId.BLS12_381));
        assertDoesNotThrow(() -> r1cs.verifyWitness(validWitness));

        // Exact modulus Fr must be rejected in-circuit
        int[] exactFr = toNibbles(fr);
        BigInteger frCommitment = PoseidonMpfHash.keyPathCommitment(PoseidonParamsBLS12_381T3.INSTANCE, exactFr);
        var exactFrInputs = new ZkInputMap()
                .put("commitment", frCommitment)
                .putArray("key", toBigInts(exactFr));
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(exactFrInputs.toWitnessMap(), CurveId.BLS12_381));

        // 64 x 0xF (all 15s, > Fr) must be rejected in-circuit
        int[] allFs = new int[ZkMpf.KEY_PATH_NIBBLES];
        Arrays.fill(allFs, 15);
        BigInteger allFsCommitment = PoseidonMpfHash.keyPathCommitment(PoseidonParamsBLS12_381T3.INSTANCE, allFs);
        var allFsInputs = new ZkInputMap()
                .put("commitment", allFsCommitment)
                .putArray("key", Collections.nCopies(ZkMpf.KEY_PATH_NIBBLES, BigInteger.valueOf(15)));
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(allFsInputs.toWitnessMap(), CurveId.BLS12_381));
    }

    private static int[] toNibbles(BigInteger value) {
        String hex = value.toString(16);
        hex = "0".repeat(ZkMpf.KEY_PATH_NIBBLES - hex.length()) + hex;
        int[] out = new int[ZkMpf.KEY_PATH_NIBBLES];
        for (int i = 0; i < out.length; i++) {
            out[i] = Character.digit(hex.charAt(i), 16);
        }
        return out;
    }

    private static List<BigInteger> toBigInts(int[] values) {
        var out = new ArrayList<BigInteger>(values.length);
        for (int v : values) out.add(BigInteger.valueOf(v));
        return out;
    }
}
