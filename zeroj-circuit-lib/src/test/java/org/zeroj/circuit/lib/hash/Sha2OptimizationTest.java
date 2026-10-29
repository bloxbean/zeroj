package org.zeroj.circuit.lib.hash;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Gate;
import org.zeroj.circuit.Variable;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0063: test the optimized relation independently of honest witness generation. */
class Sha2OptimizationTest {
    @Test
    void majorityTruthTableAndMalformedInputsAcrossFields() {
        for (int width : new int[]{32, 64}) {
            var circuit = CircuitBuilder.create("majority-" + width)
                    .publicVar("out").secretVar("a").secretVar("b").secretVar("c")
                    .define(api -> {
                        Variable[][] words = new Variable[3][width];
                        for (int i = 0; i < 3; i++) {
                            Variable bit = api.var(new String[]{"a", "b", "c"}[i]);
                            api.assertBoolean(bit);
                            Arrays.fill(words[i], bit);
                        }
                        Variable[] output = width == 32
                                ? Sha256.maj(api, words[0], words[1], words[2])
                                : Sha512.maj(api, words[0], words[1], words[2]);
                        api.assertEqual(api.fromBinary(output), api.var("out"));
                    });
            for (CurveId curve : new CurveId[]{CurveId.BLS12_381, CurveId.BN254, CurveId.PALLAS}) {
                var compiled = circuit.compileR1CS(curve);
                for (int triple = 0; triple < 8; triple++) {
                    int a = triple & 1, b = (triple >>> 1) & 1, c = (triple >>> 2) & 1;
                    BigInteger expected = a + b + c >= 2
                            ? BigInteger.ONE.shiftLeft(width).subtract(BigInteger.ONE) : BigInteger.ZERO;
                    var witness = circuit.calculateWitness(Map.of(
                            "a", List.of(BigInteger.valueOf(a)), "b", List.of(BigInteger.valueOf(b)),
                            "c", List.of(BigInteger.valueOf(c)), "out", List.of(expected)), curve);
                    assertTrue(satisfied(compiled.constraints(), witness, compiled.prime()));
                    var wrongOutput = witness.clone();
                    wrongOutput[1] = expected.xor(BigInteger.ONE);
                    assertFalse(satisfied(compiled.constraints(), wrongOutput, compiled.prime()));
                    for (int wire = 2; wire <= 4; wire++) {
                        for (BigInteger badValue : new BigInteger[]{BigInteger.TWO, compiled.prime().subtract(BigInteger.ONE)}) {
                            var bad = witness.clone();
                            bad[wire] = badValue;
                            assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()));
                        }
                    }
                }
            }
        }
    }

    @Test
    void highCarryPatternsMatchJcaAcrossPaddingAndBlockBoundaries() throws Exception {
        for (int width : new int[]{32, 64}) {
            int boundary = width == 32 ? 56 : 112;
            for (int length : new int[]{boundary - 1, boundary, width * 2, width * 4 + 1}) {
                for (int pattern : new int[]{0xff, 0xaa}) {
                    byte[] message = new byte[length];
                    Arrays.fill(message, (byte) pattern);
                    var circuit = circuit(width, length);
                    var compiled = circuit.compileR1CS(CurveId.BLS12_381);
                    var witness = circuit.calculateWitness(inputs(width, message), CurveId.BLS12_381);
                    assertTrue(satisfied(compiled.constraints(), witness, compiled.prime()),
                            "width=" + width + " length=" + length + " pattern=" + pattern);
                }
            }
        }
    }

    @Test
    void deferredRoundSumsConstrainAllCarryBitsAndLowBits() throws Exception {
        for (int width : new int[]{32, 64}) {
            byte[] message = new byte[128];
            Arrays.fill(message, (byte) 0xff);
            var circuit = circuit(width, message.length);
            var compiled = circuit.compileR1CS(CurveId.BLS12_381);
            var witness = circuit.calculateWitness(inputs(width, message), CurveId.BLS12_381);
            assertTrue(satisfied(compiled.constraints(), witness, compiled.prime()));
            // The schedule uses two carry bits and feed-forward one. Three carry bits
            // identify the optimized six/seven-word a/e sums, across every round/block.
            var roundSums = circuit.constraintGraph().gates().stream()
                    .filter(g -> g instanceof Gate.BitDecompose d && d.nBits() == width + 3)
                    .map(g -> (Gate.BitDecompose) g).toList();
            assertEquals(width == 32 ? 3 * 64 * 2 : 2 * 80 * 2, roundSums.size());
            for (int index : new int[]{0, 1, roundSums.size() / 2, roundSums.size() / 2 + 1,
                    roundSums.size() - 2, roundSums.size() - 1}) {
                var sum = roundSums.get(index);
                for (int bit : new int[]{0, width - 1, width, width + 1, width + 2}) {
                    var bad = witness.clone();
                    int wire = sum.outputs()[bit].id();
                    bad[wire] = bad[wire].xor(BigInteger.ONE);
                    assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()),
                            "width=" + width + " sum=" + index + " bit=" + bit);
                }
                for (BigInteger nonBoolean : new BigInteger[]{BigInteger.TWO, compiled.prime().subtract(BigInteger.ONE)}) {
                    var bad = witness.clone();
                    bad[sum.outputs()[width].id()] = nonBoolean;
                    assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()), "non-Boolean carry");
                }
            }
        }
    }

    private static CircuitBuilder circuit(int width, int length) {
        var builder = CircuitBuilder.create("sha2-optimized-" + width + "-" + length);
        for (int i = 0; i < width / 16; i++) builder.publicVar("digest" + i);
        for (int i = 0; i < length; i++) builder.secretVar("byte" + i);
        return builder.define(api -> {
            Variable[] bytes = new Variable[length];
            for (int i = 0; i < length; i++) bytes[i] = api.var("byte" + i);
            var digest = width == 32 ? Sha256.hashBytes(api, bytes) : Sha512.hashBytes(api, bytes);
            for (int i = 0; i < digest.length / 16; i++) {
                Variable packed = api.constant(0);
                for (int j = 0; j < 16; j++) packed = api.add(api.mul(packed, api.constant(256)), digest[i * 16 + j]);
                api.assertEqual(packed, api.var("digest" + i));
            }
        });
    }

    private static Map<String, List<BigInteger>> inputs(int width, byte[] message) throws Exception {
        var input = new HashMap<String, List<BigInteger>>();
        byte[] digest = MessageDigest.getInstance(width == 32 ? "SHA-256" : "SHA-512").digest(message);
        for (int i = 0; i < digest.length / 16; i++)
            input.put("digest" + i, List.of(new BigInteger(1, Arrays.copyOfRange(digest, i * 16, i * 16 + 16))));
        for (int i = 0; i < message.length; i++) input.put("byte" + i, List.of(BigInteger.valueOf(message[i] & 255)));
        return input;
    }

    private static boolean satisfied(List<R1CSConstraint> rows, BigInteger[] witness, BigInteger prime) {
        for (var row : rows)
            if (!evaluate(row.a(), witness, prime).multiply(evaluate(row.b(), witness, prime)).mod(prime)
                    .equals(evaluate(row.c(), witness, prime))) return false;
        return true;
    }

    private static BigInteger evaluate(Map<Integer, BigInteger> terms, BigInteger[] witness, BigInteger prime) {
        BigInteger sum = BigInteger.ZERO;
        for (var term : terms.entrySet()) sum = sum.add(term.getValue().multiply(witness[term.getKey()]));
        return sum.mod(prime);
    }
}
