package org.zeroj.circuit.lib.hash;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Gate;
import org.zeroj.circuit.Variable;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.*;

class Sha256Test {
    private static final CurveId CURVE = CurveId.BLS12_381;

    @Test
    void publishedKnownAnswers() {
        assertMatches(new byte[0], hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), false, CURVE);
        assertMatches("abc".getBytes(StandardCharsets.US_ASCII),
                hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), false, CURVE);
        assertMatches("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.US_ASCII),
                hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), false, CURVE);
    }

    @Test
    void officialNistCavpVectorsSatisfyCompiledRelation() throws Exception {
        try (var stream = getClass().getResourceAsStream("/standard-vectors/nist-sha2-selected.json")) {
            assertNotNull(stream);
            var fixture = new ObjectMapper().readTree(stream);
            int count = 0;
            for (var vector : fixture.get("cases")) {
                if (!vector.get("algorithm").asText().equals("sha256")) continue;
                byte[] message = hex(vector.get("message_hex").asText());
                assertEquals(vector.get("length_bytes").asInt(), message.length);
                assertMatches(message, hex(vector.get("digest_hex").asText()), false, CURVE);
                count++;
            }
            assertEquals(8, count, "selected original SHA-256 CAVP cases");
        }
    }

    @Test
    void paddingAndMultiBlockDifferential() throws Exception {
        Random random = new Random(1804);
        for (int length : new int[]{1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 257}) {
            byte[] message = new byte[length];
            random.nextBytes(message);
            assertMatches(message, jca(message), false, CURVE);
        }
    }

    @Test
    void bitInterfaceHasStandardMsbFirstOrder() throws Exception {
        for (int length : new int[]{0, 1, 3, 56, 64, 128}) {
            byte[] message = new byte[length];
            new Random(256 + length).nextBytes(message);
            assertMatches(message, jca(message), true, CURVE);
        }
    }

    @Test
    void supportedFieldsGiveSameDigest() throws Exception {
        byte[] message = {(byte) 0x80, (byte) 0xff, 0, 1};
        for (CurveId curve : new CurveId[]{CurveId.BN254, CurveId.PALLAS}) {
            assertMatches(message, jca(message), false, curve);
            assertMatches(message, jca(message), true, curve);
        }
    }

    @Test
    void malformedByteAndBitWitnessesAreRejected() throws Exception {
        byte[] message = {(byte) 0x80};
        for (boolean bitInput : new boolean[]{false, true}) {
            var circuit = circuit(message.length, bitInput);
            var input = inputs(message, jca(message), bitInput);
            var compiled = circuit.compileR1CS(CURVE);
            var valid = circuit.calculateWitness(input, CURVE);
            assertTrue(satisfied(compiled.constraints(), valid, compiled.prime()));
            for (int invalid : bitInput ? new int[]{-1, 2, 255} : new int[]{-1, 256, 257}) {
                var badInputs = new HashMap<>(input);
                badInputs.put("m0", List.of(BigInteger.valueOf(invalid)));
                assertThrows(RuntimeException.class, () -> circuit.calculateWitness(badInputs, CURVE));
                // Bypass the witness generator: the original constraints must reject the value too.
                var bad = valid.clone();
                bad[compiled.numPublicInputs() + 1] = BigInteger.valueOf(invalid).mod(compiled.prime());
                assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()));
            }
        }
    }

    @Test
    void allDigestBytesMessageAndReferencedIntermediatesAreBound() throws Exception {
        byte[] message = "abc".getBytes(StandardCharsets.US_ASCII);
        var circuit = circuit(message.length, false);
        var compiled = circuit.compileR1CS(CURVE);
        var input = inputs(message, jca(message), false);
        var witness = circuit.calculateWitness(input, CURVE);
        assertTrue(satisfied(compiled.constraints(), witness, compiled.prime()));
        assertEquals(32, compiled.numPublicInputs());
        for (int i = 0; i < 32; i++) {
            var bad = witness.clone();
            bad[i + 1] = bad[i + 1].xor(BigInteger.ONE);
            assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()), "digest byte " + i);
        }
        for (int i = 0; i < message.length; i++) {
            var bad = witness.clone();
            bad[33 + i] = bad[33 + i].xor(BigInteger.ONE);
            assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()), "message byte " + i);
        }
        var references = new TreeSet<Integer>();
        for (var row : compiled.constraints()) {
            references.addAll(row.a().keySet());
            references.addAll(row.b().keySet());
            references.addAll(row.c().keySet());
        }
        // The compiler can eliminate temporary wires; only mutate actual relation inputs.
        for (int index : new int[]{references.ceiling(witness.length / 3),
                references.ceiling(2 * witness.length / 3), references.last()}) {
            var bad = witness.clone();
            bad[index] = bad[index].add(BigInteger.ONE).mod(compiled.prime());
            assertFalse(satisfied(compiled.constraints(), bad, compiled.prime()), "internal wire " + index);
        }
        Gate.BitDecompose addition = circuit.constraintGraph().gates().stream()
                .filter(gate -> gate instanceof Gate.BitDecompose bits && bits.nBits() > 32)
                .map(gate -> (Gate.BitDecompose) gate).findFirst().orElseThrow();
        int carry = addition.outputs()[addition.nBits() - 1].id();
        var wrongCarry = witness.clone();
        wrongCarry[carry] = wrongCarry[carry].xor(BigInteger.ONE);
        assertFalse(satisfied(compiled.constraints(), wrongCarry, compiled.prime()), "modular-add carry");
        var nonBooleanSumBit = witness.clone();
        nonBooleanSumBit[addition.outputs()[0].id()] = BigInteger.TWO;
        assertFalse(satisfied(compiled.constraints(), nonBooleanSumBit, compiled.prime()), "modular-add low bit");
        var wrongDigest = new HashMap<>(input);
        wrongDigest.put("d31", List.of(input.get("d31").getFirst().xor(BigInteger.ONE)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(wrongDigest, CURVE));
    }

    @Test
    void lengthValidationFailsBeforeAllocationsOrConstraints() {
        assertEquals(512, Sha256.paddedBitLength(0));
        assertEquals(512, Sha256.paddedBitLength(55 * 8));
        assertEquals(1024, Sha256.paddedBitLength(56 * 8));
        assertEquals(1024, Sha256.paddedBitLength(64 * 8));
        int largestPadded = Integer.MAX_VALUE / 512 * 512;
        assertEquals(largestPadded, Sha256.paddedBitLength(largestPadded - 72));
        assertThrows(ArithmeticException.class, () -> Sha256.paddedBitLength(largestPadded - 64));
        assertThrows(ArithmeticException.class, () -> Sha256.messageBitLength(Integer.MAX_VALUE / 8 + 1));
        assertThrows(IllegalArgumentException.class, () -> Sha256.messageBitLength(-1));
        assertThrows(IllegalArgumentException.class, () -> Sha256.paddedBitLength(-8));
        assertThrows(IllegalArgumentException.class, () -> Sha256.paddedBitLength(7));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("unaligned")
                .define(api -> Sha256.hashBits(api, new Variable[7])));
    }

    @Test
    void rotationsAndShiftsMatchJavaWordOperations() {
        for (int value : new int[]{0, -1, 1, Integer.MIN_VALUE, 0x01234567, 0xdeadbeef}) {
            for (int shift : new int[]{2, 3, 6, 7, 10, 11, 13, 17, 18, 19, 22, 25, 31}) {
                var circuit = CircuitBuilder.create("word-operations").secretVar("word")
                        .publicVar("rotate").publicVar("shift").define(api -> {
                            var bits = api.toBinary(api.var("word"), 32);
                            api.assertEqual(api.fromBinary(Sha256.rotr(bits, shift)), api.var("rotate"));
                            api.assertEqual(api.fromBinary(Sha256.shr(api, bits, shift)), api.var("shift"));
                        });
                assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                        "word", List.of(unsigned(value)),
                        "rotate", List.of(unsigned(Integer.rotateRight(value, shift))),
                        "shift", List.of(unsigned(value >>> shift))), CURVE));
            }
        }
    }

    @Test
    void constraintBudgetIsBoundedWithoutRelaxingTheRelation() {
        for (int length : new int[]{32, 128}) {
            var compiled = circuit(length, false).compileR1CS(CURVE);
            System.out.println("[ADR-0063] SHA-256 bytes=" + length + " constraints="
                    + compiled.numConstraints() + " wires=" + compiled.numWires());
            assertTrue(compiled.numConstraints() > 20_000);
            assertTrue(compiled.numConstraints() < (length == 32 ? 50_000 : 150_000));
        }
    }

    private static CircuitBuilder circuit(int bytes, boolean bitInput) {
        int inputCount = bytes * (bitInput ? 8 : 1);
        var circuit = CircuitBuilder.create("sha256-" + bytes + (bitInput ? "-bits" : "-bytes"));
        for (int i = 0; i < 32; i++) circuit.publicVar("d" + i);
        for (int i = 0; i < inputCount; i++) circuit.secretVar("m" + i);
        return circuit.define(api -> {
            Variable[] message = new Variable[inputCount];
            for (int i = 0; i < inputCount; i++) message[i] = api.var("m" + i);
            Variable[] digest = bitInput ? Sha256.hashBits(api, message) : Sha256.hashBytes(api, message);
            assertEquals(bitInput ? 256 : 32, digest.length);
            for (int i = 0; i < 32; i++) {
                Variable output = digest[i];
                if (bitInput) {
                    Variable[] le = new Variable[8];
                    for (int bit = 0; bit < 8; bit++) le[bit] = digest[i * 8 + 7 - bit];
                    output = api.fromBinary(le);
                }
                api.assertEqual(output, api.var("d" + i));
            }
        });
    }

    private static Map<String, List<BigInteger>> inputs(byte[] message, byte[] expected, boolean bitInput) {
        Map<String, List<BigInteger>> input = new HashMap<>();
        for (int i = 0; i < expected.length; i++) input.put("d" + i, List.of(BigInteger.valueOf(expected[i] & 255)));
        for (int i = 0; i < message.length * (bitInput ? 8 : 1); i++) {
            int value = bitInput ? (message[i / 8] >>> (7 - i % 8)) & 1 : message[i] & 255;
            input.put("m" + i, List.of(BigInteger.valueOf(value)));
        }
        return input;
    }

    private static void assertMatches(byte[] message, byte[] expected, boolean bitInput, CurveId curve) {
        var circuit = circuit(message.length, bitInput);
        var compiled = circuit.compileR1CS(curve);
        var witness = circuit.calculateWitness(inputs(message, expected, bitInput), curve);
        assertTrue(satisfied(compiled.constraints(), witness, compiled.prime()), "message bytes=" + message.length);
        for (int i = 0; i < expected.length; i++) assertEquals(BigInteger.valueOf(expected[i] & 255), witness[i + 1]);
    }

    private static boolean satisfied(List<R1CSConstraint> rows, BigInteger[] witness, BigInteger prime) {
        for (var row : rows)
            if (dot(row.a(), witness, prime).multiply(dot(row.b(), witness, prime))
                    .subtract(dot(row.c(), witness, prime)).mod(prime).signum() != 0) return false;
        return true;
    }

    private static BigInteger dot(Map<Integer, BigInteger> terms, BigInteger[] witness, BigInteger prime) {
        BigInteger sum = BigInteger.ZERO;
        for (var term : terms.entrySet()) sum = sum.add(term.getValue().multiply(witness[term.getKey()]));
        return sum.mod(prime);
    }

    private static byte[] jca(byte[] message) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(message);
    }

    private static byte[] hex(String value) { return HexFormat.of().parseHex(value); }
    private static BigInteger unsigned(int value) { return BigInteger.valueOf(Integer.toUnsignedLong(value)); }
}
