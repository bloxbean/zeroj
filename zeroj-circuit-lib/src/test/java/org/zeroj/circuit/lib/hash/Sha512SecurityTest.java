package org.zeroj.circuit.lib.hash;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Gate;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.annotation.ZkBytes;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.lib.zk.ZkSha512;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0063: independent expected digests and adversarial compiled-relation checks. */
class Sha512SecurityTest {
    private static final CurveId CURVE = CurveId.BLS12_381;

    @Test
    void publishedNistVectorsSatisfyCompiledConstraints() throws Exception {
        int checked = 0;
        try (var resource = getClass().getResourceAsStream("/standard-vectors/nist-sha2-selected.json")) {
            assertNotNull(resource);
            var vectors = new ObjectMapper().readTree(resource).get("cases");
            for (var vector : vectors) {
                if (!vector.get("algorithm").asText().equals("sha512")) continue;
                byte[] message = HexFormat.of().parseHex(vector.get("message_hex").asText());
                byte[] digest = HexFormat.of().parseHex(vector.get("digest_hex").asText());
                assertEquals(vector.get("length_bytes").asInt(), message.length);
                var circuit = byteCircuit(message.length);
                var relation = circuit.compileR1CS(CURVE);
                var witness = circuit.calculateWitness(byteInputs(message, digest), CURVE);
                assertTrue(satisfied(relation, witness), "NIST SHA-512 length " + message.length);
                checked++;
            }
        }
        assertEquals(13, checked, "all selected official SHA-512 vectors must run");
    }

    @Test
    void bitInterfaceUsesMsbFirstOrderAndEnforcesBooleanInputs() throws Exception {
        byte[] message = {(byte) 0x80, 0, (byte) 0xff};
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);
        var circuit = bitCircuit(message.length * 8);
        var inputs = bitInputs(message, digest);
        var relation = circuit.compileR1CS(CURVE);
        var witness = circuit.calculateWitness(inputs, CURVE);
        assertTrue(satisfied(relation, witness));
        for (BigInteger invalid : List.of(BigInteger.TWO, BigInteger.ONE.negate())) {
            var bad = new HashMap<>(inputs);
            bad.put("m0", List.of(invalid));
            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(bad, CURVE));
            assertMutationRejected(relation, witness, circuit.constraintGraph().secretInputs().getFirst().id(),
                    invalid.mod(relation.prime()));
        }
        // One changed legitimate input bit, with the old digest, must also reject.
        var wrongMessage = new HashMap<>(inputs);
        wrongMessage.put("m0", List.of(BigInteger.ZERO));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(wrongMessage, CURVE));
    }

    @Test
    void bitInterfaceHandlesEmptyAndPaddingBoundaryMessages() throws Exception {
        for (int length : new int[]{0, 111, 112, 128}) {
            byte[] message = new byte[length];
            for (int i = 0; i < length; i++) message[i] = (byte) (255 - i);
            byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);
            var circuit = bitCircuit(length * 8);
            var relation = circuit.compileR1CS(CURVE);
            assertTrue(satisfied(relation, circuit.calculateWitness(bitInputs(message, digest), CURVE)),
                    "bit API length " + length);
        }
    }

    @Test
    void byteInterfaceRejectsOutOfRangeAndWrongMessageInputs() throws Exception {
        byte[] message = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);
        var circuit = byteCircuit(message.length);
        var inputs = byteInputs(message, digest);
        for (int invalid : new int[]{-1, 256, 257}) {
            var bad = new HashMap<>(inputs);
            bad.put("m0", List.of(BigInteger.valueOf(invalid)));
            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(bad, CURVE));
        }
        var wrongMessage = new HashMap<>(inputs);
        wrongMessage.put("m0", List.of(BigInteger.valueOf('b')));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(wrongMessage, CURVE));
    }

    @Test
    void compiledRelationRejectsEveryDigestByteAndMessageByteMutation() throws Exception {
        byte[] message = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);
        var circuit = byteCircuit(message.length);
        var relation = circuit.compileR1CS(CURVE);
        var witness = circuit.calculateWitness(byteInputs(message, digest), CURVE);
        assertTrue(satisfied(relation, witness));
        for (Variable output : circuit.constraintGraph().publicInputs()) {
            assertMutationRejected(relation, witness, output.id(), witness[output.id()].xor(BigInteger.ONE));
        }
        for (Variable input : circuit.constraintGraph().secretInputs()) {
            assertMutationRejected(relation, witness, input.id(), witness[input.id()].xor(BigInteger.ONE));
            assertMutationRejected(relation, witness, input.id(), BigInteger.valueOf(256));
        }
        // Bypass the witness calculator and corrupt the carry in an actual SHA addition.
        Gate.BitDecompose addition = circuit.constraintGraph().gates().stream()
                .filter(g -> g instanceof Gate.BitDecompose d && d.nBits() > 64)
                .map(g -> (Gate.BitDecompose) g).findFirst().orElseThrow();
        int carry = addition.outputs()[addition.nBits() - 1].id();
        assertMutationRejected(relation, witness, carry, witness[carry].xor(BigInteger.ONE));
        int lowBit = addition.outputs()[0].id();
        assertMutationRejected(relation, witness, lowBit, BigInteger.TWO);
    }

    @Test
    void lengthArithmeticRejectsOverflowWithoutLargeAllocations() {
        assertEquals(0, Sha512.messageBitLength(0));
        assertEquals(8, Sha512.messageBitLength(1));
        assertEquals(2_147_483_640, Sha512.messageBitLength(268_435_455));
        assertThrows(IllegalArgumentException.class, () -> Sha512.messageBitLength(-1));
        assertThrows(ArithmeticException.class, () -> Sha512.messageBitLength(268_435_456));
        assertThrows(ArithmeticException.class, () -> Sha512.messageBitLength(Integer.MAX_VALUE));
        assertEquals(1024, Sha512.paddedBitLength(0));
        assertEquals(1024, Sha512.paddedBitLength(111 * 8));
        assertEquals(2048, Sha512.paddedBitLength(112 * 8));
        assertEquals(2048, Sha512.paddedBitLength(128 * 8));
        assertEquals(2_147_482_624, Sha512.paddedBitLength(2_147_482_488));
        assertThrows(ArithmeticException.class, () -> Sha512.paddedBitLength(2_147_482_496));
        assertThrows(ArithmeticException.class, () -> Sha512.paddedBitLength(2_147_483_640));
        for (int invalid : new int[]{-8, -1, 1, 7, 9})
            assertThrows(IllegalArgumentException.class, () -> Sha512.paddedBitLength(invalid));
        for (int invalid : new int[]{1, 7, 9}) {
            assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("sha512-non-byte")
                    .define(api -> Sha512.hashBits(api, new Variable[invalid])));
        }
    }

    @Test
    void symbolicAdapterMatchesJcaOnBls12381AndRejectsWrongDigest() throws Exception {
        byte[] message = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);
        var circuit = CircuitBuilder.create("sha512-symbolic-security");
        for (int i = 0; i < message.length; i++) circuit.secretVar("m_" + i);
        for (int i = 0; i < 64; i++) circuit.publicVar("e_" + i);
        circuit.defineSignals(c -> ZkSha512.hash(new ZkContext(c), ZkBytes.secret(c, "m", message.length))
                .assertEqual(ZkBytes.publicInput(c, "e", 64)));
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        putBytes(inputs, "m_", message);
        putBytes(inputs, "e_", digest);
        var relation = circuit.compileR1CS(CURVE);
        assertTrue(satisfied(relation, circuit.calculateWitness(inputs, CURVE)));
        inputs.put("e_63", List.of(BigInteger.valueOf(digest[63] & 0xff).xor(BigInteger.ONE)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(inputs, CURVE));
    }

    @Test
    void symbolicAdapterRejectsForeignContextAndNullInputs() {
        ZkBytes[] foreign = new ZkBytes[1];
        CircuitBuilder.create("sha512-foreign").secretVar("m_0")
                .defineSignals(c -> foreign[0] = ZkBytes.secret(c, "m", 1));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("sha512-local")
                .secretVar("m_0").defineSignals(c -> ZkSha512.hash(new ZkContext(c), foreign[0])));
        assertThrows(NullPointerException.class, () -> ZkSha512.hash(null, foreign[0]));
        assertThrows(NullPointerException.class, () -> CircuitBuilder.create("sha512-null")
                .defineSignals(c -> ZkSha512.hash(new ZkContext(c), null)));
    }

    private static CircuitBuilder byteCircuit(int length) {
        var circuit = declare(length);
        return circuit.define(api -> {
            Variable[] message = new Variable[length];
            for (int i = 0; i < length; i++) message[i] = api.var("m" + i);
            Variable[] digest = Sha512.hashBytes(api, message);
            assertEquals(64, digest.length);
            for (int i = 0; i < 64; i++) api.assertEqual(digest[i], api.var("e" + i));
        });
    }

    private static CircuitBuilder bitCircuit(int length) {
        var circuit = declare(length);
        return circuit.define(api -> {
            Variable[] message = new Variable[length];
            for (int i = 0; i < length; i++) message[i] = api.var("m" + i);
            Variable[] digest = Sha512.hashBits(api, message);
            assertEquals(512, digest.length);
            for (int i = 0; i < 64; i++) {
                Variable[] littleEndian = new Variable[8];
                for (int bit = 0; bit < 8; bit++) littleEndian[bit] = digest[8 * i + 7 - bit];
                api.assertEqual(api.fromBinary(littleEndian), api.var("e" + i));
            }
        });
    }

    private static CircuitBuilder declare(int inputs) {
        var circuit = CircuitBuilder.create("sha512-security-" + inputs);
        for (int i = 0; i < inputs; i++) circuit.secretVar("m" + i);
        for (int i = 0; i < 64; i++) circuit.publicVar("e" + i);
        return circuit;
    }

    private static Map<String, List<BigInteger>> byteInputs(byte[] message, byte[] digest) {
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        putBytes(inputs, "m", message);
        putBytes(inputs, "e", digest);
        return inputs;
    }

    private static Map<String, List<BigInteger>> bitInputs(byte[] message, byte[] digest) {
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        for (int i = 0; i < message.length; i++) {
            for (int bit = 0; bit < 8; bit++)
                inputs.put("m" + (i * 8 + bit), List.of(BigInteger.valueOf((message[i] >>> (7 - bit)) & 1)));
        }
        putBytes(inputs, "e", digest);
        return inputs;
    }

    private static void putBytes(Map<String, List<BigInteger>> inputs, String prefix, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            inputs.put(prefix + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }

    private static void assertMutationRejected(R1CSConstraintSystem relation, BigInteger[] witness,
                                               int wire, BigInteger replacement) {
        BigInteger[] mutated = witness.clone();
        assertNotEquals(mutated[wire], replacement, "mutation must change wire " + wire);
        mutated[wire] = replacement;
        assertFalse(satisfied(relation, mutated), "compiled relation accepted changed wire " + wire);
    }

    private static boolean satisfied(R1CSConstraintSystem relation, BigInteger[] witness) {
        BigInteger prime = relation.prime();
        for (R1CSConstraint row : relation.constraints()) {
            if (!dot(row.a(), witness).multiply(dot(row.b(), witness)).subtract(dot(row.c(), witness))
                    .mod(prime).equals(BigInteger.ZERO)) return false;
        }
        return true;
    }

    private static BigInteger dot(Map<Integer, BigInteger> terms, BigInteger[] witness) {
        BigInteger sum = BigInteger.ZERO;
        for (var term : terms.entrySet()) sum = sum.add(term.getValue().multiply(witness[term.getKey()]));
        return sum;
    }
}
