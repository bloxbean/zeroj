package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.PublicInputs;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ZkSymbolicTypesTest {

    @Test
    void fieldArithmeticAcceptsValidWitness() {
        var circuit = CircuitBuilder.create("zk-field-mul")
                .publicVar("out")
                .secretVar("a")
                .secretVar("b")
                .defineSignals(c -> {
                    var a = ZkField.secret(c, "a");
                    var b = ZkField.secret(c, "b");
                    var out = ZkField.publicInput(c, "out");

                    a.mul(b).assertEqual(out);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(34)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254));
    }

    @Test
    void boolInputRejectsNonBooleanWitness() {
        var circuit = CircuitBuilder.create("zk-bool")
                .secretVar("flag")
                .defineSignals(c -> ZkBool.secret(c, "flag").assertTrue());

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "flag", List.of(BigInteger.ONE)), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "flag", List.of(BigInteger.TWO)), CurveId.BN254));
    }

    @Test
    void uintComparisonRejectsFalseClaim() {
        var circuit = CircuitBuilder.create("zk-uint-gte")
                .publicVar("ok")
                .secretVar("age")
                .publicVar("threshold")
                .defineSignals(c -> {
                    var ok = ZkBool.publicInput(c, "ok");
                    var age = ZkUInt.secret(c, "age", 8);
                    var threshold = ZkUInt.publicInput(c, "threshold", 8);

                    age.gte(threshold).assertEqual(ok);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "ok", List.of(BigInteger.ONE),
                "age", List.of(BigInteger.valueOf(25)),
                "threshold", List.of(BigInteger.valueOf(18))), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "ok", List.of(BigInteger.ONE),
                "age", List.of(BigInteger.valueOf(15)),
                "threshold", List.of(BigInteger.valueOf(18))), CurveId.BN254));
    }

    @Test
    void uintInputRejectsOutOfRangeWitness() {
        var circuit = CircuitBuilder.create("zk-uint-range")
                .secretVar("value")
                .defineSignals(c -> ZkUInt.secret(c, "value", 8));

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(255))), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(256))), CurveId.BN254));
    }

    @Test
    void uintAdditionExpandsOutputBitWidth() {
        var circuit = CircuitBuilder.create("zk-uint-add")
                .publicVar("out")
                .secretVar("a")
                .secretVar("b")
                .defineSignals(c -> {
                    var a = ZkUInt.secret(c, "a", 8);
                    var b = ZkUInt.secret(c, "b", 8);
                    var out = ZkUInt.publicInput(c, "out", 9);
                    var sum = a.add(b);

                    if (sum.bits() != 9) {
                        throw new IllegalStateException("8-bit + 8-bit must produce a 9-bit ZkUInt");
                    }
                    sum.assertEqual(out);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(300)),
                "a", List.of(BigInteger.valueOf(200)),
                "b", List.of(BigInteger.valueOf(100))), CurveId.BN254));
    }

    @Test
    void uintSubtractionRejectsUnderflowByDefault() {
        var circuit = CircuitBuilder.create("zk-uint-sub-underflow")
                .secretVar("a")
                .secretVar("b")
                .defineSignals(c -> ZkUInt.secret(c, "a", 8).sub(ZkUInt.secret(c, "b", 8)));

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(10)),
                "b", List.of(BigInteger.valueOf(5))), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(5)),
                "b", List.of(BigInteger.valueOf(10))), CurveId.BN254));
    }

    @Test
    void symbolicRangeCircuitMatchesSignalCircuitBehavior() {
        var symbolic = CircuitBuilder.create("zk-symbolic-range")
                .publicVar("threshold")
                .secretVar("age")
                .defineSignals(c -> {
                    var age = ZkUInt.secret(c, "age", 8);
                    var threshold = ZkUInt.publicInput(c, "threshold", 8);
                    age.gte(threshold).assertTrue();
                });

        var signal = CircuitBuilder.create("zk-signal-range")
                .publicVar("threshold")
                .secretVar("age")
                .defineSignals(c -> {
                    Signal age = c.privateInput("age");
                    Signal threshold = c.publicInput("threshold");
                    age.assertInRange(8);
                    threshold.assertInRange(8);
                    c.assertEqual(age.lessThan(threshold, 8).not(), c.constant(1));
                });

        assertEquals(signal.constraintGraph().gates().size(), symbolic.constraintGraph().gates().size());

        var valid = Map.of(
                "threshold", List.of(BigInteger.valueOf(18)),
                "age", List.of(BigInteger.valueOf(25)));
        assertDoesNotThrow(() -> symbolic.calculateWitness(valid, CurveId.BN254));
        assertDoesNotThrow(() -> signal.calculateWitness(valid, CurveId.BN254));

        var invalid = Map.of(
                "threshold", List.of(BigInteger.valueOf(18)),
                "age", List.of(BigInteger.valueOf(15)));
        assertThrows(ArithmeticException.class, () -> symbolic.calculateWitness(invalid, CurveId.BN254));
        assertThrows(ArithmeticException.class, () -> signal.calculateWitness(invalid, CurveId.BN254));
    }

    @Test
    void arrayFlattensSignalsAndSupportsFactories() {
        var circuit = CircuitBuilder.create("zk-array")
                .publicVar("out")
                .secretVar("item_0")
                .secretVar("item_1")
                .defineSignals(c -> {
                    var items = ZkArray.secretFields(c, "item", 2);
                    var out = ZkField.publicInput(c, "out");

                    items.get(0).add(items.get(1)).assertEqual(out);
                    if (items.signals().size() != 2) {
                        throw new IllegalStateException("array should flatten to two signals");
                    }
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(30)),
                "item_0", List.of(BigInteger.TEN),
                "item_1", List.of(BigInteger.valueOf(20))), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(31)),
                "item_0", List.of(BigInteger.TEN),
                "item_1", List.of(BigInteger.valueOf(20))), CurveId.BN254));
    }

    @Test
    void merkleShapedInputsSupportFieldSiblingsAndBooleanPathBits() {
        var circuit = CircuitBuilder.create("zk-merkle-shape")
                .publicVar("root")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("sibling_1")
                .secretVar("pathBit_0")
                .secretVar("pathBit_1")
                .defineSignals(c -> {
                    var root = ZkField.publicInput(c, "root");
                    var current = ZkField.secret(c, "leaf");
                    var siblings = ZkArray.secretFields(c, "sibling", 2);
                    var pathBits = ZkArray.secretBools(c, "pathBit", 2);
                    var factor = ZkField.wrap(c, c.constant(31));

                    for (int i = 0; i < siblings.size(); i++) {
                        var left = pathBits.get(i).select(siblings.get(i), current);
                        var right = pathBits.get(i).select(current, siblings.get(i));
                        current = left.mul(factor).add(right);
                    }
                    current.assertEqual(root);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "root", List.of(BigInteger.valueOf(503)),
                "leaf", List.of(BigInteger.valueOf(5)),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "sibling_1", List.of(BigInteger.valueOf(11)),
                "pathBit_0", List.of(BigInteger.ZERO),
                "pathBit_1", List.of(BigInteger.ONE)), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "root", List.of(BigInteger.valueOf(503)),
                "leaf", List.of(BigInteger.valueOf(5)),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "sibling_1", List.of(BigInteger.valueOf(11)),
                "pathBit_0", List.of(BigInteger.TWO),
                "pathBit_1", List.of(BigInteger.ONE)), CurveId.BN254));
    }

    @Test
    void bitsInputRejectsNonBooleanWitnessAndSupportsEquality() {
        var circuit = CircuitBuilder.create("zk-bits")
                .secretVar("message_0")
                .secretVar("message_1")
                .publicVar("expected_0")
                .publicVar("expected_1")
                .defineSignals(c -> {
                    var message = ZkBits.secret(c, "message", 2);
                    var expected = ZkBits.publicInput(c, "expected", 2);
                    message.assertEqual(expected);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "message_0", List.of(BigInteger.ONE),
                "message_1", List.of(BigInteger.ZERO),
                "expected_0", List.of(BigInteger.ONE),
                "expected_1", List.of(BigInteger.ZERO)), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "message_0", List.of(BigInteger.TWO),
                "message_1", List.of(BigInteger.ZERO),
                "expected_0", List.of(BigInteger.ONE),
                "expected_1", List.of(BigInteger.ZERO)), CurveId.BN254));
    }

    @Test
    void bytesInputRejectsOutOfRangeWitnessAndSupportsEquality() {
        var circuit = CircuitBuilder.create("zk-bytes")
                .secretVar("message_0")
                .secretVar("message_1")
                .publicVar("expected_0")
                .publicVar("expected_1")
                .defineSignals(c -> {
                    var message = ZkBytes.secret(c, "message", 2);
                    var expected = ZkBytes.publicInput(c, "expected", 2);
                    message.assertEqual(expected);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "message_0", List.of(BigInteger.valueOf(255)),
                "message_1", List.of(BigInteger.ZERO),
                "expected_0", List.of(BigInteger.valueOf(255)),
                "expected_1", List.of(BigInteger.ZERO)), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "message_0", List.of(BigInteger.valueOf(256)),
                "message_1", List.of(BigInteger.ZERO),
                "expected_0", List.of(BigInteger.valueOf(255)),
                "expected_1", List.of(BigInteger.ZERO)), CurveId.BN254));
    }

    @Test
    void bytesConstructorRejectsNonByteUIntValues() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-bytes-width")
                .secretVar("message_0")
                .defineSignals(c -> new ZkBytes(List.of(ZkUInt.secret(c, "message_0", 16)))));
    }

    @Test
    void schemaRejectsInvalidBitAndByteMetadata() {
        assertThrows(IllegalArgumentException.class, () -> ZkCircuitSchema.Input.scalar(
                "flag", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.BOOL, 0));
        assertThrows(IllegalArgumentException.class, () -> ZkCircuitSchema.Input.scalar(
                "bits", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.BITS, 1));
        assertThrows(IllegalArgumentException.class, () -> ZkCircuitSchema.Input.array(
                "bytes", ZkCircuitSchema.Visibility.SECRET, ZkCircuitSchema.Kind.BYTES, 16, 2));
    }

    @Test
    void schemaExposesStableNamesAndInputMapPublicValues() {
        var schema = ZkCircuitSchema.of(
                "schema-test",
                List.of(new ZkCircuitSchema.Parameter("depth", "int", "2")),
                List.of(
                        ZkCircuitSchema.Input.scalar(
                                "root", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.FIELD, -1),
                        ZkCircuitSchema.Input.array(
                                "pathBit", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.BOOL, 1, 2)),
                List.of(ZkCircuitSchema.Input.array(
                        "sibling", ZkCircuitSchema.Visibility.SECRET, ZkCircuitSchema.Kind.FIELD, -1, 2)));

        assertEquals("schema-test", schema.name());
        assertEquals(List.of("root", "pathBit_0", "pathBit_1"), schema.publicInputs().names());
        assertEquals(List.of("sibling_0", "sibling_1"), schema.secretInputs().names());
        assertEquals(2, schema.input("sibling").size());
        assertEquals(ZkCircuitSchema.Kind.FIELD, schema.input("sibling_0").kind());
        assertEquals("2", schema.parameters().getFirst().value());

        var inputs = new ZkInputMap()
                .put("root", BigInteger.valueOf(10))
                .putArray("pathBit", List.of(BigInteger.ZERO, BigInteger.ONE))
                .putArray("sibling", List.of(BigInteger.valueOf(20), BigInteger.valueOf(30)));

        assertEquals(List.of(BigInteger.valueOf(10), BigInteger.ZERO, BigInteger.ONE),
                inputs.publicValues(schema));
        assertEquals(new PublicInputs(List.of(BigInteger.valueOf(10), BigInteger.ZERO, BigInteger.ONE)),
                inputs.publicInputs(schema));
        assertEquals(BigInteger.valueOf(30), inputs.toWitnessMap().get("sibling_1").getFirst());
    }

    @Test
    void circuitMetadataBuildsEnvelopeMetadataAndBuilder() {
        var schema = ZkCircuitSchema.of(
                "metadata-test-d2",
                List.of(new ZkCircuitSchema.Parameter("depth", "int", "2")),
                List.of(ZkCircuitSchema.Input.scalar(
                        "root", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.FIELD, -1)),
                List.of());

        var metadata = ZkCircuitMetadata.of(schema, 1);
        assertEquals("metadata-test-d2", metadata.circuitId().value());
        assertEquals("2", metadata.parameters().get("depth"));
        assertEquals("metadata-test-d2",
                metadata.envelopeMetadata().get(ZkCircuitMetadata.CIRCUIT_NAME_KEY));
        assertEquals("1",
                metadata.envelopeMetadata().get(ZkCircuitMetadata.CIRCUIT_VERSION_KEY));
        assertEquals("2",
                metadata.envelopeMetadata().get(ZkCircuitMetadata.CIRCUIT_PARAM_PREFIX + "depth"));

        var publicInputs = new PublicInputs(List.of(BigInteger.valueOf(99)));
        var envelope = metadata.proofEnvelopeBuilder(
                        ProofSystemId.GROTH16,
                        CurveId.BN254,
                        new byte[]{1, 2, 3},
                        publicInputs,
                        new VerificationKeyRef.ById("vk-metadata-test"))
                .build();

        assertEquals(metadata.circuitId(), envelope.circuitId());
        assertEquals(publicInputs, envelope.publicInputs());
        assertEquals("1", envelope.metadata().get(ZkCircuitMetadata.CIRCUIT_VERSION_KEY));
    }

    @Test
    void schemaLookupPrefersExactInputNamesBeforeFlattenedNames() {
        var schema = ZkCircuitSchema.of(
                "schema-overlap",
                List.of(),
                List.of(
                        ZkCircuitSchema.Input.array(
                                "a", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.FIELD, -1, 2),
                        ZkCircuitSchema.Input.array(
                                "a_0", ZkCircuitSchema.Visibility.PUBLIC, ZkCircuitSchema.Kind.FIELD, -1, 1)),
                List.of());

        assertEquals("a_0", schema.input("a_0").name());
        assertEquals(List.of("a_0_0"), schema.input("a_0").signalNames());
    }

    @Test
    void symbolicCircuitCompilesToAllBackends() {
        var circuit = CircuitBuilder.create("zk-compile")
                .publicVar("ok")
                .secretVar("value")
                .defineSignals(c -> {
                    var ok = ZkBool.publicInput(c, "ok");
                    var value = ZkUInt.secret(c, "value", 8);
                    value.gte(ZkUInt.wrap(c, c.constant(100), 8)).assertEqual(ok);
                });

        assertNotNull(circuit.compileR1CS(CurveId.BN254));
        assertNotNull(circuit.compilePlonK(CurveId.BN254));
        assertNotNull(circuit.compileHalo2(CurveId.BN254));
    }

    @Test
    void visibilityFactoriesRejectMismatchedDeclarations() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-public-as-secret")
                .secretVar("x")
                .defineSignals(c -> ZkField.publicInput(c, "x")));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-secret-as-public")
                .publicVar("x")
                .defineSignals(c -> ZkField.secret(c, "x")));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-array-visibility")
                .publicVar("item_0")
                .defineSignals(c -> ZkArray.secretFields(c, "item", 1)));
    }

    @Test
    void wrappingRejectsSignalsFromOtherBuilders() {
        Signal[] signalFromOtherBuilder = new Signal[1];
        CircuitBuilder.create("zk-other-builder")
                .secretVar("other")
                .defineSignals(c -> signalFromOtherBuilder[0] = c.privateInput("other"));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-wrong-context")
                .secretVar("local")
                .defineSignals(c -> ZkField.wrap(new ZkContext(c), signalFromOtherBuilder[0])));
    }

    @Test
    void apiGuardrailsRejectInvalidShapeParameters() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-invalid-width")
                .secretVar("value")
                .defineSignals(c -> ZkUInt.secret(c, "value", 0)));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-invalid-array")
                .defineSignals(c -> ZkArray.secretFields(c, "item", -1)));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-max-width-comparison")
                .secretVar("a")
                .secretVar("b")
                .defineSignals(c -> ZkUInt.secret(c, "a", ZkUInt.MAX_BITS)
                        .lt(ZkUInt.secret(c, "b", ZkUInt.MAX_BITS))));
    }
}
