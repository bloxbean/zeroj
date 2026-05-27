package com.bloxbean.cardano.zeroj.circuit.annotation.processor;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.PublicInputs;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkCircuitMetadata;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkCircuitSchema;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBN254T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.annotation.processing.Processor;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CircuitAnnotationProcessorTest {

    @TempDir
    Path tempDir;

    @Test
    void processorIsServiceRegistered() {
        var processors = ServiceLoader.load(Processor.class);
        assertTrue(processors.stream()
                        .map(ServiceLoader.Provider::type)
                        .anyMatch(CircuitAnnotationProcessor.class::equals),
                "CircuitAnnotationProcessor should be discoverable via ServiceLoader");
    }

    @Test
    void fieldStyleRangeProofGeneratesBuildAndRejectsInvalidWitness() throws Exception {
        var compilation = compile("test.RangeProof", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "range-proof", version = 2)
                public class RangeProof {
                    @Secret @UInt(bits = 8)
                    ZkUInt secret;

                    @Public @UInt(bits = 8)
                    ZkUInt lo;

                    @Public @UInt(bits = 8)
                    ZkUInt hi;

                    @Prove
                    ZkBool inRange() {
                        return secret.gte(lo).and(secret.lte(hi));
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        assertTrue(compilation.generatedSource("test/RangeProofCircuit.java")
                .contains("public static final String SECRET = \"secret\";"));

        Class<?> companion = compilation.load("test.RangeProofCircuit");
        assertEquals("range-proof", companion.getField("CIRCUIT_NAME").get(null));
        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build").invoke(null);
        ZkCircuitSchema schema = (ZkCircuitSchema) companion.getMethod("schema").invoke(null);
        assertEquals("range-proof", schema.name());
        assertEquals(List.of("lo", "hi"), schema.publicInputs().names());
        assertEquals(List.of("secret"), schema.secretInputs().names());
        assertEquals(8, schema.input("secret").bits());

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "secret", List.of(BigInteger.valueOf(42)),
                "lo", List.of(BigInteger.valueOf(18)),
                "hi", List.of(BigInteger.valueOf(99))), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "secret", List.of(BigInteger.valueOf(7)),
                "lo", List.of(BigInteger.valueOf(18)),
                "hi", List.of(BigInteger.valueOf(99))), CurveId.BN254));

        Object inputs = companion.getMethod("inputs").invoke(null);
        inputs.getClass().getMethod("secret", BigInteger.class).invoke(inputs, BigInteger.valueOf(42));
        inputs.getClass().getMethod("lo", long.class).invoke(inputs, 18L);
        inputs.getClass().getMethod("hi", BigInteger.class).invoke(inputs, BigInteger.valueOf(99));
        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> witnessMap =
                (Map<String, List<BigInteger>>) inputs.getClass().getMethod("toWitnessMap").invoke(inputs);
        assertDoesNotThrow(() -> circuit.calculateWitness(witnessMap, CurveId.BN254));
        assertEquals(List.of(BigInteger.valueOf(18), BigInteger.valueOf(99)),
                inputs.getClass().getMethod("publicValues").invoke(inputs));
        var typedPublicInputs = new PublicInputs(List.of(BigInteger.valueOf(18), BigInteger.valueOf(99)));
        assertEquals(typedPublicInputs, inputs.getClass().getMethod("toPublicInputs").invoke(inputs));
        assertEquals(typedPublicInputs,
                companion.getMethod("publicInputValues", inputs.getClass()).invoke(null, inputs));
        BigInteger[] generatedWitness = (BigInteger[]) companion
                .getMethod("calculateWitness", CircuitBuilder.class, inputs.getClass(), CurveId.class)
                .invoke(null, circuit, inputs, CurveId.BN254);
        assertTrue(generatedWitness.length > 0);

        assertEquals(2, companion.getField("CIRCUIT_VERSION").get(null));
        assertEquals(new CircuitId("range-proof"), companion.getMethod("circuitId").invoke(null));
        ZkCircuitMetadata metadata = (ZkCircuitMetadata) companion.getMethod("metadata").invoke(null);
        assertEquals(new CircuitId("range-proof"), metadata.circuitId());
        assertEquals("2", metadata.envelopeMetadata().get(ZkCircuitMetadata.CIRCUIT_VERSION_KEY));
        ZkProofEnvelope envelope = ((ZkProofEnvelope.Builder) companion
                .getMethod("proofEnvelopeBuilder",
                        CircuitBuilder.class,
                        ProofSystemId.class,
                        CurveId.class,
                        byte[].class,
                        inputs.getClass(),
                        VerificationKeyRef.class)
                .invoke(null,
                        circuit,
                        ProofSystemId.GROTH16,
                        CurveId.BN254,
                        new byte[]{1, 2, 3},
                        inputs,
                        new VerificationKeyRef.ById("vk-range-proof")))
                .build();
        assertEquals(new CircuitId("range-proof"), envelope.circuitId());
        assertEquals(typedPublicInputs, envelope.publicInputs());
        assertEquals("range-proof", envelope.metadata().get(ZkCircuitMetadata.CIRCUIT_NAME_KEY));
        assertEquals("2", envelope.metadata().get(ZkCircuitMetadata.CIRCUIT_VERSION_KEY));
    }

    @Test
    void rejectsInvalidCircuitVersion() throws Exception {
        var compilation = compile("test.BadVersion", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(version = 0)
                public class BadVersion {
                    @Prove
                    ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText().contains("@ZKCircuit version must be positive"));
    }

    @Test
    void parameterStyleRangeProofGeneratesBuild() throws Exception {
        var compilation = compile("test.AgeProof", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "age-proof")
                public class AgeProof {
                    @Prove
                    ZkBool prove(
                            @Secret @UInt(bits = 8) ZkUInt age,
                            @Public @UInt(bits = 8) ZkUInt threshold) {
                        return age.gte(threshold);
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        CircuitBuilder circuit = (CircuitBuilder) compilation.load("test.AgeProofCircuit")
                .getMethod("build")
                .invoke(null);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "age", List.of(BigInteger.valueOf(25)),
                "threshold", List.of(BigInteger.valueOf(18))), CurveId.BN254));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "age", List.of(BigInteger.valueOf(15)),
                "threshold", List.of(BigInteger.valueOf(18))), CurveId.BN254));
    }

    @Test
    void bitAndByteInputsGenerateSchemaBuildersAndConstraints() throws Exception {
        var compilation = compile("test.MessageProof", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "message-proof")
                public class MessageProof {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(2) ZkBytes message,
                            @Public @FixedSize(2) ZkBytes expected,
                            @Secret @FixedSize(3) ZkBits flags,
                            @Public ZkBool accepted) {
                        return message.isEqual(expected)
                                .and(flags.get(0))
                                .and(flags.get(1).not())
                                .and(flags.get(2))
                                .and(accepted);
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Class<?> companion = compilation.load("test.MessageProofCircuit");
        ZkCircuitSchema schema = (ZkCircuitSchema) companion.getMethod("schema").invoke(null);
        assertEquals(ZkCircuitSchema.Kind.BYTES, schema.input("message").kind());
        assertEquals(8, schema.input("message").bits());
        assertEquals(ZkCircuitSchema.Kind.BITS, schema.input("flags").kind());
        assertEquals(1, schema.input("flags").bits());
        assertEquals(List.of("expected_0", "expected_1", "accepted"), schema.publicInputs().names());
        assertEquals(List.of("message_0", "message_1", "flags_0", "flags_1", "flags_2"),
                schema.secretInputs().names());

        Object inputs = companion.getMethod("inputs").invoke(null);
        inputs.getClass().getMethod("message", List.class)
                .invoke(inputs, List.of(BigInteger.valueOf(1), BigInteger.valueOf(255)));
        inputs.getClass().getMethod("expected", List.class)
                .invoke(inputs, List.of(BigInteger.valueOf(1), BigInteger.valueOf(255)));
        inputs.getClass().getMethod("flags", List.class)
                .invoke(inputs, List.of(BigInteger.ONE, BigInteger.ZERO, BigInteger.ONE));
        inputs.getClass().getMethod("accepted", long.class).invoke(inputs, 1L);

        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build").invoke(null);
        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> witness =
                (Map<String, List<BigInteger>>) inputs.getClass().getMethod("toWitnessMap").invoke(inputs);
        assertDoesNotThrow(() -> circuit.calculateWitness(witness, CurveId.BN254));

        var invalidByte = Map.of(
                "message_0", List.of(BigInteger.valueOf(256)),
                "message_1", List.of(BigInteger.valueOf(255)),
                "expected_0", List.of(BigInteger.ONE),
                "expected_1", List.of(BigInteger.valueOf(255)),
                "flags_0", List.of(BigInteger.ONE),
                "flags_1", List.of(BigInteger.ZERO),
                "flags_2", List.of(BigInteger.ONE),
                "accepted", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(invalidByte, CurveId.BN254));

        var invalidBit = Map.of(
                "message_0", List.of(BigInteger.ONE),
                "message_1", List.of(BigInteger.valueOf(255)),
                "expected_0", List.of(BigInteger.ONE),
                "expected_1", List.of(BigInteger.valueOf(255)),
                "flags_0", List.of(BigInteger.TWO),
                "flags_1", List.of(BigInteger.ZERO),
                "flags_2", List.of(BigInteger.ONE),
                "accepted", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(invalidBit, CurveId.BN254));
    }

    @Test
    void rejectsInvalidBitAndByteFixedSizeDeclarations() throws Exception {
        var missingBitsSize = compile("test.MissingBitsSize", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class MissingBitsSize {
                    @Prove
                    ZkBool prove(@Secret ZkBits flags, @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(missingBitsSize.success());
        assertTrue(missingBitsSize.diagnosticsText().contains("ZkBits symbolic inputs require @FixedSize"));

        var invalidByteSize = compile("test.InvalidByteSize", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class InvalidByteSize {
                    @Prove
                    ZkBool prove(@Secret @FixedSize(0) ZkBytes message, @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(invalidByteSize.success());
        assertTrue(invalidByteSize.diagnosticsText().contains("@FixedSize value must be positive"));

        var invalidScalarSize = compile("test.InvalidScalarSize", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class InvalidScalarSize {
                    @Prove
                    ZkBool prove(@Secret @FixedSize(1) ZkBool flag) {
                        return flag;
                    }
                }
                """);
        assertFalse(invalidScalarSize.success());
        assertTrue(invalidScalarSize.diagnosticsText()
                .contains("@FixedSize can only be used with ZkArray, ZkBits, or ZkBytes"));
    }

    @Test
    void parameterStyleInputNamesDoNotCollideWithGeneratedLocals() throws Exception {
        var compilation = compile("test.ReservedNames", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "reserved-names")
                public class ReservedNames {
                    public ReservedNames(@CircuitParam("depth") int __zerojBuilder) {}

                    @Prove
                    ZkBool prove(
                            @Public ZkBool c,
                            @Secret ZkBool zk,
                            @Secret ZkBool builder,
                            @Secret ZkBool instance) {
                        return c.and(zk).and(builder).and(instance);
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        CircuitBuilder circuit = (CircuitBuilder) compilation.load("test.ReservedNamesCircuit")
                .getMethod("build", int.class)
                .invoke(null, 4);
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.ONE),
                "zk", List.of(BigInteger.ONE),
                "builder", List.of(BigInteger.ONE),
                "instance", List.of(BigInteger.ONE)), CurveId.BN254));
    }

    @Test
    void scalarInputNamedWaitDoesNotGenerateFinalObjectWaitOverride() throws Exception {
        var compilation = compile("test.WaitInput", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "wait-input")
                public class WaitInput {
                    @Prove
                    ZkBool prove(@Public ZkBool wait) {
                        return wait;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        String generated = compilation.generatedSource("test/WaitInputCircuit.java");
        assertTrue(generated.contains("public Inputs wait(BigInteger value)"));
        assertFalse(generated.contains("public Inputs wait(long value)"));

        Class<?> companion = compilation.load("test.WaitInputCircuit");
        Object inputs = companion.getMethod("inputs").invoke(null);
        inputs.getClass().getMethod("wait", BigInteger.class).invoke(inputs, BigInteger.ONE);
        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build").invoke(null);
        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> witness =
                (Map<String, List<BigInteger>>) inputs.getClass().getMethod("toWitnessMap").invoke(inputs);
        assertDoesNotThrow(() -> circuit.calculateWitness(witness, CurveId.BN254));
    }

    @Test
    void parameterizedMerkleMembershipGeneratesBuildWithCircuitParams() throws Exception {
        var compilation = compile("test.MerkleMembership", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;
                import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;

                @ZKCircuit(name = "membership", nameTemplate = "membership-d{depth}-{hashType}")
                public class MerkleMembership {
                    private final int depth;
                    private final ZkMerkle.HashType hashType;

                    public MerkleMembership(
                            @CircuitParam("depth") int depth,
                            @CircuitParam("hashType") ZkMerkle.HashType hashType) {
                        this.depth = depth;
                        this.hashType = hashType;
                    }

                    @Prove
                    ZkBool prove(
                            ZkContext zk,
                            @Secret ZkField leaf,
                            @Public ZkField root,
                            @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                            @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {
                        return ZkMerkle.isMember(zk, leaf, root, siblings, pathBits, hashType);
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Class<?> companion = compilation.load("test.MerkleMembershipCircuit");
        CircuitBuilder circuit = (CircuitBuilder) companion
                .getMethod("build", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.POSEIDON);
        String circuitName = "membership-d1-POSEIDON--depth-1:1--hashType-8:POSEIDON";
        assertEquals(circuitName, circuit.constraintGraph().name());
        ZkCircuitSchema schema = (ZkCircuitSchema) companion
                .getMethod("schema", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.POSEIDON);
        assertEquals(circuitName, schema.name());
        assertEquals("depth", schema.parameters().get(0).name());
        assertEquals("1:1", schema.parameters().get(0).value());
        assertEquals("8:POSEIDON", schema.parameters().get(1).value());
        assertEquals(new CircuitId(circuitName), companion
                .getMethod("circuitId", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.POSEIDON));
        ZkCircuitMetadata metadata = (ZkCircuitMetadata) companion
                .getMethod("metadata", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.POSEIDON);
        assertEquals("1:1", metadata.parameters().get("depth"));
        assertEquals("8:POSEIDON", metadata.parameters().get("hashType"));
        assertEquals(List.of("root"), schema.publicInputs().names());
        assertEquals(List.of("leaf", "sibling_0", "pathBit_0"), schema.secretInputs().names());
        assertEquals(1, schema.input("sibling").size());
        assertTrue(schema.input("pathBit_0").array());

        BigInteger root = PoseidonHash.hash(
                PoseidonParamsBN254T3.INSTANCE,
                BigInteger.valueOf(5),
                BigInteger.valueOf(7));
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "leaf", List.of(BigInteger.valueOf(5)),
                "root", List.of(root),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "pathBit_0", List.of(BigInteger.ZERO)), CurveId.BN254));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "leaf", List.of(BigInteger.valueOf(5)),
                "root", List.of(BigInteger.ONE),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "pathBit_0", List.of(BigInteger.ZERO)), CurveId.BN254));

        Object inputs = companion
                .getMethod("inputs", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.POSEIDON);
        inputs.getClass().getMethod("leaf", BigInteger.class).invoke(inputs, BigInteger.valueOf(5));
        inputs.getClass().getMethod("root", BigInteger.class).invoke(inputs, root);
        inputs.getClass().getMethod("siblings", List.class).invoke(inputs, List.of(BigInteger.valueOf(7)));
        inputs.getClass().getMethod("pathBits", int.class, long.class).invoke(inputs, 0, 0L);
        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> generatedWitness =
                (Map<String, List<BigInteger>>) inputs.getClass().getMethod("toWitnessMap").invoke(inputs);
        assertDoesNotThrow(() -> circuit.calculateWitness(generatedWitness, CurveId.BN254));
        assertEquals(List.of(root), companion.getMethod("publicInputs", inputs.getClass()).invoke(null, inputs));

        CircuitBuilder mismatchedCircuit = (CircuitBuilder) companion
                .getMethod("build", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.MIMC);
        var mismatchedWitness = assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> companion.getMethod("calculateWitness", CircuitBuilder.class, inputs.getClass(), CurveId.class)
                        .invoke(null, mismatchedCircuit, inputs, CurveId.BN254));
        assertTrue(mismatchedWitness.getCause() instanceof IllegalArgumentException);
        assertTrue(mismatchedWitness.getCause().getMessage().contains("does not match generated input schema"));

        var mismatchedEnvelope = assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> companion.getMethod("proofEnvelopeBuilder",
                                CircuitBuilder.class,
                                ProofSystemId.class,
                                CurveId.class,
                                byte[].class,
                                inputs.getClass(),
                                VerificationKeyRef.class)
                        .invoke(null,
                                mismatchedCircuit,
                                ProofSystemId.GROTH16,
                                CurveId.BN254,
                                new byte[]{1},
                                inputs,
                                new VerificationKeyRef.ById("vk-membership")));
        assertTrue(mismatchedEnvelope.getCause() instanceof IllegalArgumentException);

        Object badInputs = companion
                .getMethod("inputs", int.class, ZkMerkle.HashType.class)
                .invoke(null, 1, ZkMerkle.HashType.POSEIDON);
        var ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> badInputs.getClass().getMethod("siblings", List.class)
                        .invoke(badInputs, List.of(BigInteger.valueOf(7), BigInteger.valueOf(8))));
        assertTrue(ex.getCause() instanceof IllegalArgumentException);

        var badBuild = assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> companion.getMethod("build", int.class, ZkMerkle.HashType.class)
                        .invoke(null, 0, ZkMerkle.HashType.POSEIDON));
        assertTrue(badBuild.getCause() instanceof IllegalArgumentException);
        assertTrue(badBuild.getCause().getMessage().contains("@FixedSize(param = \"depth\") must be positive"));
    }

    @Test
    void fixedSizeParamCanReferenceBoxedIntegerCircuitParam() throws Exception {
        var compilation = compile("test.BoxedDepth", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "boxed-depth")
                public class BoxedDepth {
                    public BoxedDepth(@CircuitParam("depth") Integer depth) {}

                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Class<?> companion = compilation.load("test.BoxedDepthCircuit");
        ZkCircuitSchema schema = (ZkCircuitSchema) companion
                .getMethod("schema", Integer.class)
                .invoke(null, 2);
        assertEquals(List.of("sibling_0", "sibling_1"), schema.secretInputs().names());

        Object inputs = companion.getMethod("inputs", Integer.class).invoke(null, 2);
        inputs.getClass().getMethod("siblings", List.class)
                .invoke(inputs, List.of(BigInteger.ONE, BigInteger.TWO));
        inputs.getClass().getMethod("ok", long.class).invoke(inputs, 1L);
        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> witness =
                (Map<String, List<BigInteger>>) inputs.getClass().getMethod("toWitnessMap").invoke(inputs);
        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build", Integer.class).invoke(null, 2);
        assertDoesNotThrow(() -> circuit.calculateWitness(witness, CurveId.BN254));
    }

    @Test
    void nestedUIntArrayGeneratesRowMajorSchemaBuilderAndWitness() throws Exception {
        var compilation = compile("test.NestedMatrix", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "nested-matrix", nameTemplate = "nested-matrix-{rows}x{cols}")
                public class NestedMatrix {
                    private final int rows;
                    private final int cols;

                    public NestedMatrix(
                            @CircuitParam("rows") int rows,
                            @CircuitParam("cols") int cols) {
                        this.rows = rows;
                        this.cols = cols;
                    }

                    @Prove
                    void prove(
                            ZkContext zk,
                            @Public @FixedSize(param = "rows", innerParam = "cols")
                            ZkArray<ZkArray<ZkField>> expected,
                            @Secret @UInt(bits = 8) @FixedSize(param = "rows", innerParam = "cols")
                            ZkArray<ZkArray<ZkUInt>> values) {
                        for (int row = 0; row < rows; row++) {
                            for (int col = 0; col < cols; col++) {
                                values.get(row).get(col).asField().assertEqual(expected.get(row).get(col));
                            }
                        }
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Class<?> companion = compilation.load("test.NestedMatrixCircuit");
        ZkCircuitSchema schema = (ZkCircuitSchema) companion.getMethod("schema", int.class, int.class)
                .invoke(null, 2, 2);

        assertEquals("nested-matrix-2x2--rows-1:2--cols-1:2", schema.name());
        assertEquals(List.of("expected_0_0", "expected_0_1", "expected_1_0", "expected_1_1"),
                schema.publicInputs().names());
        assertEquals(List.of("value_0_0", "value_0_1", "value_1_0", "value_1_1"),
                schema.secretInputs().names());
        assertEquals(List.of(2, 2), schema.input("value").dimensions());
        assertEquals(4, schema.input("value").size());
        assertEquals(8, schema.input("value_1_1").bits());

        Object inputs = companion.getMethod("inputs", int.class, int.class).invoke(null, 2, 2);
        inputs.getClass().getMethod("expected", List.class).invoke(inputs, List.of(
                List.of(BigInteger.ONE, BigInteger.TWO),
                List.of(BigInteger.valueOf(3), BigInteger.valueOf(4))));
        inputs.getClass().getMethod("values", int.class, int.class, long.class)
                .invoke(inputs, 0, 0, 1L);
        inputs.getClass().getMethod("values", List.class).invoke(inputs, List.of(
                List.of(BigInteger.ONE, BigInteger.TWO),
                List.of(BigInteger.valueOf(3), BigInteger.valueOf(4))));

        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> witness =
                (Map<String, List<BigInteger>>) inputs.getClass().getMethod("toWitnessMap").invoke(inputs);
        assertEquals(BigInteger.valueOf(4), witness.get("value_1_1").getFirst());
        assertEquals(List.of(BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4)),
                companion.getMethod("publicInputs", inputs.getClass()).invoke(null, inputs));

        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build", int.class, int.class)
                .invoke(null, 2, 2);
        assertDoesNotThrow(() -> circuit.calculateWitness(witness, CurveId.BN254));

        Object badInputs = companion.getMethod("inputs", int.class, int.class).invoke(null, 2, 2);
        var ragged = assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> badInputs.getClass().getMethod("values", List.class).invoke(badInputs, List.of(
                        List.of(BigInteger.ONE),
                        List.of(BigInteger.TWO, BigInteger.valueOf(3)))));
        assertTrue(ragged.getCause() instanceof IllegalArgumentException);

        Object wrongInputs = companion.getMethod("inputs", int.class, int.class).invoke(null, 2, 2);
        wrongInputs.getClass().getMethod("expected", List.class).invoke(wrongInputs, List.of(
                List.of(BigInteger.ONE, BigInteger.TWO),
                List.of(BigInteger.valueOf(3), BigInteger.valueOf(4))));
        wrongInputs.getClass().getMethod("values", List.class).invoke(wrongInputs, List.of(
                List.of(BigInteger.ONE, BigInteger.TWO),
                List.of(BigInteger.valueOf(3), BigInteger.valueOf(5))));
        @SuppressWarnings("unchecked")
        Map<String, List<BigInteger>> wrongWitness =
                (Map<String, List<BigInteger>>) wrongInputs.getClass().getMethod("toWitnessMap").invoke(wrongInputs);
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(wrongWitness, CurveId.BN254));
    }

    @Test
    void nestedBoolArrayConstrainsEveryElement() throws Exception {
        var compilation = compile("test.NestedBoolMatrix", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "nested-bool-matrix")
                public class NestedBoolMatrix {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(value = 2, inner = 2)
                            ZkArray<ZkArray<ZkBool>> flags,
                            @Public ZkBool ok) {
                        return flags.get(0).get(0)
                                .and(flags.get(0).get(1))
                                .and(flags.get(1).get(0))
                                .and(flags.get(1).get(1))
                                .and(ok);
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Class<?> companion = compilation.load("test.NestedBoolMatrixCircuit");
        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build").invoke(null);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "flag_0_0", List.of(BigInteger.ONE),
                "flag_0_1", List.of(BigInteger.ONE),
                "flag_1_0", List.of(BigInteger.ONE),
                "flag_1_1", List.of(BigInteger.ONE),
                "ok", List.of(BigInteger.ONE)), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "flag_0_0", List.of(BigInteger.ONE),
                "flag_0_1", List.of(BigInteger.TWO),
                "flag_1_0", List.of(BigInteger.ONE),
                "flag_1_1", List.of(BigInteger.ONE),
                "ok", List.of(BigInteger.ONE)), CurveId.BN254));
    }

    @Test
    void rejectsInvalidNestedArrayShapes() throws Exception {
        var missingInner = compile("test.MissingInner", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class MissingInner {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(2) ZkArray<ZkArray<ZkField>> matrix,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(missingInner.success());
        assertTrue(missingInner.diagnosticsText().contains("@FixedSize inner dimension"));

        var innerOnFlat = compile("test.InnerOnFlat", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class InnerOnFlat {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(value = 2, inner = 2) ZkArray<ZkField> items,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(innerOnFlat.success());
        assertTrue(innerOnFlat.diagnosticsText().contains("inner or innerParam can only be used"));

        var deeper = compile("test.DeeperArray", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class DeeperArray {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(value = 2, inner = 2)
                            ZkArray<ZkArray<ZkArray<ZkField>>> matrix,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(deeper.success());
        assertTrue(deeper.diagnosticsText().contains("Only two-dimensional"));
    }

    @Test
    void parameterizedCircuitWithoutNameTemplateUsesCanonicalSuffix() throws Exception {
        var compilation = compile("test.ParamStatic", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "param-static")
                public class ParamStatic {
                    private ParamStatic() {}

                    public ParamStatic(@CircuitParam("depth") int depth) {}

                    @Prove
                    static ZkBool prove(@Secret ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        CircuitBuilder depth2 = (CircuitBuilder) compilation.load("test.ParamStaticCircuit")
                .getMethod("build", int.class)
                .invoke(null, 2);
        CircuitBuilder depth3 = (CircuitBuilder) compilation.load("test.ParamStaticCircuit")
                .getMethod("build", int.class)
                .invoke(null, 3);
        assertEquals("param-static--depth-1:2", depth2.constraintGraph().name());
        assertEquals("param-static--depth-1:3", depth3.constraintGraph().name());
    }

    @Test
    void circuitParamValuesUseCanonicalEncodingAndRejectUnsupportedTypes() throws Exception {
        var stringParam = compile("test.StringParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "string-param")
                public class StringParam {
                    public StringParam(@CircuitParam("label") String label) {}

                    @Prove
                    static ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(stringParam.success(), stringParam.diagnosticsText());
        Class<?> companion = stringParam.load("test.StringParamCircuit");
        CircuitBuilder circuit = (CircuitBuilder) companion.getMethod("build", String.class)
                .invoke(null, "a-b");
        assertEquals("string-param--label-3:a-b", circuit.constraintGraph().name());
        ZkCircuitSchema schema = (ZkCircuitSchema) companion.getMethod("schema", String.class)
                .invoke(null, "a-b");
        assertEquals("3:a-b", schema.parameters().getFirst().value());

        var unsupported = compile("test.UnsupportedParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class UnsupportedParam {
                    public UnsupportedParam(@CircuitParam("shape") Object shape) {}

                    @Prove
                    ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(unsupported.success());
        assertTrue(unsupported.diagnosticsText().contains("@CircuitParam type must be"));
    }

    @Test
    void nameTemplateCollisionsAreAvoidedByCanonicalSuffix() throws Exception {
        var compilation = compile("test.CollidingTemplate", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "colliding", nameTemplate = "colliding-{a}{b}")
                public class CollidingTemplate {
                    public CollidingTemplate(
                            @CircuitParam("a") int a,
                            @CircuitParam("b") int b) {}

                    @Prove
                    static ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Class<?> companion = compilation.load("test.CollidingTemplateCircuit");
        CircuitBuilder oneTwentyThree = (CircuitBuilder) companion.getMethod("build", int.class, int.class)
                .invoke(null, 1, 23);
        ZkCircuitSchema twelveThree = (ZkCircuitSchema) companion.getMethod("schema", int.class, int.class)
                .invoke(null, 12, 3);

        assertEquals("colliding-123--a-1:1--b-2:23", oneTwentyThree.constraintGraph().name());
        assertEquals("colliding-123--a-2:12--b-1:3", twelveThree.name());
        assertFalse(oneTwentyThree.constraintGraph().name().equals(twelveThree.name()));
    }

    @Test
    void staticProveDoesNotRequireVisibleNoArgConstructor() throws Exception {
        var compilation = compile("test.StaticProof", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(name = "static-proof")
                public class StaticProof {
                    private StaticProof() {}

                    @Prove
                    static ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        CircuitBuilder circuit = (CircuitBuilder) compilation.load("test.StaticProofCircuit")
                .getMethod("build")
                .invoke(null);
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of("ok", List.of(BigInteger.ONE)), CurveId.BN254));
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(Map.of("ok", List.of(BigInteger.ZERO)), CurveId.BN254));
    }

    @Test
    void rejectsStaticProveWithFieldStyleInputs() throws Exception {
        var compilation = compile("test.StaticFieldStyle", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class StaticFieldStyle {
                    @Public
                    ZkBool ok;

                    @Prove
                    static ZkBool prove() {
                        return null;
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText()
                .contains("Static @Prove methods must use parameter-style symbolic inputs"));
    }

    @Test
    void rejectsPrivateProveMethods() throws Exception {
        var compilation = compile("test.PrivateProof", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class PrivateProof {
                    @Prove
                    private ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText().contains("@Prove method must be visible to generated code"));
    }

    @Test
    void rejectsNestedCircuitClassesInPhase4() throws Exception {
        var compilation = compile("test.OuterCircuitHolder", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                public class OuterCircuitHolder {
                    @ZKCircuit
                    public static class InnerProof {
                        @Prove
                        ZkBool prove(@Public ZkBool ok) {
                            return ok;
                        }
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText()
                .contains("Nested @ZKCircuit classes are not supported in Phase 4"));
    }

    @Test
    void rejectsUnsupportedBooleanAndBigIntegerProofMethods() throws Exception {
        var booleanCompilation = compile("test.BooleanProof", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class BooleanProof {
                    @Prove
                    boolean prove() {
                        return true;
                    }
                }
                """);
        assertFalse(booleanCompilation.success());
        assertTrue(booleanCompilation.diagnosticsText().contains("must return ZkBool or void"));

        var bigIntegerCompilation = compile("test.BigIntegerProof", """
                package test;

                import java.math.BigInteger;
                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class BigIntegerProof {
                    @Prove
                    BigInteger prove() {
                        return BigInteger.ONE;
                    }
                }
                """);
        assertFalse(bigIntegerCompilation.success());
        assertTrue(bigIntegerCompilation.diagnosticsText().contains("must return ZkBool or void"));
    }

    @Test
    void rejectsInvalidFixedSizeParamReferences() throws Exception {
        var compilation = compile("test.BadMerkle", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class BadMerkle {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText().contains("must reference an integer @CircuitParam"));
    }

    @Test
    void rejectsCircuitParamOnProveParametersInPhase4() throws Exception {
        var compilation = compile("test.ProveParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class ProveParam {
                    @Prove
                    ZkBool prove(@CircuitParam("depth") int depth, @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText()
                .contains("@CircuitParam is only supported on constructors in Phase 4"));

        var contextCompilation = compile("test.ProveContextParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class ProveContextParam {
                    @Prove
                    ZkBool prove(@CircuitParam("zk") ZkContext zk, @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(contextCompilation.success());
        assertTrue(contextCompilation.diagnosticsText()
                .contains("@CircuitParam is only supported on constructors in Phase 4"));
    }

    @Test
    void rejectsVisibilityAnnotationsOnZkContextParameters() throws Exception {
        var compilation = compile("test.ContextVisibility", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class ContextVisibility {
                    @Prove
                    ZkBool prove(@Secret ZkContext zk, @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText().contains("ZkContext parameters cannot be @Public or @Secret"));
    }

    @Test
    void rejectsDuplicateAndUnsafeCircuitParamNames() throws Exception {
        var duplicate = compile("test.DuplicateCircuitParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class DuplicateCircuitParam {
                    public DuplicateCircuitParam(
                            @CircuitParam("depth") int first,
                            @CircuitParam("depth") int second) {}

                    @Prove
                    ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(duplicate.success());
        assertTrue(duplicate.diagnosticsText().contains("Duplicate @CircuitParam name: depth"));

        var unsafe = compile("test.UnsafeCircuitParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class UnsafeCircuitParam {
                    public UnsafeCircuitParam(@CircuitParam("bad-name") int depth) {}

                    @Prove
                    ZkBool prove(@Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(unsafe.success());
        assertTrue(unsafe.diagnosticsText().contains("@CircuitParam name must match [A-Za-z_][A-Za-z0-9_]*"));
    }

    @Test
    void rejectsUIntWidthsAboveSymbolicLimit() throws Exception {
        var compilation = compile("test.BadUInt", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class BadUInt {
                    @Prove
                    ZkBool prove(@Secret @UInt(bits = 254) ZkUInt value) {
                        return value.gte(value);
                    }
                }
                """);

        assertFalse(compilation.success());
        assertTrue(compilation.diagnosticsText().contains("@UInt bits must be in [1, 253]"));
    }

    @Test
    void rejectsDuplicateFlattenedAndConstantNames() throws Exception {
        var flattened = compile("test.DuplicateFlattened", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class DuplicateFlattened {
                    @Prove
                    ZkBool prove(
                            @Secret @FixedSize(1) ZkArray<ZkField> siblings,
                            @Secret(name = "sibling_0") ZkField sibling0,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(flattened.success());
        assertTrue(flattened.diagnosticsText().contains("Duplicate flattened input"));

        var constants = compile("test.DuplicateConstants", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class DuplicateConstants {
                    @Prove
                    ZkBool prove(
                            @Secret(name = "a-b") ZkField a,
                            @Secret(name = "a_b") ZkField b,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(constants.success());
        assertTrue(constants.diagnosticsText().contains("Duplicate generated input constant name"));

        var reservedConstant = compile("test.ReservedInputConstant", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class ReservedInputConstant {
                    @Prove
                    ZkBool prove(@Public(name = "circuitName") ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(reservedConstant.success());
        assertTrue(reservedConstant.diagnosticsText().contains("Duplicate generated input constant name"));

        var reservedVersionConstant = compile("test.ReservedVersionInputConstant", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class ReservedVersionInputConstant {
                    @Prove
                    ZkBool prove(@Public(name = "circuitVersion") ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(reservedVersionConstant.success());
        assertTrue(reservedVersionConstant.diagnosticsText()
                .contains("Duplicate generated input constant name"));
    }

    @Test
    void rejectsArrayBaseNamesThatOverlapFlattenedInputNames() throws Exception {
        var literal = compile("test.OverlappingArrayBase", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class OverlappingArrayBase {
                    @Prove
                    ZkBool prove(
                            @Secret(name = "item") @FixedSize(2) ZkArray<ZkField> items,
                            @Secret(name = "item_0") @FixedSize(1) ZkArray<ZkField> itemZero,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(literal.success());
        assertTrue(literal.diagnosticsText().contains("Input base name overlaps a flattened input name"));

        var parameterized = compile("test.OverlappingParamArrayBase", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class OverlappingParamArrayBase {
                    public OverlappingParamArrayBase(@CircuitParam("depth") int depth) {}

                    @Prove
                    ZkBool prove(
                            @Secret(name = "sibling") @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                            @Secret(name = "sibling_0") @FixedSize(1) ZkArray<ZkField> siblingZero,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(parameterized.success());
        assertTrue(parameterized.diagnosticsText().contains("Duplicate flattened input name may be generated"));
    }

    @Test
    void sanitizesGeneratedInputConstantsThatWouldNotBeJavaIdentifiers() throws Exception {
        var compilation = compile("test.OddInputNames", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class OddInputNames {
                    @Prove
                    ZkBool prove(
                            @Public(name = "1") ZkField one,
                            @Secret(name = "-") ZkField dash,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        String generated = compilation.generatedSource("test/OddInputNamesCircuit.java");
        assertTrue(generated.contains("public static final String INPUT_1 = \"1\";"));
        assertTrue(generated.contains("public static final String INPUT__ = \"-\";"));

        CircuitBuilder circuit = (CircuitBuilder) compilation.load("test.OddInputNamesCircuit")
                .getMethod("build")
                .invoke(null);
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "1", List.of(BigInteger.ONE),
                "-", List.of(BigInteger.TEN),
                "ok", List.of(BigInteger.ONE)), CurveId.BN254));
    }

    @Test
    void generatedArrayInputBuilderEscapesInputNamesInMessages() throws Exception {
        var compilation = compile("test.OddArrayNames", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit
                public class OddArrayNames {
                    @Prove
                    ZkBool prove(
                            @Secret(name = "item\\\"\\n") @FixedSize(1) ZkArray<ZkField> items,
                            @Public ZkBool ok) {
                        return ok;
                    }
                }
                """);

        assertTrue(compilation.success(), compilation.diagnosticsText());
        Object inputs = compilation.load("test.OddArrayNamesCircuit")
                .getMethod("inputs")
                .invoke(null);
        var ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> inputs.getClass().getMethod("items", List.class)
                        .invoke(inputs, List.of(BigInteger.ONE, BigInteger.TWO)));
        assertTrue(ex.getCause().getMessage().contains("item\"\n expects 1 values"));
    }

    @Test
    void rejectsNameTemplateThatOmitsOrReferencesUnknownParams() throws Exception {
        var missing = compile("test.MissingTemplateParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(nameTemplate = "missing-{depth}")
                public class MissingTemplateParam {
                    public MissingTemplateParam(
                            @CircuitParam("depth") int depth,
                            @CircuitParam("hashType") String hashType) {}

                    @Prove
                    ZkBool prove(@Secret ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(missing.success());
        assertTrue(missing.diagnosticsText().contains("must include @CircuitParam {hashType}"));

        var unknown = compile("test.UnknownTemplateParam", """
                package test;

                import com.bloxbean.cardano.zeroj.circuit.annotation.*;

                @ZKCircuit(nameTemplate = "unknown-{depth}-{other}")
                public class UnknownTemplateParam {
                    public UnknownTemplateParam(@CircuitParam("depth") int depth) {}

                    @Prove
                    ZkBool prove(@Secret ZkBool ok) {
                        return ok;
                    }
                }
                """);
        assertFalse(unknown.success());
        assertTrue(unknown.diagnosticsText().contains("references unknown @CircuitParam: other"));
    }

    private Compilation compile(String className, String source) throws Exception {
        var compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "Tests require a JDK, not a JRE");

        Path classesDir = Files.createDirectories(tempDir.resolve(className.replace('.', '_') + "_classes"));
        Path sourcesDir = Files.createDirectories(tempDir.resolve(className.replace('.', '_') + "_generated"));

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(
                diagnostics, null, StandardCharsets.UTF_8)) {
            List<String> options = List.of(
                    "-classpath", System.getProperty("java.class.path"),
                    "-processor", CircuitAnnotationProcessor.class.getName(),
                    "-d", classesDir.toString(),
                    "-s", sourcesDir.toString());

            Boolean ok = compiler.getTask(
                    null,
                    fileManager,
                    diagnostics,
                    options,
                    null,
                    List.of(new SourceFile(className, source))).call();
            return new Compilation(Boolean.TRUE.equals(ok), diagnostics, classesDir, sourcesDir);
        }
    }

    private record Compilation(
            boolean success,
            DiagnosticCollector<JavaFileObject> diagnostics,
            Path classesDir,
            Path sourcesDir) {

        String diagnosticsText() {
            return diagnostics.getDiagnostics().stream()
                    .map(d -> d.getKind() + ": " + d.getMessage(null))
                    .reduce("", (a, b) -> a + b + "\n");
        }

        String generatedSource(String relativePath) throws Exception {
            return Files.readString(sourcesDir.resolve(relativePath));
        }

        Class<?> load(String className) throws Exception {
            URLClassLoader loader = new URLClassLoader(
                    new java.net.URL[]{classesDir.toUri().toURL()},
                    CircuitAnnotationProcessorTest.class.getClassLoader());
            return Class.forName(className, true, loader);
        }
    }

    private static final class SourceFile extends SimpleJavaFileObject {
        private final String source;

        private SourceFile(String className, String source) {
            super(URI.create("string:///" + className.replace('.', '/') + JavaFileObject.Kind.SOURCE.extension),
                    JavaFileObject.Kind.SOURCE);
            this.source = source;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
        }
    }

}
