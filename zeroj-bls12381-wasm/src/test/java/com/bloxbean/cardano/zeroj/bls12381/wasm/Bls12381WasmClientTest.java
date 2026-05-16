package com.bloxbean.cardano.zeroj.bls12381.wasm;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.types.ExternalType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class Bls12381WasmClientTest {

    private final Bls12381WasmClient client = Bls12381WasmClient.createDefault();

    @Test
    void wasmModule_hasNoHostImportsAndExpectedExports() throws IOException {
        var module = Parser.parse(loadDefaultWasm());
        assertEquals(0, module.importSection().importCount());

        Set<String> exports = new HashSet<>();
        for (int i = 0; i < module.exportSection().exportCount(); i++) {
            var export = module.exportSection().getExport(i);
            if (export.exportType() == ExternalType.FUNCTION) {
                exports.add(export.name());
            }
        }
        assertTrue(exports.contains("zeroj_bls12381_version"));
        assertTrue(exports.contains("zeroj_bls12381_g1_generator"));
        assertTrue(exports.contains("zeroj_bls12381_g2_generator"));
        assertTrue(exports.contains("zeroj_bls12381_g1_scalar_mul"));
        assertTrue(exports.contains("zeroj_bls12381_g2_scalar_mul"));
        assertTrue(exports.contains("zeroj_bls12381_pairing_check"));
        assertTrue(exports.contains("alloc"));
        assertTrue(exports.contains("dealloc"));
    }

    @Test
    void generators_matchPureJavaConstants() {
        assertEquals(Bls12381Generators.G1, client.g1Generator());
        assertEquals(Bls12381Generators.G2, client.g2Generator());
    }

    @Test
    void scalarMul_matchesPureJavaProvider() {
        var pure = Bls12381Providers.pureJava();
        BigInteger scalar = BigInteger.valueOf(42);

        assertEquals(pure.g1ScalarMul(Bls12381Generators.G1, scalar),
                client.g1ScalarMul(Bls12381Generators.G1, scalar));
        assertEquals(pure.g2ScalarMul(Bls12381Generators.G2, scalar),
                client.g2ScalarMul(Bls12381Generators.G2, scalar));
    }

    @Test
    void scalarMul_byZero_returnsInfinity() {
        assertEquals(G1Point.INFINITY, client.g1ScalarMul(Bls12381Generators.G1, BigInteger.ZERO));
        assertEquals(G2Point.INFINITY, client.g2ScalarMul(Bls12381Generators.G2, BigInteger.ZERO));
    }

    @Test
    void scalarMul_reducesScalarsLikePureJavaProvider() {
        var pure = Bls12381Providers.pureJava();
        var r = Bls12381Generators.SCALAR_FIELD_ORDER;

        for (BigInteger scalar : new BigInteger[]{r, r.add(BigInteger.ONE), BigInteger.valueOf(-1)}) {
            assertEquals(pure.g1ScalarMul(Bls12381Generators.G1, scalar),
                    client.g1ScalarMul(Bls12381Generators.G1, scalar));
            assertEquals(pure.g2ScalarMul(Bls12381Generators.G2, scalar),
                    client.g2ScalarMul(Bls12381Generators.G2, scalar));
        }
    }

    @Test
    void scalarMul_rejectsInvalidPointsBeforeWasmCall() {
        assertThrows(IllegalArgumentException.class,
                () -> client.g1ScalarMul(new G1Point(Fp.ZERO, Fp.ZERO), BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> client.g2ScalarMul(new G2Point(Fp2.ZERO, Fp2.ZERO), BigInteger.ONE));
    }

    @Test
    void rawWasmInvocation_reportsWrongLengthAndInvalidPointErrors() {
        assertThrows(Bls12381WasmException.class,
                () -> client.invokeRawForTesting("zeroj_bls12381_g1_scalar_mul", new byte[1]));
        assertThrows(Bls12381WasmException.class,
                () -> client.invokeRawForTesting("zeroj_bls12381_pairing_check", new byte[3]));

        byte[] invalidG1ScalarMul = new byte[128];
        assertThrows(Bls12381WasmException.class,
                () -> client.invokeRawForTesting("zeroj_bls12381_g1_scalar_mul", invalidG1ScalarMul));
    }

    @Test
    void rawWasmInvocation_repeatedErrorsDoNotPoisonClient() {
        for (int i = 0; i < 100; i++) {
            assertThrows(Bls12381WasmException.class,
                    () -> client.invokeRawForTesting("zeroj_bls12381_g2_scalar_mul", new byte[7]));
        }
        assertEquals(Bls12381Generators.G1, client.g1Generator());
    }

    @Test
    void malformedResponseLengthStillFreesResponseAllocation() {
        var malformed = new Bls12381WasmClient(malformedResponseWasm());

        assertThrows(Bls12381WasmException.class,
                () -> malformed.invokeRawForTesting("malformed_response", new byte[]{1, 2, 3}));

        assertEquals(2, malformed.invokeExportForTesting("dealloc_count"));
        assertEquals(4, malformed.invokeExportForTesting("last_dealloc_len"));
    }

    @Test
    void malformedNoArgResponseLengthStillFreesResponseAllocation() {
        var malformed = new Bls12381WasmClient(malformedResponseWasm());

        assertThrows(Bls12381WasmException.class,
                () -> malformed.invokeNoArgRawForTesting("malformed_noarg"));

        assertEquals(1, malformed.invokeExportForTesting("dealloc_count"));
        assertEquals(4, malformed.invokeExportForTesting("last_dealloc_len"));
    }

    @Test
    void pairingProduct_matchesExpectedIdentityResult() {
        G1Point g1 = Bls12381Generators.G1;
        G2Point g2 = Bls12381Generators.G2;

        assertFalse(client.pairingProductIsIdentity(new G1Point[]{g1}, new G2Point[]{g2}));
        assertTrue(client.pairingProductIsIdentity(new G1Point[]{g1, g1.negate()}, new G2Point[]{g2, g2}));
    }

    @Test
    void provider_implementsSharedSpi() {
        var provider = WasmBls12381Provider.createDefault();

        assertEquals("zeroj-bls12381-wasm-zkcrypto", provider.id());
        assertEquals(Bls12381Generators.G1, provider.g1Generator());
        assertEquals(Bls12381Generators.G1,
                provider.g1FromCompressed(provider.g1ToCompressed(Bls12381Generators.G1)));
        assertEquals(provider.g1ScalarMulGenerator(BigInteger.valueOf(42)),
                provider.g1SecretScalarMulGenerator(BigInteger.valueOf(42)));
        assertEquals(provider.g2ScalarMulGenerator(BigInteger.valueOf(42)),
                provider.g2SecretScalarMulGenerator(BigInteger.valueOf(42)));
        assertTrue(provider.g1HashToCurve(
                "abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(java.nio.charset.StandardCharsets.US_ASCII)).isValid());
        assertTrue(provider.pairingProductIsIdentity(
                new G1Point[]{Bls12381Generators.G1, Bls12381Generators.G1.negate()},
                new G2Point[]{Bls12381Generators.G2, Bls12381Generators.G2}));
    }

    private static byte[] loadDefaultWasm() throws IOException {
        try (var in = Bls12381WasmClient.class.getResourceAsStream(Bls12381WasmClient.DEFAULT_RESOURCE)) {
            assertNotNull(in);
            return in.readAllBytes();
        }
    }

    private static byte[] malformedResponseWasm() {
        var wasm = new ByteArrayOutputStream();
        write(wasm, 0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00);
        section(wasm, 1, out -> {
            u32(out, 4);
            funcType(out, 0, true);
            funcType(out, 1, true);
            funcType(out, 2, false);
            funcType(out, 2, true);
        });
        section(wasm, 3, out -> {
            u32(out, 7);
            write(out, 0, 1, 2, 3, 0, 0, 0);
        });
        section(wasm, 5, out -> write(out, 1, 0, 1));
        section(wasm, 7, out -> {
            u32(out, 8);
            export(out, "memory", 2, 0);
            export(out, "zeroj_bls12381_version", 0, 0);
            export(out, "alloc", 0, 1);
            export(out, "dealloc", 0, 2);
            export(out, "malformed_response", 0, 3);
            export(out, "malformed_noarg", 0, 4);
            export(out, "dealloc_count", 0, 5);
            export(out, "last_dealloc_len", 0, 6);
        });
        section(wasm, 10, out -> {
            u32(out, 7);
            code(out, 0x00, 0x41, 0x01, 0x0b);
            code(out, 0x00, 0x41, 0x80, 0x08, 0x0b);
            code(out,
                    0x00,
                    0x41, 0x00,
                    0x41, 0x00,
                    0x28, 0x02, 0x00,
                    0x41, 0x01,
                    0x6a,
                    0x36, 0x02, 0x00,
                    0x41, 0x04,
                    0x20, 0x01,
                    0x36, 0x02, 0x00,
                    0x0b);
            code(out, 0x00, 0x41, 0x08, 0x41, 0x00, 0x36, 0x02, 0x00, 0x41, 0x08, 0x0b);
            code(out, 0x00, 0x41, 0x08, 0x41, 0x00, 0x36, 0x02, 0x00, 0x41, 0x08, 0x0b);
            code(out, 0x00, 0x41, 0x00, 0x28, 0x02, 0x00, 0x0b);
            code(out, 0x00, 0x41, 0x04, 0x28, 0x02, 0x00, 0x0b);
        });
        return wasm.toByteArray();
    }

    private static void funcType(ByteArrayOutputStream out, int paramCount, boolean hasResult) {
        write(out, 0x60);
        u32(out, paramCount);
        for (int i = 0; i < paramCount; i++) {
            write(out, 0x7f);
        }
        u32(out, hasResult ? 1 : 0);
        if (hasResult) {
            write(out, 0x7f);
        }
    }

    private static void export(ByteArrayOutputStream out, String name, int kind, int index) {
        byte[] nameBytes = name.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        u32(out, nameBytes.length);
        out.writeBytes(nameBytes);
        write(out, kind);
        u32(out, index);
    }

    private static void code(ByteArrayOutputStream out, int... body) {
        u32(out, body.length);
        write(out, body);
    }

    private static void section(ByteArrayOutputStream wasm, int id, SectionWriter writer) {
        var body = new ByteArrayOutputStream();
        writer.write(body);
        write(wasm, id);
        u32(wasm, body.size());
        wasm.writeBytes(body.toByteArray());
    }

    private static void u32(ByteArrayOutputStream out, int value) {
        int remaining = value;
        do {
            int b = remaining & 0x7f;
            remaining >>>= 7;
            if (remaining != 0) {
                b |= 0x80;
            }
            write(out, b);
        } while (remaining != 0);
    }

    private static void write(ByteArrayOutputStream out, int... bytes) {
        for (int b : bytes) {
            out.write(b);
        }
    }

    private interface SectionWriter {
        void write(ByteArrayOutputStream out);
    }
}
