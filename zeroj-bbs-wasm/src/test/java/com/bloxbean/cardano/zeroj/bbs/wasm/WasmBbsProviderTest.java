package com.bloxbean.cardano.zeroj.bbs.wasm;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsKeyPair;
import com.bloxbean.cardano.zeroj.bbs.BbsProof;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSecretKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.types.ExternalType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class WasmBbsProviderTest {

    private static final byte[] KEY_MATERIAL = hex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
    private static final byte[] KEY_INFO = hex("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
    private static final byte[] EXPECTED_SK = hex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    private static final byte[] EXPECTED_PK = hex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    private static final byte[] HEADER = hex("11223344556677889900aabbccddeeff");
    private static final byte[] PRESENTATION_HEADER = hex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
    private static final byte[] SINGLE_MSG = hex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
    private static final byte[] EXPECTED_SIG_SHA256 = hex("84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0");

    @Test
    void wasmModule_hasExactlyOneImportAndExpectedExports() throws IOException {
        var module = Parser.parse(loadDefaultWasm());

        assertEquals(1, module.importSection().importCount());
        var imp = module.importSection().getImport(0);
        assertEquals("env", imp.module());
        assertEquals("zeroj_host_getrandom", imp.name());
        assertEquals(ExternalType.FUNCTION, imp.importType());

        Set<String> exports = new HashSet<>();
        for (int i = 0; i < module.exportSection().exportCount(); i++) {
            var export = module.exportSection().getExport(i);
            if (export.exportType() == ExternalType.FUNCTION) {
                exports.add(export.name());
            }
        }
        assertTrue(exports.contains("zeroj_bbs_version"));
        assertTrue(exports.contains("zeroj_bbs_keygen"));
        assertTrue(exports.contains("zeroj_bbs_sk_to_pk"));
        assertTrue(exports.contains("zeroj_bbs_sign"));
        assertTrue(exports.contains("zeroj_bbs_verify"));
        assertTrue(exports.contains("zeroj_bbs_proof_gen"));
        assertTrue(exports.contains("zeroj_bbs_proof_verify"));
        assertTrue(exports.contains("alloc"));
        assertTrue(exports.contains("dealloc"));
    }

    @Test
    void keygenAndSkToPk_matchDraft10ShaFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);

        BbsSecretKey sk = provider.keyGen(KEY_MATERIAL, KEY_INFO);
        assertArrayEquals(EXPECTED_SK, sk.toBytes());

        BbsPublicKey pk = provider.skToPk(sk);
        assertArrayEquals(EXPECTED_PK, pk.bytes());
    }

    @Test
    void sign_matchesDraft10ShaSingleMessageFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);

        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), List.of(SINGLE_MSG), HEADER);

        assertArrayEquals(EXPECTED_SIG_SHA256, sig.bytes());
        assertTrue(provider.verify(kp.publicKey(), sig, List.of(SINGLE_MSG), HEADER));
    }

    @Test
    void verify_rejectsTamperedSignature() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), List.of(SINGLE_MSG), HEADER);

        byte[] bad = sig.bytes();
        bad[bad.length - 1] ^= 1;

        assertFalse(provider.verify(
                kp.publicKey(),
                new BbsSignature(bad, BbsCiphersuite.BLS12381_SHA256),
                List.of(SINGLE_MSG),
                HEADER));
    }

    @Test
    void proofGen_roundtripsViaProofVerify() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        List<byte[]> messages = List.of(SINGLE_MSG);
        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), messages, HEADER);

        BbsProof proof = provider.proofGen(
                kp.publicKey(),
                sig,
                messages,
                HEADER,
                PRESENTATION_HEADER,
                new int[]{0},
                new SecureRandom());

        assertTrue(provider.proofVerify(
                kp.publicKey(),
                proof,
                HEADER,
                PRESENTATION_HEADER,
                messages,
                new int[]{0}));
    }

    @Test
    void proofGen_isNonDeterministicAcrossCalls() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        List<byte[]> messages = List.of(SINGLE_MSG);
        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), messages, HEADER);

        BbsProof first = provider.proofGen(
                kp.publicKey(), sig, messages, HEADER, PRESENTATION_HEADER, new int[]{0}, new SecureRandom());
        BbsProof second = provider.proofGen(
                kp.publicKey(), sig, messages, HEADER, PRESENTATION_HEADER, new int[]{0}, new SecureRandom());

        assertFalse(java.util.Arrays.equals(first.bytes(), second.bytes()),
                "host RNG must produce distinct proofs across calls");
        assertTrue(provider.proofVerify(
                kp.publicKey(), first, HEADER, PRESENTATION_HEADER, messages, new int[]{0}));
        assertTrue(provider.proofVerify(
                kp.publicKey(), second, HEADER, PRESENTATION_HEADER, messages, new int[]{0}));
    }

    @Test
    void shake256_signRoundtripsViaVerify() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHAKE256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);

        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), List.of(SINGLE_MSG), HEADER);
        assertTrue(provider.verify(kp.publicKey(), sig, List.of(SINGLE_MSG), HEADER));
    }

    @Test
    void rawInvocation_reportsTypedExceptionOnShortInput() {
        var client = Bbs12381WasmClient.createDefault();

        assertThrows(Bbs12381WasmException.class,
                () -> client.invokeRawForTesting("zeroj_bbs_sign", new byte[1]));
        assertThrows(Bbs12381WasmException.class,
                () -> client.invokeRawForTesting("zeroj_bbs_verify", new byte[]{}));
    }

    @Test
    void rawInvocation_reportsTypedExceptionOnInvalidPublicKey() {
        var client = Bbs12381WasmClient.createDefault();

        byte[] req = new byte[1 + 32];
        req[0] = Bbs12381WasmClient.SUITE_SHA256;
        assertThrows(Bbs12381WasmException.class,
                () -> client.invokeRawForTesting("zeroj_bbs_sk_to_pk",
                        java.util.Arrays.copyOf(req, req.length - 1)));
    }

    @Test
    void repeatedErrors_doNotPoisonClient() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        for (int i = 0; i < 50; i++) {
            assertThrows(Bbs12381WasmException.class,
                    () -> provider.keyGen(new byte[0], new byte[0]));
        }
        BbsSecretKey sk = provider.keyGen(KEY_MATERIAL, KEY_INFO);
        assertArrayEquals(EXPECTED_SK, sk.toBytes());
    }

    @Test
    void malformedResponseLength_freesResponseAllocationOnInvoke() {
        SecureRandom rng = new SecureRandom();
        var malformed = new Bbs12381WasmClient(malformedResponseWasm(), rng);

        assertThrows(Bbs12381WasmException.class,
                () -> malformed.invokeRawForTesting("malformed_response", new byte[]{1, 2, 3}));

        assertEquals(2, malformed.invokeExportForTesting("dealloc_count"));
        assertEquals(4, malformed.invokeExportForTesting("last_dealloc_len"));
    }

    @Test
    void malformedResponseLength_freesResponseAllocationOnInvokeNoArg() {
        SecureRandom rng = new SecureRandom();
        var malformed = new Bbs12381WasmClient(malformedResponseWasm(), rng);

        assertThrows(Bbs12381WasmException.class,
                () -> malformed.invokeNoArgRawForTesting("malformed_noarg"));

        assertEquals(1, malformed.invokeExportForTesting("dealloc_count"));
        assertEquals(4, malformed.invokeExportForTesting("last_dealloc_len"));
    }

    private static byte[] loadDefaultWasm() throws IOException {
        try (var in = Bbs12381WasmClient.class.getResourceAsStream(Bbs12381WasmClient.DEFAULT_RESOURCE)) {
            assertNotNull(in, "BBS WASM resource must be present on the classpath");
            return in.readAllBytes();
        }
    }

    // Hand-built synthetic WASM module exporting only the version-1 ABI shape
    // we need to exercise the response-buffer cleanup path. Mirrors the
    // technique in Bls12381WasmClientTest.malformedResponseWasm. Notably this
    // synthetic module declares no imports, so it remains compatible with the
    // Bbs12381WasmClient constructor (which always supplies the
    // env.zeroj_host_getrandom import — Chicory ignores unused-import slots).
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
            export(out, "zeroj_bbs_version", 0, 0);
            export(out, "alloc", 0, 1);
            export(out, "dealloc", 0, 2);
            export(out, "malformed_response", 0, 3);
            export(out, "malformed_noarg", 0, 4);
            export(out, "dealloc_count", 0, 5);
            export(out, "last_dealloc_len", 0, 6);
        });
        section(wasm, 10, out -> {
            u32(out, 7);
            // zeroj_bbs_version: return 1
            code(out, 0x00, 0x41, 0x01, 0x0b);
            // alloc: return 0x400 (1024)
            code(out, 0x00, 0x41, 0x80, 0x08, 0x0b);
            // dealloc: count++, last_len = arg1
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
            // malformed_response: write 0 at addr 8, return 8
            code(out, 0x00, 0x41, 0x08, 0x41, 0x00, 0x36, 0x02, 0x00, 0x41, 0x08, 0x0b);
            // malformed_noarg: same
            code(out, 0x00, 0x41, 0x08, 0x41, 0x00, 0x36, 0x02, 0x00, 0x41, 0x08, 0x0b);
            // dealloc_count: load addr 0
            code(out, 0x00, 0x41, 0x00, 0x28, 0x02, 0x00, 0x0b);
            // last_dealloc_len: load addr 4
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

    private static byte[] hex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private interface SectionWriter {
        void write(ByteArrayOutputStream out);
    }
}
