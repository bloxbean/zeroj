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

    // SHAKE-256 ciphersuite fixtures (same key_material + key_info, different ciphersuite).
    private static final byte[] EXPECTED_SK_SHAKE = hex("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079");
    private static final byte[] EXPECTED_PK_SHAKE = hex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5");
    private static final byte[] EXPECTED_SIG_SHAKE_SINGLE = hex("b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef");
    private static final byte[] EXPECTED_SIG_SHAKE_MULTI = hex("956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e");

    // SHA-256 multi-message signature (signature004.json, 10 messages, with header).
    private static final byte[] EXPECTED_SIG_SHA256_MULTI = hex("8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8");

    // SHA-256 no-header signature (signature010.json, 10 messages, empty header).
    private static final byte[] EXPECTED_SIG_SHA256_NOHEADER = hex("8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d");

    private static List<byte[]> tenFixtureMessages() {
        return List.of(
                hex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
                hex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
                hex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
                hex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
                hex("496694774c5604ab1b2544eababcf0f53278ff50"),
                hex("515ae153e22aae04ad16f759e07237b4"),
                hex("d183ddc6e2665aa4e2f088af"),
                hex("ac55fb33a75909ed"),
                hex("96012096"),
                new byte[0]);
    }

    // SHA-256 proof001: single-message revealed proof; CFRG mockedRng-derived
    // proof bytes; proof_verify must accept.
    private static final byte[] PROOF_SHA256_PROOF001 = hex("94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418");

    // SHAKE-256 proof001.
    private static final byte[] PROOF_SHAKE_PROOF001 = hex("89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d");

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
    void proofGen_honorsPerCallSecureRandom() {
        // The per-call SecureRandom must actually drive the host getrandom
        // import. We can't assert "same RNG → same proof" within one WASM
        // instance because zkryptium's ThreadRng has its own internal state
        // that advances across calls (our host bytes only reseed it
        // periodically). Instead we observe that the supplied RNG is being
        // read at all, AND that the constructor's defaultRandom is NOT being
        // read while the per-call random is present.
        var defaultCounter = new CountingSecureRandom();
        var perCallCounter = new CountingSecureRandom();
        var provider = new WasmBbsProvider(
                BbsCiphersuite.BLS12381_SHA256,
                Bbs12381WasmClient.createDefault(defaultCounter));

        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        List<byte[]> messages = List.of(SINGLE_MSG);
        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), messages, HEADER);

        // KeyGen, SkToPk, Sign are deterministic in CFRG draft-10 — they
        // must NOT consume any host RNG bytes.
        assertEquals(0, defaultCounter.bytesRead, "deterministic ops must not call host getrandom");

        BbsProof proof = provider.proofGen(
                kp.publicKey(), sig, messages, HEADER, PRESENTATION_HEADER,
                new int[]{0}, perCallCounter);

        assertTrue(perCallCounter.bytesRead > 0,
                "per-call SecureRandom must drive host getrandom (read 0 bytes)");
        assertEquals(0, defaultCounter.bytesRead,
                "defaultRandom must NOT be read when a per-call SecureRandom is supplied");
        assertTrue(provider.proofVerify(
                kp.publicKey(), proof, HEADER, PRESENTATION_HEADER, messages, new int[]{0}));
    }

    /** SecureRandom subclass that records how many bytes have been consumed via nextBytes. */
    private static final class CountingSecureRandom extends SecureRandom {
        volatile int bytesRead = 0;

        CountingSecureRandom() {
            super(new java.security.SecureRandomSpi() {
                @Override protected void engineSetSeed(byte[] seed) {}
                @Override protected void engineNextBytes(byte[] bytes) {
                    // Fill with arbitrary deterministic bytes so proof_gen still
                    // succeeds (zkryptium will reject out-of-range scalars,
                    // 0x42... is well below r).
                    java.util.Arrays.fill(bytes, (byte) 0x42);
                }
                @Override protected byte[] engineGenerateSeed(int numBytes) {
                    byte[] b = new byte[numBytes];
                    java.util.Arrays.fill(b, (byte) 0x42);
                    return b;
                }
            }, null);
        }

        @Override
        public void nextBytes(byte[] bytes) {
            super.nextBytes(bytes);
            bytesRead += bytes.length;
        }
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
    void keygenAndSkToPk_matchDraft10ShakeFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHAKE256);

        BbsSecretKey sk = provider.keyGen(KEY_MATERIAL, KEY_INFO);
        assertArrayEquals(EXPECTED_SK_SHAKE, sk.toBytes());

        BbsPublicKey pk = provider.skToPk(sk);
        assertArrayEquals(EXPECTED_PK_SHAKE, pk.bytes());
    }

    @Test
    void sign_matchesDraft10ShakeSingleMessageFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHAKE256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);

        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), List.of(SINGLE_MSG), HEADER);

        assertArrayEquals(EXPECTED_SIG_SHAKE_SINGLE, sig.bytes());
        assertTrue(provider.verify(kp.publicKey(), sig, List.of(SINGLE_MSG), HEADER));
    }

    @Test
    void sign_matchesDraft10ShakeMultiMessageFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHAKE256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        List<byte[]> messages = tenFixtureMessages();

        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), messages, HEADER);

        assertArrayEquals(EXPECTED_SIG_SHAKE_MULTI, sig.bytes());
        assertTrue(provider.verify(kp.publicKey(), sig, messages, HEADER));
    }

    @Test
    void sign_matchesDraft10ShaMultiMessageFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        List<byte[]> messages = tenFixtureMessages();

        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), messages, HEADER);

        assertArrayEquals(EXPECTED_SIG_SHA256_MULTI, sig.bytes());
        assertTrue(provider.verify(kp.publicKey(), sig, messages, HEADER));
    }

    @Test
    void sign_matchesDraft10ShaNoHeaderFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsKeyPair kp = provider.keyPair(KEY_MATERIAL, KEY_INFO);
        List<byte[]> messages = tenFixtureMessages();
        byte[] emptyHeader = new byte[0];

        BbsSignature sig = provider.sign(kp.secretKey(), kp.publicKey(), messages, emptyHeader);

        assertArrayEquals(EXPECTED_SIG_SHA256_NOHEADER, sig.bytes());
        assertTrue(provider.verify(kp.publicKey(), sig, messages, emptyHeader));
    }

    @Test
    void proofVerify_acceptsOfficialDraft10ShaProofFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsPublicKey pk = new BbsPublicKey(EXPECTED_PK, BbsCiphersuite.BLS12381_SHA256);
        BbsProof proof = new BbsProof(PROOF_SHA256_PROOF001, BbsCiphersuite.BLS12381_SHA256);
        List<byte[]> disclosedMessages = List.of(SINGLE_MSG);
        int[] disclosedIndexes = {0};

        assertTrue(provider.proofVerify(
                pk, proof, HEADER, PRESENTATION_HEADER, disclosedMessages, disclosedIndexes));
    }

    @Test
    void proofVerify_acceptsOfficialDraft10ShakeProofFixture() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHAKE256);
        BbsPublicKey pk = new BbsPublicKey(EXPECTED_PK_SHAKE, BbsCiphersuite.BLS12381_SHAKE256);
        BbsProof proof = new BbsProof(PROOF_SHAKE_PROOF001, BbsCiphersuite.BLS12381_SHAKE256);
        List<byte[]> disclosedMessages = List.of(SINGLE_MSG);
        int[] disclosedIndexes = {0};

        assertTrue(provider.proofVerify(
                pk, proof, HEADER, PRESENTATION_HEADER, disclosedMessages, disclosedIndexes));
    }

    @Test
    void proofVerify_rejectsOfficialProofWithWrongPresentationHeader() {
        var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
        BbsPublicKey pk = new BbsPublicKey(EXPECTED_PK, BbsCiphersuite.BLS12381_SHA256);
        BbsProof proof = new BbsProof(PROOF_SHA256_PROOF001, BbsCiphersuite.BLS12381_SHA256);
        List<byte[]> disclosedMessages = List.of(SINGLE_MSG);
        int[] disclosedIndexes = {0};
        byte[] wrongPh = new byte[PRESENTATION_HEADER.length];
        System.arraycopy(PRESENTATION_HEADER, 0, wrongPh, 0, PRESENTATION_HEADER.length);
        wrongPh[0] ^= 1;

        assertFalse(provider.proofVerify(
                pk, proof, HEADER, wrongPh, disclosedMessages, disclosedIndexes));
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

    @Test
    void verify_rejectsNonCanonicalBooleanResponse() {
        SecureRandom rng = new SecureRandom();
        var bad = new Bbs12381WasmClient(badBoolResponseWasm(), rng);

        byte[] pk = new byte[96];
        byte[] sig = new byte[80];
        Bbs12381WasmException ex = assertThrows(
                Bbs12381WasmException.class,
                () -> bad.verify(BbsCiphersuite.BLS12381_SHA256, pk, sig, new byte[0], List.of()));
        assertTrue(ex.getMessage().contains("boolean response byte"),
                "expected strict bool decode error, got: " + ex.getMessage());
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

    // Synthetic WASM that always returns a "success" response with a bool
    // payload byte of 0x02 (instead of the legal 0x00 or 0x01). Used to verify
    // that Bbs12381WasmClient.decodeBool rejects non-canonical truthy values.
    private static byte[] badBoolResponseWasm() {
        var wasm = new ByteArrayOutputStream();
        write(wasm, 0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00);
        section(wasm, 1, out -> {
            u32(out, 4);
            funcType(out, 0, true);   // () -> i32
            funcType(out, 1, true);   // (i32) -> i32
            funcType(out, 2, false);  // (i32, i32) -> void
            funcType(out, 2, true);   // (i32, i32) -> i32
        });
        section(wasm, 3, out -> {
            u32(out, 4);
            write(out, 0, 1, 2, 3);
        });
        section(wasm, 5, out -> write(out, 1, 0, 1));
        section(wasm, 7, out -> {
            u32(out, 5);
            export(out, "memory", 2, 0);
            export(out, "zeroj_bbs_version", 0, 0);
            export(out, "alloc", 0, 1);
            export(out, "dealloc", 0, 2);
            export(out, "zeroj_bbs_verify", 0, 3);
        });
        section(wasm, 10, out -> {
            u32(out, 4);
            // zeroj_bbs_version -> 1
            code(out, 0x00, 0x41, 0x01, 0x0b);
            // alloc -> 0x400 (1024)
            code(out, 0x00, 0x41, 0x80, 0x08, 0x0b);
            // dealloc -> no-op
            code(out, 0x00, 0x0b);
            // zeroj_bbs_verify: write [u32 LE 2 | 0x00 | 0x02] at addr 8, return 8.
            //   addr 8..12: response length = 2
            //   addr 12:    status = 0 (success)
            //   addr 13:    payload byte = 0x02 (illegal bool)
            code(out,
                    0x00,
                    0x41, 0x08, 0x41, 0x02, 0x36, 0x02, 0x00,    // i32.store [8] = 2
                    0x41, 0x0c, 0x41, 0x00, 0x3a, 0x00, 0x00,    // i32.store8 [12] = 0
                    0x41, 0x0d, 0x41, 0x02, 0x3a, 0x00, 0x00,    // i32.store8 [13] = 2
                    0x41, 0x08, 0x0b);                            // return 8
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
