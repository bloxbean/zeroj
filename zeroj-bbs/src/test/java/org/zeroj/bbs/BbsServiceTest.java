package org.zeroj.bbs;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.PublicInputs;
import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.ZkProofEnvelope;
import org.zeroj.bbs.internal.BbsCodec;
import org.zeroj.bbs.verifier.BbsZkVerifier;
import org.zeroj.bbs.spi.PureJavaBbsProvider;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.Bls12381Providers;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BbsServiceTest {

    @Test
    void serviceSignsVerifiesAndDerivesPresentation() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("01234567890123456789012345678901"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("name:alice"), bytes("age:42"), bytes("member:true"));
        byte[] header = bytes("credential-v1");
        byte[] presentationHeader = bytes("verifier-session-123");

        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        assertTrue(service.verify(keyPair.publicKey(), signature, messages, header));

        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, presentationHeader, new int[]{0, 2});

        assertEquals(List.of(new BbsRevealedMessage(0, messages.get(0)), new BbsRevealedMessage(2, messages.get(2))),
                presentation.revealedMessages());
        assertTrue(service.verifyPresentation(keyPair.publicKey(), presentation));
    }

    @Test
    void secretKeyMaterialIsRedactedFromToString() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("01234567890123456789012345678901"), bytes("issuer-key"));

        String secretValue = keyPair.secretKey().value().toString();

        assertTrue(keyPair.secretKey().toString().contains("redacted"));
        assertFalse(keyPair.secretKey().toString().contains(secretValue));
        assertTrue(keyPair.toString().contains("secretKey=redacted"));
        assertFalse(keyPair.toString().contains(secretValue));
    }

    @Test
    void rawProofRejectsMoreThanMaxMessages() {
        BbsCiphersuite suite = BbsCiphersuite.BLS12381_SHA256;
        int floor = 3 * suite.g1Bytes() + 4 * suite.scalarBytes();
        byte[] oversized = new byte[floor + (BbsCodec.MAX_MESSAGES + 1) * suite.scalarBytes()];

        assertThrows(IllegalArgumentException.class, () -> new BbsProof(oversized, suite));
    }

    @Test
    void presentationCborRoundTrips() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("abcdefghijklmnopqrstuvwxyz123456"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("status:active"), bytes("role:member"));
        byte[] header = bytes("credential-v1");
        byte[] presentationHeader = bytes("session");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, presentationHeader, new int[]{1});

        byte[] cbor = BbsPresentationCodec.encode(presentation);
        BbsPresentation decoded = BbsPresentationCodec.decode(cbor);

        assertEquals(presentation.proof(), decoded.proof());
        assertArrayEquals(presentation.header(), decoded.header());
        assertArrayEquals(presentation.presentationHeader(), decoded.presentationHeader());
        assertEquals(presentation.revealedMessages(), decoded.revealedMessages());
        assertArrayEquals(cbor, BbsPresentationCodec.encode(decoded));
        assertTrue(service.verifyPresentation(keyPair.publicKey(), decoded));
    }

    @Test
    void specOrderSignAndVerifyOverloadsWork() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("abcdefghijklmnopqrstuvwxyzabcdef"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("status:active"), bytes("role:member"));
        byte[] header = bytes("credential-v1");

        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), header, messages);

        assertTrue(service.verify(keyPair.publicKey(), signature, header, messages));
    }

    @Test
    void verifyRejectsTamperedSignatureWrongPublicKeyAndModifiedMessage() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789ij"), bytes("issuer-key"));
        BbsKeyPair wrongKeyPair = service.keyPair(bytes("012345678901234567890123456789kl"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        byte[] tamperedSignatureBytes = signature.bytes();
        tamperedSignatureBytes[tamperedSignatureBytes.length - 1] ^= 0x01;

        assertFalse(service.verify(
                keyPair.publicKey(),
                new BbsSignature(tamperedSignatureBytes, BbsCiphersuite.BLS12381_SHA256),
                messages,
                header));
        assertFalse(service.verify(wrongKeyPair.publicKey(), signature, messages, header));
        assertFalse(service.verify(
                keyPair.publicKey(),
                signature,
                List.of(bytes("given:Alice"), bytes("family:Changed")),
                header));
    }

    @Test
    void presentationIndexValidationRejectsInvalidServiceInputs() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789mn"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);

        assertThrows(BbsException.class, () -> service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("nonce"), new int[]{2}));
        assertThrows(BbsException.class, () -> service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("nonce"), new int[]{0, 0}));

        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("nonce"), new int[]{0});
        BbsPresentation duplicateRevealed = new BbsPresentation(
                presentation.proof(),
                presentation.header(),
                presentation.presentationHeader(),
                List.of(new BbsRevealedMessage(0, messages.get(0)), new BbsRevealedMessage(0, messages.get(0))));

        assertThrows(BbsException.class, () -> service.verifyPresentation(keyPair.publicKey(), duplicateRevealed));
    }

    @Test
    void presentationCodecRejectsMalformedNonCanonicalAndDuplicateIndexCbor() throws Exception {
        BbsPresentation presentation = samplePresentation();

        assertThrows(BbsException.class, () -> BbsPresentationCodec.decode(new byte[]{0}));
        assertThrows(BbsException.class, () -> BbsPresentationCodec.decode(envelope(presentation, 2, false, false)));
        assertThrows(BbsException.class, () -> BbsPresentationCodec.decode(envelope(presentation, 1, true, false)));
        assertThrows(BbsException.class, () -> BbsPresentationCodec.decode(envelope(presentation, 1, false, true)));
    }

    @Test
    void presentationCodecAppliesFieldLengthCaps() {
        BbsPresentation presentation = samplePresentation();
        byte[] oversizedHeader = new byte[65_536];
        BbsPresentation oversized = new BbsPresentation(
                presentation.proof(),
                oversizedHeader,
                presentation.presentationHeader(),
                presentation.revealedMessages());

        assertThrows(BbsException.class, () -> BbsPresentationCodec.encode(oversized));
    }

    @Test
    void zkVerifierAcceptsPresentationEnvelope() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789ab"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"), bytes("age:20"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("verifier-nonce"), new int[]{0});

        ZkProofEnvelope envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-selective-disclosure"))
                .proofBytes(BbsPresentationCodec.encode(presentation))
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("issuer-key"))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT)
                .build();
        VerificationMaterial material = VerificationMaterial.of(
                keyPair.publicKey().bytes(),
                ProofSystemId.BBS,
                CurveId.BLS12_381,
                new CircuitId("bbs-selective-disclosure"));

        var result = new BbsZkVerifier(service).verify(envelope, material);

        assertTrue(result.proofValid(), result.message().orElse(""));
    }

    @Test
    void zkVerifierAcceptsShake256PresentationEnvelope() {
        BbsService service = BbsService.pureJava(BbsCiphersuite.BLS12381_SHAKE256);
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789cd"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"), bytes("age:20"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("verifier-nonce"), new int[]{0, 2});

        ZkProofEnvelope envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-selective-disclosure-shake"))
                .proofBytes(BbsPresentationCodec.encode(presentation))
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("issuer-key"))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT)
                .build();
        VerificationMaterial material = VerificationMaterial.of(
                keyPair.publicKey().bytes(),
                ProofSystemId.BBS,
                CurveId.BLS12_381,
                new CircuitId("bbs-selective-disclosure-shake"));

        var result = new BbsZkVerifier().verify(envelope, material);

        assertTrue(result.proofValid(), result.message().orElse(""));
    }

    @Test
    void zkVerifierEnforcesMaterialBindingAndClassifiesMalformedInput() throws Exception {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789ef"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("age:20"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("verifier-nonce"), new int[]{0});
        byte[] pkBytes = keyPair.publicKey().bytes();
        byte[] pkHash = java.security.MessageDigest.getInstance("SHA-256").digest(pkBytes);
        byte[] proofBytes = BbsPresentationCodec.encode(presentation);

        VerificationMaterial material = VerificationMaterial.of(
                pkBytes, ProofSystemId.BBS, CurveId.BLS12_381, new CircuitId("bbs-a"));
        BbsZkVerifier verifier = new BbsZkVerifier(service);

        // Matching ByHash succeeds
        ZkProofEnvelope matchingHash = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-a")).proofBytes(proofBytes)
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ByHash(pkHash))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT).build();
        assertTrue(verifier.verify(matchingHash, material).proofValid());

        // Mismatched circuitId -> VK_MISMATCH
        ZkProofEnvelope wrongCircuit = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-other")).proofBytes(proofBytes)
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ByHash(pkHash))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT).build();
        assertEquals(org.zeroj.api.VerificationResult.ReasonCode.VK_MISMATCH,
                verifier.verify(wrongCircuit, material).reasonCode().orElse(null));

        // Mismatched ByHash -> VK_MISMATCH
        ZkProofEnvelope wrongHash = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-a")).proofBytes(proofBytes)
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ByHash(new byte[32]))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT).build();
        assertEquals(org.zeroj.api.VerificationResult.ReasonCode.VK_MISMATCH,
                verifier.verify(wrongHash, material).reasonCode().orElse(null));

        // Malformed CBOR presentation -> MALFORMED_ENVELOPE (not INTERNAL_ERROR)
        ZkProofEnvelope malformedCbor = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-a")).proofBytes(new byte[]{0x01, 0x02, 0x03})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ByHash(pkHash))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT).build();
        assertEquals(org.zeroj.api.VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                verifier.verify(malformedCbor, material).reasonCode().orElse(null));

        // Non-empty publicInputs vector must be rejected on both direct and orchestrated BBS calls
        ZkProofEnvelope nonEmptyPublicInputs = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-a")).proofBytes(proofBytes)
                .publicInputs(new PublicInputs(List.of(java.math.BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ByHash(pkHash))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT).build();
        assertEquals(org.zeroj.api.VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                verifier.verify(nonEmptyPublicInputs, material).reasonCode().orElse(null));

        var registry = org.zeroj.verifier.core.VerifierRegistry.empty();
        registry.register(verifier);
        var vkRegistry = new org.zeroj.backend.spi.InMemoryVerificationKeyRegistry();
        vkRegistry.register(material);
        var orchestrator = new org.zeroj.verifier.core.VerifierOrchestrator(registry, vkRegistry);
        assertTrue(orchestrator.verify(matchingHash).proofValid());
        assertEquals(org.zeroj.api.VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                orchestrator.verify(nonEmptyPublicInputs).reasonCode().orElse(null));
    }

    @Test
    void signingAndProofGenerationUseSecretScalarProviderBoundary() {
        var bls = new CountingBlsProvider(Bls12381Providers.pureJava());
        var provider = new PureJavaBbsProvider(BbsCiphersuite.BLS12381_SHA256, bls);
        BbsService service = new BbsService(provider, new SecureRandom(new byte[]{1, 2, 3, 4}));
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789ef"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"), bytes("age:20"));

        assertTrue(bls.g2SecretScalarMulCalls > 0, "SkToPk must use the secret G2 scalar boundary");

        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, bytes("credential-v1"));
        assertTrue(bls.g1SecretScalarMulCalls > 0, "Sign must use the secret G1 scalar boundary");
        int afterSignSecretCalls = bls.g1SecretScalarMulCalls;

        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, bytes("credential-v1"), bytes("verifier-nonce"), new int[]{0});

        assertTrue(bls.g1SecretScalarMulCalls > afterSignSecretCalls,
                "ProofGen must use the secret G1 scalar boundary");
        assertTrue(service.verifyPresentation(keyPair.publicKey(), presentation));
    }

    @Test
    void serviceFactoryAcceptsExplicitBlsProvider() {
        var bls = new CountingBlsProvider(Bls12381Providers.pureJava());
        BbsService service = BbsService.withBlsProvider(BbsCiphersuite.BLS12381_SHAKE256, bls);

        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789gh"), bytes("issuer-key"));

        assertEquals(BbsCiphersuite.BLS12381_SHAKE256, service.provider().ciphersuite());
        assertEquals(BbsCiphersuite.BLS12381_SHAKE256, keyPair.publicKey().ciphersuite());
        assertTrue(bls.g2SecretScalarMulCalls > 0, "Selected BLS provider must be used for SkToPk");
    }

    @Test
    void octetsToProofAndVerifyPresentationRejectZeroAndOutOfRangeScalarsInEverySlot() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789qr"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"), bytes("age:20"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("nonce"), new int[]{0});

        BbsCiphersuite suite = BbsCiphersuite.BLS12381_SHA256;
        byte[] validProofBytes = presentation.proof().bytes();
        int pointSection = 3 * suite.g1Bytes();
        int scalarCount = (validProofBytes.length - pointSection) / suite.scalarBytes();
        assertEquals(6, scalarCount, "eHat, r1Hat, r3Hat, 2 hidden mHats, challenge");

        byte[] modulusBytes = new byte[32];
        byte[] rRaw = G1Point.R.toByteArray();
        System.arraycopy(rRaw, Math.max(0, rRaw.length - 32), modulusBytes,
                32 - Math.min(32, rRaw.length), Math.min(32, rRaw.length));

        for (int slot = 0; slot < scalarCount; slot++) {
            int offset = pointSection + slot * suite.scalarBytes();

            // Draft-10 §4.2.4.5 step 14: scalar == 0 must be rejected.
            byte[] zeroScalarProof = validProofBytes.clone();
            Arrays.fill(zeroScalarProof, offset, offset + suite.scalarBytes(), (byte) 0);
            int slotIndex = slot;
            assertThrows(IllegalArgumentException.class,
                    () -> BbsCodec.octetsToProof(zeroScalarProof, suite),
                    "octetsToProof must reject zero scalar at slot " + slotIndex);
            BbsPresentation zeroPres = new BbsPresentation(
                    new BbsProof(zeroScalarProof, suite),
                    presentation.header(),
                    presentation.presentationHeader(),
                    presentation.revealedMessages());
            assertFalse(service.verifyPresentation(keyPair.publicKey(), zeroPres),
                    "verifyPresentation must reject zero scalar at slot " + slotIndex);

            // Draft-10 §4.2.4.5 step 14: scalar >= r must be rejected.
            byte[] rScalarProof = validProofBytes.clone();
            System.arraycopy(modulusBytes, 0, rScalarProof, offset, suite.scalarBytes());
            assertThrows(IllegalArgumentException.class,
                    () -> BbsCodec.octetsToProof(rScalarProof, suite),
                    "octetsToProof must reject scalar == r at slot " + slotIndex);
        }
    }

    @Test
    void proofPartsAndProofToOctetsRejectZeroAndOutOfRangeScalarsInEverySlot() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789st"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"), bytes("age:20"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(), signature, messages, header, bytes("nonce"), new int[]{0});

        BbsCodec.ProofParts valid = BbsCodec.octetsToProof(
                presentation.proof().bytes(), BbsCiphersuite.BLS12381_SHA256);
        assertEquals(2, valid.mHats().size());
        assertArrayEquals(presentation.proof().bytes(), BbsCodec.proofToOctets(valid));

        BigInteger[] invalidScalars = {BigInteger.ZERO, BigInteger.ONE.negate(), G1Point.R, G1Point.R.add(BigInteger.ONE)};
        for (BigInteger bad : invalidScalars) {
            assertThrows(IllegalArgumentException.class, () -> new BbsCodec.ProofParts(
                    valid.aBar(), valid.bBar(), valid.d(),
                    bad, valid.r1Hat(), valid.r3Hat(), valid.mHats(), valid.challenge()),
                    "ProofParts must reject invalid eHat=" + bad);
            assertThrows(IllegalArgumentException.class, () -> new BbsCodec.ProofParts(
                    valid.aBar(), valid.bBar(), valid.d(),
                    valid.eHat(), bad, valid.r3Hat(), valid.mHats(), valid.challenge()),
                    "ProofParts must reject invalid r1Hat=" + bad);
            assertThrows(IllegalArgumentException.class, () -> new BbsCodec.ProofParts(
                    valid.aBar(), valid.bBar(), valid.d(),
                    valid.eHat(), valid.r1Hat(), bad, valid.mHats(), valid.challenge()),
                    "ProofParts must reject invalid r3Hat=" + bad);
            for (int i = 0; i < valid.mHats().size(); i++) {
                List<BigInteger> badMHats = new ArrayList<>(valid.mHats());
                badMHats.set(i, bad);
                int idx = i;
                assertThrows(IllegalArgumentException.class, () -> new BbsCodec.ProofParts(
                        valid.aBar(), valid.bBar(), valid.d(),
                        valid.eHat(), valid.r1Hat(), valid.r3Hat(), badMHats, valid.challenge()),
                        "ProofParts must reject invalid mHat[" + idx + "]=" + bad);
            }
            assertThrows(IllegalArgumentException.class, () -> new BbsCodec.ProofParts(
                    valid.aBar(), valid.bBar(), valid.d(),
                    valid.eHat(), valid.r1Hat(), valid.r3Hat(), valid.mHats(), bad),
                    "ProofParts must reject invalid challenge=" + bad);
        }
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static BbsPresentation samplePresentation() {
        BbsService service = BbsService.pureJava();
        BbsKeyPair keyPair = service.keyPair(bytes("012345678901234567890123456789op"), bytes("issuer-key"));
        List<byte[]> messages = List.of(bytes("given:Alice"), bytes("family:Liddell"), bytes("age:20"));
        byte[] header = bytes("credential-v1");
        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        return service.derivePresentation(keyPair.publicKey(), signature, messages, header, bytes("nonce"), new int[]{0, 2});
    }

    private static byte[] envelope(
            BbsPresentation presentation,
            int version,
            boolean reversedKeys,
            boolean duplicateRevealedIndex) throws CborException {
        co.nstant.in.cbor.model.Array revealed = new co.nstant.in.cbor.model.Array();
        for (BbsRevealedMessage message : presentation.revealedMessages()) {
            co.nstant.in.cbor.model.Array pair = new co.nstant.in.cbor.model.Array();
            pair.add(new UnsignedInteger(duplicateRevealedIndex ? 0 : message.index()));
            pair.add(new ByteString(message.message()));
            revealed.add(pair);
        }

        co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
        if (reversedKeys) {
            map.put(new UnsignedInteger(6), revealed);
            map.put(new UnsignedInteger(5), new ByteString(presentation.presentationHeader()));
            map.put(new UnsignedInteger(4), new ByteString(presentation.header()));
            map.put(new UnsignedInteger(3), new ByteString(presentation.proof().bytes()));
            map.put(new UnsignedInteger(2), new UnicodeString(presentation.proof().ciphersuite().ciphersuiteId()));
            map.put(new UnsignedInteger(1), new UnsignedInteger(version));
        } else {
            map.put(new UnsignedInteger(1), new UnsignedInteger(version));
            map.put(new UnsignedInteger(2), new UnicodeString(presentation.proof().ciphersuite().ciphersuiteId()));
            map.put(new UnsignedInteger(3), new ByteString(presentation.proof().bytes()));
            map.put(new UnsignedInteger(4), new ByteString(presentation.header()));
            map.put(new UnsignedInteger(5), new ByteString(presentation.presentationHeader()));
            map.put(new UnsignedInteger(6), revealed);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CborEncoder encoder = new CborEncoder(baos);
        if (reversedKeys) {
            encoder.nonCanonical();
        }
        encoder.encode(new CborBuilder().add(map).build());
        return baos.toByteArray();
    }

    private static final class CountingBlsProvider implements Bls12381Provider {
        private final Bls12381Provider delegate;
        private int g1SecretScalarMulCalls;
        private int g2SecretScalarMulCalls;

        private CountingBlsProvider(Bls12381Provider delegate) {
            this.delegate = delegate;
        }

        @Override
        public String id() {
            return "counting-" + delegate.id();
        }

        @Override
        public G1Point g1Generator() {
            return delegate.g1Generator();
        }

        @Override
        public G2Point g2Generator() {
            return delegate.g2Generator();
        }

        @Override
        public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
            return delegate.g1ScalarMul(point, scalar);
        }

        @Override
        public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
            return delegate.g2ScalarMul(point, scalar);
        }

        @Override
        public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
            g1SecretScalarMulCalls++;
            return delegate.g1SecretScalarMul(point, scalar);
        }

        @Override
        public G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
            g2SecretScalarMulCalls++;
            return delegate.g2SecretScalarMul(point, scalar);
        }

        @Override
        public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
            return delegate.pairingProductIsIdentity(g1Points, g2Points);
        }
    }
}
