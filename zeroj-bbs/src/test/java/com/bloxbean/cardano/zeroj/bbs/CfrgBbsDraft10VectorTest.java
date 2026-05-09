package com.bloxbean.cardano.zeroj.bbs;

import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProviders;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class CfrgBbsDraft10VectorTest {
    private static final BbsCiphersuite SUITE = BbsCiphersuite.BLS12381_SHA256;
    private static final Properties VECTORS = loadVectors();

    @Test
    void keyGenAndSkToPk_matchDraft10Vector() {
        var provider = BbsProviders.pureJava();

        BbsSecretKey secretKey = provider.keyGen(hex("key_material"), hex("key_info"));
        BbsPublicKey publicKey = provider.skToPk(secretKey);

        assertArrayEquals(hex("sk"), secretKey.toBytes());
        assertArrayEquals(hex("pk"), publicKey.bytes());
    }

    @Test
    void messagesToScalars_matchDraft10Vector() {
        List<byte[]> messages = messages();
        List<BigInteger> actual = CfrgBbsCore.messagesToScalars(messages, SUITE);
        List<String> expected = csv("message_scalars");

        assertEquals(expected.size(), actual.size());
        for (int i = 0; i < expected.size(); i++) {
            assertArrayEquals(hexString(expected.get(i)), com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec.scalarToBytesAllowZero(actual.get(i)));
        }
    }

    @Test
    void generators_matchDraft10Vector() {
        var generators = CfrgBbsCore.createGenerators(11, SUITE, Bls12381Providers.pureJava());
        List<String> expected = csv("generators");

        assertArrayEquals(hexString(expected.get(0)), Bls12381Codecs.g1ToCompressed(generators.q1()));
        for (int i = 0; i < generators.h().size(); i++) {
            assertArrayEquals(hexString(expected.get(i + 1)), Bls12381Codecs.g1ToCompressed(generators.h().get(i)));
        }
    }

    @Test
    void signAndVerify_matchDraft10SingleMessageVector() {
        var provider = BbsProviders.pureJava();
        BbsSecretKey secretKey = new BbsSecretKey(new BigInteger(1, hex("sk")), SUITE);
        BbsPublicKey publicKey = new BbsPublicKey(hex("pk"), SUITE);
        List<byte[]> oneMessage = messages().subList(0, 1);

        BbsSignature signature = provider.sign(secretKey, publicKey, oneMessage, hex("header"));

        assertArrayEquals(hex("single_message_signature"), signature.bytes());
        assertTrue(provider.verify(publicKey, signature, oneMessage, hex("header")));
        assertFalse(provider.verify(publicKey, tamper(signature), oneMessage, hex("header")));
        assertFalse(provider.verify(publicKey, signature, oneMessage, hexString("00")));
    }

    @Test
    void signAndVerify_matchDraft10MultiMessageVector() {
        var provider = BbsProviders.pureJava();
        BbsSecretKey secretKey = new BbsSecretKey(new BigInteger(1, hex("sk")), SUITE);
        BbsPublicKey publicKey = new BbsPublicKey(hex("pk"), SUITE);
        List<byte[]> messages = messages();

        BbsSignature signature = provider.sign(secretKey, publicKey, messages, hex("header"));

        assertArrayEquals(hex("multi_message_signature"), signature.bytes());
        assertTrue(provider.verify(publicKey, signature, messages, hex("header")));
        assertFalse(provider.verify(publicKey, signature, replace(messages, 2, hexString("01")), hex("header")));
    }

    @Test
    void seededRandomScalars_matchDraft10MockVector() {
        List<BigInteger> scalars = CfrgBbsCore.seededRandomScalars(hex("mock_seed"), hex("mock_dst"), 10, SUITE);
        List<String> expected = csv("mock_scalars");

        assertEquals(expected.size(), scalars.size());
        for (int i = 0; i < expected.size(); i++) {
            assertArrayEquals(hexString(expected.get(i)), com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec.scalarToBytesAllowZero(scalars.get(i)));
        }
    }

    @Test
    void proofGenAndVerify_matchDraft10SingleMessageProofVector() {
        List<BigInteger> randomScalars = csv("single_proof_random_scalars").stream()
                .map(hex -> new BigInteger(1, hexString(hex)))
                .toList();
        byte[] proof = CfrgBbsCore.proofGenWithRandomScalars(
                hex("pk"),
                hex("single_message_signature"),
                messages().subList(0, 1),
                hex("header"),
                hex("presentation_header"),
                new int[]{0},
                SUITE,
                Bls12381Providers.pureJava(),
                randomScalars);

        assertArrayEquals(hex("single_proof"), proof);
        assertTrue(CfrgBbsCore.proofVerify(
                hex("pk"),
                proof,
                hex("header"),
                hex("presentation_header"),
                messages().subList(0, 1),
                new int[]{0},
                SUITE,
                Bls12381Providers.pureJava()));
    }

    @Test
    void proofGenAndVerify_matchDraft10AllDisclosedProofVector() {
        List<byte[]> messages = messages();
        int[] allIndexes = java.util.stream.IntStream.range(0, messages.size()).toArray();
        List<BigInteger> randomScalars = CfrgBbsCore.seededRandomScalars(hex("mock_seed"), hex("mock_dst"), 5, SUITE);

        byte[] proof = CfrgBbsCore.proofGenWithRandomScalars(
                hex("pk"),
                hex("multi_message_signature"),
                messages,
                hex("header"),
                hex("presentation_header"),
                allIndexes,
                SUITE,
                Bls12381Providers.pureJava(),
                randomScalars);

        assertArrayEquals(hex("all_disclosed_proof"), proof);
        assertTrue(CfrgBbsCore.proofVerify(
                hex("pk"),
                proof,
                hex("header"),
                hex("presentation_header"),
                messages,
                allIndexes,
                SUITE,
                Bls12381Providers.pureJava()));
    }

    @Test
    void proofGenAndVerify_matchDraft10SomeDisclosedProofVector() {
        List<byte[]> messages = messages();
        int[] disclosedIndexes = {0, 2, 4, 6};
        List<byte[]> disclosedMessages = Arrays.stream(disclosedIndexes)
                .mapToObj(messages::get)
                .toList();
        List<BigInteger> randomScalars = CfrgBbsCore.seededRandomScalars(hex("mock_seed"), hex("mock_dst"), 11, SUITE);

        byte[] proof = CfrgBbsCore.proofGenWithRandomScalars(
                hex("pk"),
                hex("multi_message_signature"),
                messages,
                hex("header"),
                hex("presentation_header"),
                disclosedIndexes,
                SUITE,
                Bls12381Providers.pureJava(),
                randomScalars);

        assertArrayEquals(hex("some_disclosed_proof"), proof);
        assertTrue(CfrgBbsCore.proofVerify(
                hex("pk"),
                proof,
                hex("header"),
                hex("presentation_header"),
                disclosedMessages,
                disclosedIndexes,
                SUITE,
                Bls12381Providers.pureJava()));
        assertFalse(CfrgBbsCore.proofVerify(
                hex("pk"),
                proof,
                hex("header"),
                hexString("00"),
                disclosedMessages,
                disclosedIndexes,
                SUITE,
                Bls12381Providers.pureJava()));
    }

    @Test
    void invalidDisclosedIndexesReject() {
        var provider = BbsProviders.pureJava();
        BbsPublicKey publicKey = new BbsPublicKey(hex("pk"), SUITE);
        BbsSignature signature = new BbsSignature(hex("multi_message_signature"), SUITE);
        List<byte[]> messages = messages();

        assertThrows(IllegalArgumentException.class,
                () -> provider.proofGen(publicKey, signature, messages, hex("header"), new byte[0], new int[]{2, 2}, new java.security.SecureRandom()));
        assertThrows(IllegalArgumentException.class,
                () -> provider.proofGen(publicKey, signature, messages, hex("header"), new byte[0], new int[]{3, 1}, new java.security.SecureRandom()));
        assertFalse(provider.proofVerify(publicKey, new BbsProof(hex("some_disclosed_proof"), SUITE),
                hex("header"), hex("presentation_header"), List.of(messages.get(0), messages.get(2)), new int[]{0, 0}));
    }

    private static BbsSignature tamper(BbsSignature signature) {
        byte[] bytes = signature.bytes();
        bytes[bytes.length - 1] ^= 1;
        return new BbsSignature(bytes, signature.ciphersuite());
    }

    private static List<byte[]> replace(List<byte[]> messages, int index, byte[] replacement) {
        java.util.ArrayList<byte[]> copy = new java.util.ArrayList<>(messages);
        copy.set(index, replacement);
        return List.copyOf(copy);
    }

    private static List<byte[]> messages() {
        return csv("messages").stream().map(CfrgBbsDraft10VectorTest::hexString).toList();
    }

    private static byte[] hex(String property) {
        return hexString(VECTORS.getProperty(property));
    }

    private static byte[] hexString(String hex) {
        if (hex.isEmpty()) {
            return new byte[0];
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static List<String> csv(String property) {
        return Arrays.asList(VECTORS.getProperty(property).split(",", -1));
    }

    private static Properties loadVectors() {
        try (var in = CfrgBbsDraft10VectorTest.class.getResourceAsStream("/cfrg-bbs/draft10/sha256.properties")) {
            Properties properties = new Properties();
            properties.load(in);
            return properties;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to load CFRG BBS draft-10 vectors", e);
        }
    }
}
