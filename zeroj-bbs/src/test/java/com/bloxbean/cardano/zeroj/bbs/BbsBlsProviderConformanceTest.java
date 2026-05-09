package com.bloxbean.cardano.zeroj.bbs;

import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProvider;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProviders;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
import com.bloxbean.cardano.zeroj.bls12381.wasm.WasmBls12381Provider;
import com.bloxbean.cardano.zeroj.blst.BlstBls12381Provider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BbsBlsProviderConformanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final List<SuiteFixture> SUITES = List.of(
            new SuiteFixture("/cfrg-bbs/draft10/official/bls12-381-sha-256", BbsCiphersuite.BLS12381_SHA256),
            new SuiteFixture("/cfrg-bbs/draft10/official/bls12-381-shake-256", BbsCiphersuite.BLS12381_SHAKE256));

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("providerSuites")
    void selectedBlsProviderMatchesOfficialKeySignatureAndProofVectors(
            ProviderFixture providerFixture,
            SuiteFixture suite) {
        BbsProvider provider = BbsProviders.withBlsProvider(suite.ciphersuite(), providerFixture.bls());

        assertKeyPairFixture(provider, suite);
        assertSignatureFixture(provider, suite);
        assertProofFixture(providerFixture.bls(), provider, suite);
    }

    private static void assertKeyPairFixture(BbsProvider provider, SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/keypair.json");

        BbsSecretKey secretKey = provider.keyGen(hex(fixture, "keyMaterial"), hex(fixture, "keyInfo"));
        BbsPublicKey publicKey = provider.skToPk(secretKey);

        assertArrayEquals(hex(fixture.at("/keyPair/secretKey")), secretKey.toBytes());
        assertArrayEquals(hex(fixture.at("/keyPair/publicKey")), publicKey.bytes());
    }

    private static void assertSignatureFixture(BbsProvider provider, SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/signature/signature001.json");
        BbsSecretKey secretKey = new BbsSecretKey(
                new BigInteger(1, hex(fixture.at("/signerKeyPair/secretKey"))),
                suite.ciphersuite());
        BbsPublicKey publicKey = new BbsPublicKey(hex(fixture.at("/signerKeyPair/publicKey")), suite.ciphersuite());
        BbsSignature expected = new BbsSignature(hex(fixture, "signature"), suite.ciphersuite());
        List<byte[]> messages = byteArrayList(fixture.get("messages"));
        byte[] header = hex(fixture, "header");

        BbsSignature generated = provider.sign(secretKey, publicKey, messages, header);

        assertArrayEquals(expected.bytes(), generated.bytes());
        assertTrue(provider.verify(publicKey, expected, messages, header));
        assertTrue(provider.verify(publicKey, generated, messages, header));
    }

    private static void assertProofFixture(Bls12381Provider bls, BbsProvider provider, SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/proof/proof001.json");
        BbsPublicKey publicKey = new BbsPublicKey(hex(fixture, "signerPublicKey"), suite.ciphersuite());
        BbsProof expected = new BbsProof(hex(fixture, "proof"), suite.ciphersuite());
        byte[] header = hex(fixture, "header");
        byte[] presentationHeader = hex(fixture, "presentationHeader");
        List<byte[]> messages = byteArrayList(fixture.get("messages"));
        int[] disclosedIndexes = intArray(fixture.get("disclosedIndexes"));
        List<byte[]> disclosedMessages = select(messages, disclosedIndexes);

        assertTrue(provider.proofVerify(
                publicKey,
                expected,
                header,
                presentationHeader,
                disclosedMessages,
                disclosedIndexes));

        byte[] generated = CfrgBbsCore.proofGenWithRandomScalars(
                publicKey.bytes(),
                hex(fixture, "signature"),
                messages,
                header,
                presentationHeader,
                disclosedIndexes,
                suite.ciphersuite(),
                bls,
                proofRandomScalars(fixture.at("/trace/random_scalars")));
        assertArrayEquals(expected.bytes(), generated);
    }

    private static List<BigInteger> proofRandomScalars(JsonNode randomScalars) {
        List<BigInteger> out = new ArrayList<>();
        out.add(scalar(randomScalars, "r1"));
        out.add(scalar(randomScalars, "r2"));
        out.add(scalar(randomScalars, "e_tilde"));
        out.add(scalar(randomScalars, "r1_tilde"));
        out.add(scalar(randomScalars, "r3_tilde"));
        for (JsonNode mTilde : randomScalars.get("m_tilde_scalars")) {
            out.add(new BigInteger(1, hex(mTilde)));
        }
        return List.copyOf(out);
    }

    private static BigInteger scalar(JsonNode node, String fieldName) {
        return new BigInteger(1, hex(node, fieldName));
    }

    private static List<byte[]> select(List<byte[]> values, int[] indexes) {
        List<byte[]> out = new ArrayList<>(indexes.length);
        for (int index : indexes) {
            out.add(values.get(index));
        }
        return List.copyOf(out);
    }

    private static List<byte[]> byteArrayList(JsonNode array) {
        List<byte[]> out = new ArrayList<>();
        for (JsonNode item : array) {
            out.add(hex(item));
        }
        return List.copyOf(out);
    }

    private static int[] intArray(JsonNode array) {
        int[] out = new int[array.size()];
        for (int i = 0; i < array.size(); i++) {
            out[i] = array.get(i).asInt();
        }
        return out;
    }

    private static byte[] hex(JsonNode node, String fieldName) {
        return hex(node.get(fieldName));
    }

    private static byte[] hex(JsonNode node) {
        String hex = node.asText();
        if (hex.isEmpty()) {
            return new byte[0];
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static JsonNode read(String resource) {
        try (var in = BbsBlsProviderConformanceTest.class.getResourceAsStream(resource)) {
            assertNotNull(in, "Missing fixture resource: " + resource);
            return JSON.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read fixture resource: " + resource, e);
        }
    }

    private static Stream<Arguments> providerSuites() {
        List<ProviderFixture> providers = List.of(
                new ProviderFixture("pure-java", Bls12381Providers.pureJava()),
                new ProviderFixture("wasm-zkcrypto", WasmBls12381Provider.createDefault()),
                new ProviderFixture("blst", BlstBls12381Provider.createDefault()));
        return providers.stream()
                .flatMap(provider -> SUITES.stream().map(suite -> Arguments.of(provider, suite)));
    }

    private record ProviderFixture(String name, Bls12381Provider bls) {
        @Override
        public String toString() {
            return name;
        }
    }

    private record SuiteFixture(String resourceBase, BbsCiphersuite ciphersuite) {
        @Override
        public String toString() {
            return ciphersuite.name();
        }
    }
}
