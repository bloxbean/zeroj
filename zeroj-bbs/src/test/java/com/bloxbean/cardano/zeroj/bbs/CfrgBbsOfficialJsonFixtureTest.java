package com.bloxbean.cardano.zeroj.bbs;

import com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProviders;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class CfrgBbsOfficialJsonFixtureTest {
    private static final List<SuiteFixture> SUITES = List.of(
            new SuiteFixture("/cfrg-bbs/draft10/official/bls12-381-sha-256", BbsCiphersuite.BLS12381_SHA256),
            new SuiteFixture("/cfrg-bbs/draft10/official/bls12-381-shake-256", BbsCiphersuite.BLS12381_SHAKE256));
    private static final ObjectMapper JSON = new ObjectMapper();

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    void officialKeyPairFixtureMatches(SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/keypair.json");
        var provider = BbsProviders.pureJava(suite.ciphersuite());

        BbsSecretKey secretKey = provider.keyGen(hex(fixture, "keyMaterial"), hex(fixture, "keyInfo"));
        BbsPublicKey publicKey = provider.skToPk(secretKey);

        assertArrayEquals(hex(fixture.at("/keyPair/secretKey")), secretKey.toBytes());
        assertArrayEquals(hex(fixture.at("/keyPair/publicKey")), publicKey.bytes());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    void officialMapMessageToScalarFixtureMatches(SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/MapMessageToScalarAsHash.json");
        for (JsonNode c : fixture.get("cases")) {
            BigInteger scalar = CfrgBbsCore.messagesToScalars(List.of(hex(c, "message")), suite.ciphersuite()).getFirst();

            assertArrayEquals(hex(c, "scalar"), BbsCodec.scalarToBytesAllowZero(scalar));
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    void officialGeneratorFixtureMatches(SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/generators.json");
        var generators = CfrgBbsCore.createGenerators(11, suite.ciphersuite(), Bls12381Providers.pureJava());

        assertArrayEquals(hex(fixture, "P1"), Bls12381Codecs.g1ToCompressed(suite.ciphersuite().p1()));
        assertArrayEquals(hex(fixture, "Q1"), Bls12381Codecs.g1ToCompressed(generators.q1()));
        for (int i = 0; i < fixture.get("MsgGenerators").size(); i++) {
            assertArrayEquals(hex(fixture.get("MsgGenerators").get(i)),
                    Bls12381Codecs.g1ToCompressed(generators.h().get(i)));
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    void officialHashToScalarFixtureMatches(SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/h2s.json");
        BigInteger scalar = CfrgBbsCore.hashToScalar(hex(fixture, "message"), hex(fixture, "dst"), suite.ciphersuite());

        assertArrayEquals(hex(fixture, "scalar"), BbsCodec.scalarToBytesAllowZero(scalar));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    void officialMockedRngFixtureMatches(SuiteFixture suite) {
        JsonNode fixture = read(suite.resourceBase() + "/mockedRng.json");
        List<BigInteger> scalars = CfrgBbsCore.seededRandomScalars(
                hex(fixture, "seed"), hex(fixture, "dst"), fixture.get("count").asInt(), suite.ciphersuite());

        assertEquals(fixture.get("mockedScalars").size(), scalars.size());
        for (int i = 0; i < scalars.size(); i++) {
            assertArrayEquals(hex(fixture.get("mockedScalars").get(i)), BbsCodec.scalarToBytesAllowZero(scalars.get(i)));
        }
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("signatureFixtures")
    void officialSignatureFixturesVerifyAndValidCasesSign(SuiteFixture suite, String resource) {
        JsonNode fixture = read(resource);
        var provider = BbsProviders.pureJava(suite.ciphersuite());
        BbsSecretKey secretKey = new BbsSecretKey(new BigInteger(1, hex(fixture.at("/signerKeyPair/secretKey"))), suite.ciphersuite());
        BbsPublicKey publicKey = new BbsPublicKey(hex(fixture.at("/signerKeyPair/publicKey")), suite.ciphersuite());
        BbsSignature signature = new BbsSignature(hex(fixture, "signature"), suite.ciphersuite());
        List<byte[]> messages = byteArrayList(fixture.get("messages"));
        byte[] header = hex(fixture, "header");
        boolean expected = fixture.at("/result/valid").asBoolean();

        assertEquals(expected, provider.verify(publicKey, signature, messages, header), fixture.get("caseName").asText());

        if (expected) {
            BbsSignature generated = provider.sign(secretKey, publicKey, messages, header);
            assertArrayEquals(signature.bytes(), generated.bytes());
            assertSignatureTrace(fixture, publicKey.bytes(), messages, header, suite.ciphersuite());
        }
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("proofFixtures")
    void officialProofFixturesVerifyAndValidCasesGenerate(SuiteFixture suite, String resource) {
        JsonNode fixture = read(resource);
        byte[] publicKey = hex(fixture, "signerPublicKey");
        byte[] proof = hex(fixture, "proof");
        byte[] header = hex(fixture, "header");
        byte[] presentationHeader = hex(fixture, "presentationHeader");
        List<byte[]> messages = byteArrayList(fixture.get("messages"));
        int[] disclosedIndexes = intArray(fixture.get("disclosedIndexes"));
        List<byte[]> disclosedMessages = select(messages, disclosedIndexes);
        boolean expected = fixture.at("/result/valid").asBoolean();

        assertEquals(expected, CfrgBbsCore.proofVerify(
                publicKey,
                proof,
                header,
                presentationHeader,
                disclosedMessages,
                disclosedIndexes,
                suite.ciphersuite(),
                Bls12381Providers.pureJava()), fixture.get("caseName").asText());

        if (expected) {
            byte[] generated = CfrgBbsCore.proofGenWithRandomScalars(
                    publicKey,
                    hex(fixture, "signature"),
                    messages,
                    header,
                    presentationHeader,
                    disclosedIndexes,
                    suite.ciphersuite(),
                    Bls12381Providers.pureJava(),
                    proofRandomScalars(fixture.at("/trace/random_scalars")));
            assertArrayEquals(proof, generated);
        }
    }

    private static void assertSignatureTrace(
            JsonNode fixture,
            byte[] publicKey,
            List<byte[]> messages,
            byte[] header,
            BbsCiphersuite ciphersuite) {
        List<BigInteger> scalars = CfrgBbsCore.messagesToScalars(messages, ciphersuite);
        var generators = CfrgBbsCore.createGenerators(scalars.size() + 1, ciphersuite, Bls12381Providers.pureJava());
        BigInteger domain = CfrgBbsCore.calculateDomain(publicKey, generators, header, ciphersuite);

        assertArrayEquals(hex(fixture.at("/trace/domain")), BbsCodec.scalarToBytesAllowZero(domain));
        assertArrayEquals(hex(fixture.at("/trace/B")),
                Bls12381Codecs.g1ToCompressed(CfrgBbsCore.calculateB(generators, domain, scalars, ciphersuite)));
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
        try (var in = CfrgBbsOfficialJsonFixtureTest.class.getResourceAsStream(resource)) {
            assertNotNull(in, "Missing fixture resource: " + resource);
            return JSON.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read fixture resource: " + resource, e);
        }
    }

    private static Stream<SuiteFixture> suites() {
        return SUITES.stream();
    }

    private static Stream<Arguments> signatureFixtures() {
        return SUITES.stream()
                .flatMap(suite -> IntStream.rangeClosed(1, 10)
                        .mapToObj(i -> Arguments.of(suite, suite.resourceBase() + "/signature/signature%03d.json".formatted(i))));
    }

    private static Stream<Arguments> proofFixtures() {
        return SUITES.stream()
                .flatMap(suite -> IntStream.rangeClosed(1, 15)
                        .mapToObj(i -> Arguments.of(suite, suite.resourceBase() + "/proof/proof%03d.json".formatted(i))));
    }

    private record SuiteFixture(String resourceBase, BbsCiphersuite ciphersuite) {
        @Override
        public String toString() {
            return ciphersuite.name();
        }
    }
}
