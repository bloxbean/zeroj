package org.zeroj.onchain.julc.pedersen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M4 (I4, I10; {@code commitment-profiles-v1} §13.4): every on-chain-applicable case of the
 * independent G1 vector files, run through {@code PedersenG1Lib} in the Julc VM. A positive case must
 * succeed with exactly the expected point, scalar or verdict; a negative case must fail the script.
 * A negative whose class is a scalar or configuration check must fail before any scalar
 * multiplication, by exact builtin counts ({@link MarkedBuiltinCounts}).
 *
 * <p>Skipped and counted: operations with no on-chain counterpart (generation, opening and envelope
 * codecs), which the Java loaders run; and payloads longer than the 16,384-octet maximum transaction
 * size, which no transaction can carry (the Julc VM also refuses to build their 65,600-octet framed
 * input: "AppendByteString: ByteString overflow").
 */
class PedersenG1VectorsVmTest extends ContractTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String DIR = "/test-vectors/commitment-profiles-v1/";
    private static final Set<String> OFF_CHAIN_ONLY =
            Set.of("commit", "encodeOpening", "decodeOpening", "encodeEnvelope", "decodeEnvelope");
    private static final Set<String> GUARD_CLASSES =
            Set.of("NON_CANONICAL_SCALAR", "OUT_OF_RANGE", "INVALID_CONFIGURATION");
    private static final String IDENTITY_HEX = "c0" + "00".repeat(47);
    /** PV11 maximum transaction size: no on-chain payload can be longer. */
    private static final int MAX_TX_BYTES = 16_384;

    /** Cases executed per operation (positive/negative), so a skipped operation or emptied file fails. */
    private static final Map<String, String> EXPECTED_COUNTS = Map.of(
            "pedersen-bls12-381-g1-v1", "decodePoint 7/24 publicDelta 17/27 relation 12/5 verifyOpening 19/34",
            "pedersen-bls12-381-g1-bytes-v1", "decodePoint 5/24 hashToScalar 14/0 verifyOpening 4/21");

    private final Map<Class<?>, CompileResult> compiled = new HashMap<>();
    private MarkedBuiltinCounts.Counts lastCounts;

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pedersen-bls12-381-g1-v1", "pedersen-bls12-381-g1-bytes-v1"})
    @DisplayName("Every on-chain-applicable vector gives the expected outcome in the Julc VM")
    void vectors(String profileId) throws IOException {
        JsonNode file = load(profileId);
        assertEquals(profileId, file.get("profileId").asText());
        Map<String, int[]> counts = new TreeMap<>();
        List<String> failures = new ArrayList<>();
        int skipped = 0;
        int oversized = 0;
        for (String kind : List.of("positive", "negative")) {
            for (JsonNode c : file.get(kind)) {
                String op = c.get("operation").asText();
                if (OFF_CHAIN_ONLY.contains(op)) {
                    skipped++;
                    continue;
                }
                JsonNode payload = c.get("input").get("payload");
                if (payload != null && payload(payload).length > MAX_TX_BYTES) {
                    oversized++;
                    continue;
                }
                boolean positive = kind.equals("positive");
                String name = c.get("name").asText();
                EvalResult result = evaluate(profileId, op, c.get("input"), positive ? c.get("expected") : null);
                boolean expectSuccess = positive && !"false".equals(text(c.get("expected"), "result"));
                if (result.isSuccess() != expectSuccess) {
                    failures.add(name + ": expected " + (expectSuccess ? "success" : "failure") + ", got " + result);
                }
                if (!positive && GUARD_CLASSES.contains(c.get("error").asText())
                        && (lastCounts.scalarMul() != 0 || lastCounts.msm() != 0)) {
                    failures.add(name + ": " + c.get("error").asText() + " reached a scalar multiplication");
                }
                counts.computeIfAbsent(op, k -> new int[2])[positive ? 0 : 1]++;
            }
        }
        StringBuilder summary = new StringBuilder("[vectors] " + profileId + " (positive/negative):");
        counts.forEach((op, n) -> summary.append(' ').append(op).append(' ').append(n[0]).append('/').append(n[1]));
        System.out.println(summary + "; skipped off-chain-only " + skipped + ", payload > max tx size " + oversized);
        assertTrue(failures.isEmpty(), String.join("\n", failures));
        StringBuilder executed = new StringBuilder();
        counts.forEach((op, n) -> executed.append(executed.isEmpty() ? "" : " ").append(op).append(' ')
                .append(n[0]).append('/').append(n[1]));
        assertEquals(EXPECTED_COUNTS.get(profileId), executed.toString());
    }

    private EvalResult evaluate(String profileId, String op, JsonNode in, JsonNode expected) {
        boolean bytesProfile = profileId.endsWith("-bytes-v1");
        return switch (op) {
            case "decodePoint" -> run(PedersenG1DecodeProbe.class, bytes(in, "pointHex"));
            case "verifyOpening" -> bytesProfile
                    ? run(PedersenG1BytesProbe.class, bytes(in, "pointHex"), PlutusData.bytes(payload(in.get("payload"))),
                            integer(in, "blinding"))
                    : run(PedersenG1OpeningProbe.class, bytes(in, "pointHex"), integer(in, "value"), integer(in, "blinding"),
                            PlutusData.constr(in.has("amountBits") ? 1 : 0),
                            in.has("amountBits") ? integer(in, "amountBits") : PlutusData.integer(BigInteger.ZERO));
            case "relation" -> relation(in, expected);
            case "publicDelta" -> run(PedersenG1DeltaProbe.class, bytes(in, "pointHex"), integer(in, "delta"),
                    integer(in, "deltaBits"), expectedPoint(expected));
            case "hashToScalar" -> run(PedersenG1HashProbe.class, PlutusData.bytes(payload(in.get("payload"))),
                    PlutusData.integer(new BigInteger(expected.get("scalar").asText())));
            default -> throw new IllegalStateException("operation " + op + " is not mapped");
        };
    }

    private EvalResult relation(JsonNode in, JsonNode expected) {
        JsonNode points = in.get("pointsHex");
        String op = in.get("op").asText();
        int code = switch (op) {
            case "add" -> 0;
            case "subtract" -> 1;
            case "negate" -> 2;
            default -> throw new IllegalStateException("relation op " + op);
        };
        PlutusData a = PlutusData.bytes(HEX.parseHex(points.get(0).asText()));
        // negate takes one point; the probe still decodes its second argument, so pass the first again.
        PlutusData b = points.size() > 1 ? PlutusData.bytes(HEX.parseHex(points.get(1).asText())) : a;
        return run(PedersenG1SumProbe.class, a, b, PlutusData.integer(BigInteger.valueOf(code)), expectedPoint(expected));
    }

    /** The expected point of a positive case; a negative case compares with the identity, never reached. */
    private static PlutusData expectedPoint(JsonNode expected) {
        return PlutusData.bytes(HEX.parseHex(expected == null ? IDENTITY_HEX : expected.get("pointHex").asText()));
    }

    private EvalResult run(Class<?> probe, PlutusData... fields) {
        CompileResult result = compiled.computeIfAbsent(probe, p -> compileValidator(p, Path.of("src/test/java")));
        PlutusData ctx = spendingContext(TestDataBuilder.randomTxOutRef_typed(), PlutusData.integer(0))
                .redeemer(PlutusData.constr(0, fields)).buildPlutusData();
        EvalResult evaluated = evaluate(result.program(), ctx);
        lastCounts = MarkedBuiltinCounts.count(result, ctx, evaluated.isSuccess());
        return evaluated;
    }

    private static byte[] payload(JsonNode payload) {
        if (payload.has("hex")) {
            return HEX.parseHex(payload.get("hex").asText());
        }
        assertEquals("131i+17", payload.get("pattern").asText());
        int n = Integer.parseInt(payload.get("length").asText());
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) (131 * i + 17);
        }
        return out;
    }

    private static PlutusData bytes(JsonNode in, String field) {
        return PlutusData.bytes(HEX.parseHex(in.get(field).asText()));
    }

    private static PlutusData integer(JsonNode in, String field) {
        return PlutusData.integer(new BigInteger(in.get(field).asText()));
    }

    private static String text(JsonNode node, String field) {
        return node != null && node.has(field) ? node.get(field).asText() : null;
    }

    private static JsonNode load(String profileId) throws IOException {
        try (InputStream in = PedersenG1VectorsVmTest.class.getResourceAsStream(DIR + profileId + ".json")) {
            assertNotNull(in, profileId + ".json on the test classpath (zeroj-test-vectors)");
            return new ObjectMapper().readTree(in);
        }
    }
}
