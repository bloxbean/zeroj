package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * ADR-0061 M2, test fixture: runs the {@code zeroj-proof-vectors-v1} file of
 * {@code bulletproof-range-bls12-381-g1-v1} (spec §11) through a given prover, verifier and G1
 * Pedersen instance, so the pure-Java and blst providers run the same cases with the same code.
 *
 * <p>The file is written by {@code bulletproof-g1-reference/emit_bulletproof_vectors_v1.py}, ZeroJ's
 * independent Python implementation of the spec; nothing here derives an expected value from the
 * code under test. Before any case runs, the file is validated: strict JSON (no duplicate keys, no
 * trailing content), no JSON numbers, exactly the spec §11 fields, the expected identifiers, and the
 * 129 generator encodings equal to the pins this package uses. An invalid fixture rejects the whole
 * file with {@link IllegalStateException}.
 *
 * <ul>
 *   <li><b>Positive:</b> the commitment, the test-nonce proof (spec §7.5), acceptance by every
 *       verify overload, the session identifier and every challenge must all equal the file.</li>
 *   <li><b>Negative:</b> the verifier must give exactly {@code expected} (an error class or
 *       {@code false}) and stop at exactly {@code layer} (spec §8.1–§8.3).</li>
 *   <li><b>proverNegative:</b> the opening type or the prover must refuse with exactly
 *       {@code expected} (spec §7.1).</li>
 * </ul>
 *
 * <p>Test code only: this class is never published (zeroj-bls12381's test-fixtures variants are
 * removed from its Maven component).
 */
public final class BulletproofVectorRunner {

    /** Resource path of the vector file. */
    public static final String RESOURCE = "/test-vectors/commitment-profiles-v1/bulletproof-range-bls12-381-g1-v1.json";

    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();
    private static final HexFormat HEX = HexFormat.of();
    private static final Pattern HEX_STRING = Pattern.compile("([0-9a-f]{2})*");
    private static final Pattern DECIMAL = Pattern.compile("0|-?[1-9][0-9]*");

    private static final Set<String> TOP = Set.of("schema", "protocolId", "profileId", "generatorSetId",
            "generatorDigestHex", "generators", "spec", "generator", "positive", "negative", "proverNegative");
    private static final Set<String> POSITIVE = Set.of("id", "bits", "ctxHex", "value", "blinding", "commitmentHex",
            "nonceSeedHex", "sessionIdHex", "challenges", "proofHex");
    private static final Set<String> NEGATIVE = Set.of("id", "bits", "ctxHex", "commitmentHex", "proofHex", "expected",
            "layer");
    private static final Set<String> PROVER_NEGATIVE = Set.of("id", "bits", "ctxHex", "value", "blinding", "expected");
    private static final Set<String> CHALLENGES = Set.of("y", "z", "x", "xu", "xj");
    private static final Set<String> LAYERS = Set.of("configuration", "statement", "length", "point", "scalar",
            "challenge", "check1", "check2");

    private BulletproofVectorRunner() {
    }

    /** The outcome of a run: how many cases ran, which failed (with a reason), and each case's outcome. */
    public record Report(int executed, List<String> failures, Map<String, String> outcomes) {
    }

    /** Loads and validates the vector file from the test classpath. */
    public static JsonNode load() throws IOException {
        try (InputStream in = BulletproofVectorRunner.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(RESOURCE + " is not on the classpath");
            }
            JsonNode file = JSON.readTree(in.readAllBytes());
            validate(file);
            return file;
        }
    }

    /** Runs every case of a validated file. Never throws for a failing case; it is reported instead. */
    public static Report run(JsonNode file, G1RangeProver prover, G1RangeVerifier verifier, G1Pedersen pedersen) {
        Objects.requireNonNull(prover, "prover");
        Objects.requireNonNull(verifier, "verifier");
        Objects.requireNonNull(pedersen, "pedersen");
        validate(file);
        List<String> failures = new ArrayList<>();
        Map<String, String> outcomes = new LinkedHashMap<>();
        int executed = 0;
        for (JsonNode c : file.get("positive")) {
            executed++;
            record(c, outcomes, failures, () -> positive(c, prover, verifier, pedersen));
        }
        for (JsonNode c : file.get("negative")) {
            executed++;
            record(c, outcomes, failures, () -> negative(c, verifier));
        }
        for (JsonNode c : file.get("proverNegative")) {
            executed++;
            record(c, outcomes, failures, () -> proverNegative(c, prover));
        }
        return new Report(executed, failures, outcomes);
    }

    /**
     * ADR-0061 M3 determinism: the verifier's verdict and layer for every positive and negative case,
     * keyed by case id, in file order. Verification only (no proving), so a run is cheap enough to
     * repeat across runs, providers and JVMs.
     */
    public static Map<String, String> verdicts(JsonNode file, G1RangeVerifier verifier) {
        Objects.requireNonNull(verifier, "verifier");
        validate(file);
        Map<String, String> out = new LinkedHashMap<>();
        for (String section : List.of("positive", "negative")) {
            for (JsonNode c : file.get(section)) {
                int bits = Integer.parseInt(c.get("bits").asText());
                byte[] ctx = HEX.parseHex(c.get("ctxHex").asText());
                byte[] vWire = HEX.parseHex(c.get("commitmentHex").asText());
                byte[] wire = HEX.parseHex(c.get("proofHex").asText());
                String verdict;
                try {
                    verdict = String.valueOf(verifier.verify(vWire, wire, bits, ctx));
                } catch (CommitmentFormatException e) {
                    verdict = e.reason().name();
                }
                out.put(c.get("id").asText(), verdict + " @" + layer(verifier, vWire, wire, bits, ctx));
            }
        }
        return out;
    }

    private interface Case {
        String run() throws Exception;
    }

    private static void record(JsonNode c, Map<String, String> outcomes, List<String> failures, Case body) {
        String id = c.get("id").asText();
        try {
            outcomes.put(id, body.run());
        } catch (AssertionError | Exception e) {
            outcomes.put(id, "ERROR " + e);
            failures.add(id + ": " + e);
        }
    }

    // ---- cases ----

    private static String positive(JsonNode c, G1RangeProver prover, G1RangeVerifier verifier, G1Pedersen pedersen) {
        int bits = Integer.parseInt(c.get("bits").asText());
        byte[] ctx = HEX.parseHex(c.get("ctxHex").asText());
        BigInteger value = new BigInteger(c.get("value").asText());
        BigInteger blinding = new BigInteger(c.get("blinding").asText());
        G1PedersenOpening opening = G1PedersenOpening.of(value, blinding);
        G1PedersenCommitment commitment = pedersen.commitScalar(value, blinding);
        expect(c.get("commitmentHex").asText(), HEX.formatHex(commitment.toPointBytes()), "commitment");

        G1RangeProof proof = TestNonceProver.prove(prover, opening, bits, ctx, HEX.parseHex(c.get("nonceSeedHex").asText()));
        String proofHex = HEX.formatHex(proof.toBytes());
        expect(c.get("proofHex").asText(), proofHex, "proof");

        byte[] wire = HEX.parseHex(c.get("proofHex").asText());
        byte[] vWire = HEX.parseHex(c.get("commitmentHex").asText());
        G1PedersenCommitment decoded = G1PedersenCommitment.decode(vWire);
        expect("true", String.valueOf(verifier.verify(vWire, wire, bits, ctx)), "verify(octets, octets)");
        expect("true", String.valueOf(verifier.verify(decoded, wire, bits, ctx)), "verify(commitment, octets)");
        expect("true", String.valueOf(verifier.verify(decoded, G1RangeProof.decode(wire, bits), bits, ctx)),
                "verify(commitment, proof)");

        G1RangeVerifier.Outcome outcome = verifier.evaluate(PointCodec.point(decoded), G1RangeProof.decode(wire, bits), ctx);
        expect("ACCEPT", outcome.layer().name(), "layer");
        G1RangeVerifier.Challenges ch = outcome.challenges();
        expect(c.get("sessionIdHex").asText(), HEX.formatHex(ch.sessionId()), "session id");
        JsonNode want = c.get("challenges");
        expect(want.get("y").asText(), ch.y().toString(), "y");
        expect(want.get("z").asText(), ch.z().toString(), "z");
        expect(want.get("x").asText(), ch.x().toString(), "x");
        expect(want.get("xu").asText(), ch.xu().toString(), "xu");
        JsonNode xj = want.get("xj");
        expect(String.valueOf(xj.size()), String.valueOf(ch.xj().length), "xj count");
        for (int j = 0; j < xj.size(); j++) {
            expect(xj.get(j).asText(), ch.xj()[j].toString(), "x_" + (j + 1));
        }
        return "accept " + proofHex;
    }

    private static String negative(JsonNode c, G1RangeVerifier verifier) {
        int bits = Integer.parseInt(c.get("bits").asText());
        byte[] ctx = HEX.parseHex(c.get("ctxHex").asText());
        byte[] vWire = HEX.parseHex(c.get("commitmentHex").asText());
        byte[] wire = HEX.parseHex(c.get("proofHex").asText());

        // The public verdict.
        String verdict;
        try {
            verdict = String.valueOf(verifier.verify(vWire, wire, bits, ctx));
        } catch (CommitmentFormatException e) {
            verdict = e.reason().name();
        }
        expect(c.get("expected").asText(), verdict, "verdict");

        // The layer, stepping through spec §8.1–§8.3 with the same code the verifier uses.
        String layer = layer(verifier, vWire, wire, bits, ctx);
        expect(c.get("layer").asText(), layer, "layer");
        return verdict + " @" + layer;
    }

    private static String layer(G1RangeVerifier verifier, byte[] vWire, byte[] wire, int bits, byte[] ctx) {
        try {
            RangeTranscript.requireConfiguration(bits, ctx);
        } catch (CommitmentFormatException e) {
            return "configuration";
        }
        if (wire.length != G1RangeProof.length(bits)) {
            return "length";
        }
        G1RangeProof proof;
        try {
            proof = G1RangeProof.decode(wire, bits);
        } catch (CommitmentFormatException e) {
            return e.reason() == CommitmentError.NON_CANONICAL_SCALAR ? "scalar" : "point";
        }
        G1PedersenCommitment v;
        try {
            v = G1PedersenCommitment.decode(vWire);
        } catch (CommitmentFormatException e) {
            return "statement";
        }
        return switch (verifier.evaluate(PointCodec.point(v), proof, ctx).layer()) {
            case ACCEPT -> "accept";
            case STATEMENT -> "statement";
            case CHALLENGE -> "challenge";
            case CHECK1 -> "check1";
            case CHECK2 -> "check2";
        };
    }

    private static String proverNegative(JsonNode c, G1RangeProver prover) {
        int bits = Integer.parseInt(c.get("bits").asText());
        byte[] ctx = HEX.parseHex(c.get("ctxHex").asText());
        BigInteger value = new BigInteger(c.get("value").asText());
        BigInteger blinding = new BigInteger(c.get("blinding").asText());
        String refusal;
        try {
            // In Java the opening type itself enforces check 1 (spec §7.1 refusal 2).
            G1PedersenOpening opening = G1PedersenOpening.of(value, blinding);
            prover.prove(opening, bits, ctx);
            refusal = "proved";
        } catch (CommitmentFormatException e) {
            refusal = e.reason().name();
        }
        expect(c.get("expected").asText(), refusal, "refusal");
        return refusal;
    }

    private static void expect(String want, String got, String what) {
        if (!want.equals(got)) {
            throw new AssertionError(what + ": expected " + abbreviate(want) + " but was " + abbreviate(got));
        }
    }

    private static String abbreviate(String s) {
        return s.length() > 80 ? s.substring(0, 80) + "…" : s;
    }

    // ---- validation ----

    /** Validates the whole file against spec §11 and the pins; {@link IllegalStateException} otherwise. */
    static void validate(JsonNode file) {
        require(file != null && file.isObject(), "the file is a JSON object");
        fields(file, TOP, "file");
        noNumbers(file, "file");
        equal(file, "schema", "zeroj-proof-vectors-v1");
        equal(file, "protocolId", G1RangeProof.PROTOCOL.id().value());
        equal(file, "profileId", G1RangeProof.PROTOCOL.consumes().id().value());
        equal(file, "generatorSetId", G1RangeProof.PROTOCOL.generatorSetId().value());
        equal(file, "generatorDigestHex", BulletproofGenerators.D_GENS_HEX);

        JsonNode gens = file.get("generators");
        require(gens.isArray() && gens.size() == 2 * BulletproofGenerators.MAX_BITS + 1, "129 generators");
        for (int i = 0; i < gens.size(); i++) {
            JsonNode g = gens.get(i);
            fields(g, Set.of("name", "compressedHex"), "generators[" + i + "]");
            String name = i < 64 ? "G_" + i : i < 128 ? "H_" + (i - 64) : "U";
            String pin = i < 64 ? BulletproofGenerators.G_VEC_HEX.get(i) : i < 128
                    ? BulletproofGenerators.H_VEC_HEX.get(i - 64) : BulletproofGenerators.U_HEX;
            require(name.equals(g.get("name").asText()), "generator " + i + " is " + name);
            require(pin.equals(g.get("compressedHex").asText()), "generator " + name + " equals its pin");
        }
        require(file.get("spec").isArray() && file.get("spec").size() >= 1, "spec provenance");
        fields(file.get("generator"), Set.of("script", "scriptSha256", "python"), "generator");

        Set<String> ids = new HashSet<>();
        Set<String> seeds = new HashSet<>();
        Set<String> widths = new HashSet<>();
        for (JsonNode c : array(file, "positive")) {
            fields(c, POSITIVE, "positive case");
            fields(c.get("challenges"), CHALLENGES, "challenges");
            caseCommon(c, ids);
            hex(c, "commitmentHex", 48);
            hex(c, "nonceSeedHex", 32);
            hex(c, "sessionIdHex", 32);
            hex(c, "proofHex", -1);
            decimal(c, "value");
            decimal(c, "blinding");
            // Spec §7.5: two proofs under one seed reuse every nonce; each positive has its own.
            require(seeds.add(c.get("nonceSeedHex").asText()), "unique nonce seed " + c.get("id"));
            widths.add(c.get("bits").asText());
        }
        // Spec §11: a positive case at every width (which includes n = 64, registry §2.4 item 4).
        require(widths.equals(Set.of("16", "32", "64")), "positive cases at n = 16, 32 and 64, not " + widths);
        for (JsonNode c : array(file, "negative")) {
            fields(c, NEGATIVE, "negative case");
            caseCommon(c, ids);
            hex(c, "commitmentHex", -1);
            hex(c, "proofHex", -1);
            require(LAYERS.contains(c.get("layer").asText()), "layer of " + c.get("id"));
        }
        for (JsonNode c : array(file, "proverNegative")) {
            fields(c, PROVER_NEGATIVE, "proverNegative case");
            caseCommon(c, ids);
            decimal(c, "value");
            decimal(c, "blinding");
        }
    }

    private static void caseCommon(JsonNode c, Set<String> ids) {
        require(ids.add(c.get("id").asText()), "unique id " + c.get("id"));
        require(DECIMAL.matcher(c.get("bits").asText()).matches(), "bits is a decimal string");
        hex(c, "ctxHex", -1);
    }

    private static Iterable<JsonNode> array(JsonNode file, String name) {
        JsonNode a = file.get(name);
        require(a != null && a.isArray() && !a.isEmpty(), name + " is a non-empty array");
        return a;
    }

    private static void fields(JsonNode node, Set<String> expected, String where) {
        require(node != null && node.isObject(), where + " is an object");
        Set<String> got = new HashSet<>();
        Iterator<String> names = node.fieldNames();
        names.forEachRemaining(got::add);
        require(got.equals(expected), where + " has exactly the fields " + expected + ", not " + got);
    }

    private static void noNumbers(JsonNode node, String where) {
        require(!node.isNumber() && !node.isBoolean() && !node.isNull(), where + ": every value is a string");
        if (node.isContainerNode()) {
            node.forEach(child -> noNumbers(child, where));
        }
    }

    private static void equal(JsonNode file, String field, String expected) {
        require(expected.equals(file.get(field).asText()), field + " is " + expected);
    }

    private static void hex(JsonNode c, String field, int octets) {
        String s = c.get(field).asText();
        require(HEX_STRING.matcher(s).matches(), field + " is lowercase hex");
        require(octets < 0 || s.length() == 2 * octets, field + " is " + octets + " octets");
    }

    private static void decimal(JsonNode c, String field) {
        require(DECIMAL.matcher(c.get(field).asText()).matches(), field + " is a canonical decimal");
    }

    private static void require(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException("invalid zeroj-proof-vectors-v1 file: " + what);
        }
    }
}
