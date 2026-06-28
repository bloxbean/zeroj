package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.codec.CanonicalHash;
import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKSetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PlonkBLS12381VerifierTest {

    @Test
    void verify_javaGeneratedProof_accepts() {
        var fixture = fixture();

        var result = new PlonkBLS12381Verifier().verify(fixture.envelope(), fixture.material());
        assertTrue(result.proofValid(), () -> result.message().orElse("verification failed"));
    }

    @Test
    void verify_cardanoProfileJavaGeneratedProof_accepts() {
        var fixture = fixture(true);

        var result = new PlonkBLS12381Verifier().verify(fixture.envelope(), fixture.material());
        assertTrue(result.proofValid(), () -> result.message().orElse("verification failed"));
    }

    @Test
    void verify_cardanoMpiProfileJavaGeneratedProof_accepts() {
        var fixture = mpiFixture(4, true);

        var result = new PlonkBLS12381Verifier().verify(fixture.envelope(), fixture.material());
        assertTrue(result.proofValid(), () -> result.message().orElse("verification failed"));
    }

    @Test
    void verify_cardanoV1ProfileRejectsMultiplePublicInputs() {
        var fixture = mpiFixture(4, false);
        var envelope = copyEnvelopeWithProofFormat(fixture.envelope(), PlonkBLS12381Verifier.CARDANO_PROOF_FORMAT);

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_cardanoMpiProfileRejectsWhenClaimedAsV1Transcript() {
        var fixture = mpiFixture(4, true);
        var envelope = copyEnvelopeWithProofFormat(fixture.envelope(), PlonkBLS12381Verifier.CARDANO_PROOF_FORMAT);

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_cardanoProfileProof_rejectsWhenClaimedAsSnarkjsTranscript() {
        var fixture = fixture(true);
        var envelope = copyEnvelopeWithProofFormat(fixture.envelope(), PlonkBLS12381Verifier.SNARKJS_PROOF_FORMAT);

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());
        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsNegativePublicInput() {
        var fixture = fixture();
        var envelope = copyEnvelope(fixture.envelope(), fixture.proofJson(),
                new PublicInputs(List.of(BigInteger.valueOf(-1))));

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsWrongPublicInputCount() {
        var fixture = fixture();
        var envelope = copyEnvelope(fixture.envelope(), fixture.proofJson(), new PublicInputs(List.of()));

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsMaterialCircuitMismatch() {
        var fixture = fixture();
        var material = VerificationMaterial.of(fixture.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.PLONK, CurveId.BLS12_381, new CircuitId("other-circuit"));

        var result = new PlonkBLS12381Verifier().verify(fixture.envelope(), material);

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.VK_MISMATCH, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsWrongProofCurveMetadata() {
        var fixture = fixture();
        var proofJson = fixture.proofJson().replace("\"curve\":\"bls12381\"", "\"curve\":\"bn128\"");
        var envelope = copyEnvelope(fixture.envelope(), proofJson, fixture.envelope().publicInputs());

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.UNSUPPORTED_CURVE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsWrongVkCurveMetadata() {
        var fixture = fixture();
        var vkJson = fixture.vkJson().replace("\"curve\":\"bls12381\"", "\"curve\":\"bn128\"");
        var envelope = copyEnvelopeWithVkHash(fixture.envelope(), fixture.proofJson(),
                fixture.envelope().publicInputs(), vkJson);
        var material = materialFor(fixture, vkJson);

        var result = new PlonkBLS12381Verifier().verify(envelope, material);

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.UNSUPPORTED_CURVE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsGnarkProofFormat() {
        var fixture = fixture();
        var envelope = copyEnvelopeWithProofFormat(fixture.envelope(), "gnark-plonk-json");

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsUnsupportedProofFormat() {
        var fixture = fixture();
        var envelope = copyEnvelopeWithProofFormat(fixture.envelope(), "zeroj-plonk-binary");

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsOverFieldProofScalar() {
        var fixture = fixture();
        var proofJson = fixture.proofJson()
                .replaceFirst("\"eval_a\":\"[0-9]+\"", "\"eval_a\":\"" + G1Point.R + "\"");
        var envelope = copyEnvelope(fixture.envelope(), proofJson, fixture.envelope().publicInputs());

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsInvalidVkDomainRoot() {
        var fixture = fixture();
        var vkJson = replaceTopLevelValue(fixture.vkJson(), "w", "\"1\"");
        var envelope = copyEnvelopeWithVkHash(fixture.envelope(), fixture.proofJson(),
                fixture.envelope().publicInputs(), vkJson);
        var material = materialFor(fixture, vkJson);

        var result = new PlonkBLS12381Verifier().verify(envelope, material);

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsInvalidPermutationCoset() {
        var fixture = fixture();
        var vkJson = replaceTopLevelValue(fixture.vkJson(), "k1", "\"1\"");
        var envelope = copyEnvelopeWithVkHash(fixture.envelope(), fixture.proofJson(),
                fixture.envelope().publicInputs(), vkJson);
        var material = materialFor(fixture, vkJson);

        var result = new PlonkBLS12381Verifier().verify(envelope, material);

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsOffCurveProofCommitment() {
        var fixture = fixture();
        var proofJson = fixture.proofJson()
                .replaceFirst("\"A\":\\[[^]]+\\]", "\"A\":[\"0\",\"0\",\"1\"]");
        var envelope = copyEnvelope(fixture.envelope(), proofJson, fixture.envelope().publicInputs());

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsNonNormalizedProofCommitment() {
        var fixture = fixture();
        var proofJson = replaceTopLevelValue(fixture.proofJson(), "A", "[\"1\",\"2\",\"2\"]");
        var envelope = copyEnvelope(fixture.envelope(), proofJson, fixture.envelope().publicInputs());

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsInfinityProofCommitment() {
        var fixture = fixture();
        var proofJson = replaceTopLevelValue(fixture.proofJson(), "A", "[\"0\",\"1\",\"0\"]");
        var envelope = copyEnvelope(fixture.envelope(), proofJson, fixture.envelope().publicInputs());

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsInfinityX2() {
        var fixture = fixture();
        var vkJson = replaceTopLevelValue(fixture.vkJson(), "X_2",
                "[[\"0\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]");
        var envelope = copyEnvelopeWithVkHash(fixture.envelope(), fixture.proofJson(),
                fixture.envelope().publicInputs(), vkJson);
        var material = materialFor(fixture, vkJson);

        var result = new PlonkBLS12381Verifier().verify(envelope, material);

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.MALFORMED_ENVELOPE, result.reasonCode().orElseThrow());
    }

    @Test
    void verify_rejectsVkHashMismatch() {
        var fixture = fixture();
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(fixture.envelope().proofSystem())
                .curve(fixture.envelope().curve())
                .circuitId(fixture.envelope().circuitId())
                .proofBytes(fixture.proofJson().getBytes(StandardCharsets.UTF_8))
                .publicInputs(fixture.envelope().publicInputs())
                .vkRef(new VerificationKeyRef.ByHash(new byte[32]))
                .proofFormat("snarkjs-plonk-json")
                .build();

        var result = new PlonkBLS12381Verifier().verify(envelope, fixture.material());

        assertFalse(result.proofValid());
        assertEquals(VerificationResult.ReasonCode.VK_MISMATCH, result.reasonCode().orElseThrow());
    }

    private static Fixture fixture() {
        return fixture(false);
    }

    private static Fixture fixture(boolean cardanoProfile) {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));

        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        int numGates = plonk.numGates();
        BigInteger[][] gates = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gates[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }

        var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), gates,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);

        var extWitness = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr381[] wireA = new MontFr381[n];
        MontFr381[] wireB = new MontFr381[n];
        MontFr381[] wireC = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(extWitness[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(extWitness[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(extWitness[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
            }
        }

        BigInteger[] publicInputs = new BigInteger[plonk.numPublicInputs()];
        for (int i = 0; i < publicInputs.length; i++) {
            publicInputs[i] = witness[i + 1];
        }

        var proof = cardanoProfile
                ? PlonKProverBLS381.proveCardano(pk, wireA, wireB, wireC, publicInputs)
                : PlonKProverBLS381.prove(pk, wireA, wireB, wireC, publicInputs);
        String proofJson = proofJson(proof);
        String vkJson = vkJson(pk);
        String publicJson = "[\"33\"]";

        var envelope = SnarkjsPlonkCodec.toEnvelopeFromJson(
                proofJson, vkJson, publicJson, new CircuitId("bls381-plonk-multiplier"));
        if (cardanoProfile) {
            envelope = copyEnvelopeWithProofFormat(envelope, PlonkBLS12381Verifier.CARDANO_PROOF_FORMAT);
        }
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.PLONK, CurveId.BLS12_381, new CircuitId("bls381-plonk-multiplier"));

        return new Fixture(envelope, material, proofJson, vkJson);
    }

    private static Fixture mpiFixture(int publicInputCount, boolean cardanoMpiProfile) {
        var circuit = multiInputCircuit(publicInputCount);
        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        var witness = circuit.calculateWitness(multiInputWitness(publicInputCount), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        int numGates = plonk.numGates();
        BigInteger[][] gates = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gates[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }

        var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), gates,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);

        var extWitness = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr381[] wireA = new MontFr381[n];
        MontFr381[] wireB = new MontFr381[n];
        MontFr381[] wireC = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(extWitness[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(extWitness[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(extWitness[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
            }
        }

        BigInteger[] publicInputs = new BigInteger[plonk.numPublicInputs()];
        for (int i = 0; i < publicInputs.length; i++) {
            publicInputs[i] = witness[i + 1];
        }

        PlonKProofBLS381 proof;
        if (cardanoMpiProfile) {
            var rng = new SecureRandom(new byte[]{0x4d, 0x50, 0x49, (byte) publicInputCount});
            proof = PlonKProverBLS381.proveCardanoMpi(pk, wireA, wireB, wireC, publicInputs, rng);
        } else {
            proof = PlonKProverBLS381.prove(pk, wireA, wireB, wireC, publicInputs);
        }

        String proofJson = proofJson(proof);
        String vkJson = vkJson(pk);
        var envelope = SnarkjsPlonkCodec.toEnvelopeFromJson(
                proofJson, vkJson, publicJson(publicInputs), new CircuitId("bls381-plonk-mpi-" + publicInputCount));
        if (cardanoMpiProfile) {
            envelope = copyEnvelopeWithProofFormat(envelope, PlonkBLS12381Verifier.CARDANO_MPI_PROOF_FORMAT);
        }
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.PLONK, CurveId.BLS12_381, new CircuitId("bls381-plonk-mpi-" + publicInputCount));

        return new Fixture(envelope, material, proofJson, vkJson);
    }

    private static CircuitBuilder multiInputCircuit(int publicInputCount) {
        var builder = CircuitBuilder.create("multi-public-linear-" + publicInputCount);
        for (int i = 0; i < publicInputCount; i++) {
            builder.publicVar("p" + i);
        }
        builder.secretVar("x");
        return builder.define(api -> {
            var expr = api.mul(api.var("p0"), api.var("x"));
            for (int i = 1; i < publicInputCount - 1; i++) {
                expr = api.add(expr, api.var("p" + i));
            }
            api.assertEqual(expr, api.var("p" + (publicInputCount - 1)));
        });
    }

    private static Map<String, List<BigInteger>> multiInputWitness(int publicInputCount) {
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        BigInteger x = BigInteger.valueOf(7);
        inputs.put("x", List.of(x));
        BigInteger acc = BigInteger.valueOf(3).multiply(x);
        inputs.put("p0", List.of(BigInteger.valueOf(3)));
        for (int i = 1; i < publicInputCount - 1; i++) {
            BigInteger value = BigInteger.valueOf(i + 3L);
            inputs.put("p" + i, List.of(value));
            acc = acc.add(value);
        }
        inputs.put("p" + (publicInputCount - 1), List.of(acc));
        return inputs;
    }

    private static String publicJson(BigInteger[] publicInputs) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < publicInputs.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(publicInputs[i]).append('"');
        }
        return json.append(']').toString();
    }

    private static ZkProofEnvelope copyEnvelope(ZkProofEnvelope original, String proofJson, PublicInputs publicInputs) {
        return ZkProofEnvelope.builder()
                .proofSystem(original.proofSystem())
                .curve(original.curve())
                .circuitId(original.circuitId())
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .publicInputs(publicInputs)
                .vkRef(original.vkRef())
                .proofFormat("snarkjs-plonk-json")
                .build();
    }

    private static ZkProofEnvelope copyEnvelopeWithProofFormat(ZkProofEnvelope original, String proofFormat) {
        return ZkProofEnvelope.builder()
                .proofSystem(original.proofSystem())
                .curve(original.curve())
                .circuitId(original.circuitId())
                .proofBytes(original.proofBytes())
                .publicInputs(original.publicInputs())
                .vkRef(original.vkRef())
                .proofFormat(proofFormat)
                .build();
    }

    private static ZkProofEnvelope copyEnvelopeWithVkHash(
            ZkProofEnvelope original,
            String proofJson,
            PublicInputs publicInputs,
            String vkJson) {
        return ZkProofEnvelope.builder()
                .proofSystem(original.proofSystem())
                .curve(original.curve())
                .circuitId(original.circuitId())
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .publicInputs(publicInputs)
                .vkRef(new VerificationKeyRef.ByHash(CanonicalHash.sha256(vkJson.getBytes(StandardCharsets.UTF_8))))
                .proofFormat("snarkjs-plonk-json")
                .build();
    }

    private static VerificationMaterial materialFor(Fixture fixture, String vkJson) {
        return VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.PLONK, CurveId.BLS12_381, fixture.envelope().circuitId());
    }

    private static String replaceTopLevelValue(String json, String fieldName, String replacement) {
        String key = "\"" + fieldName + "\":";
        int keyStart = json.indexOf(key);
        if (keyStart < 0) {
            throw new IllegalArgumentException("Missing JSON field: " + fieldName);
        }
        int valueStart = keyStart + key.length();
        int valueEnd = jsonValueEnd(json, valueStart);
        return json.substring(0, valueStart) + replacement + json.substring(valueEnd);
    }

    private static int jsonValueEnd(String json, int valueStart) {
        char first = json.charAt(valueStart);
        if (first == '"') {
            boolean escaped = false;
            for (int i = valueStart + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    return i + 1;
                }
            }
            throw new IllegalArgumentException("Unterminated JSON string");
        }
        if (first == '[') {
            int depth = 0;
            boolean inString = false;
            boolean escaped = false;
            for (int i = valueStart; i < json.length(); i++) {
                char c = json.charAt(i);
                if (inString) {
                    if (escaped) {
                        escaped = false;
                    } else if (c == '\\') {
                        escaped = true;
                    } else if (c == '"') {
                        inString = false;
                    }
                    continue;
                }
                if (c == '"') {
                    inString = true;
                } else if (c == '[') {
                    depth++;
                } else if (c == ']') {
                    depth--;
                    if (depth == 0) {
                        return i + 1;
                    }
                }
            }
            throw new IllegalArgumentException("Unterminated JSON array");
        }
        int comma = json.indexOf(',', valueStart);
        int objectEnd = json.indexOf('}', valueStart);
        if (comma < 0) {
            return objectEnd;
        }
        return Math.min(comma, objectEnd);
    }

    private record Fixture(
            ZkProofEnvelope envelope,
            VerificationMaterial material,
            String proofJson,
            String vkJson
    ) {}

    private static String proofJson(PlonKProofBLS381 proof) {
        return "{"
                + "\"A\":" + g1(proof.commitA()) + ","
                + "\"B\":" + g1(proof.commitB()) + ","
                + "\"C\":" + g1(proof.commitC()) + ","
                + "\"Z\":" + g1(proof.commitZ()) + ","
                + "\"T1\":" + g1(proof.commitT1()) + ","
                + "\"T2\":" + g1(proof.commitT2()) + ","
                + "\"T3\":" + g1(proof.commitT3()) + ","
                + "\"eval_a\":\"" + proof.evalA() + "\","
                + "\"eval_b\":\"" + proof.evalB() + "\","
                + "\"eval_c\":\"" + proof.evalC() + "\","
                + "\"eval_s1\":\"" + proof.evalS1() + "\","
                + "\"eval_s2\":\"" + proof.evalS2() + "\","
                + "\"eval_zw\":\"" + proof.evalZw() + "\","
                + "\"Wxi\":" + g1(proof.commitWxi()) + ","
                + "\"Wxiw\":" + g1(proof.commitWxiw()) + ","
                + "\"protocol\":\"plonk\","
                + "\"curve\":\"bls12381\""
                + "}";
    }

    private static String vkJson(PlonKProvingKeyBLS381 pk) {
        return "{"
                + "\"protocol\":\"plonk\","
                + "\"curve\":\"bls12381\","
                + "\"nPublic\":" + pk.nPublic() + ","
                + "\"power\":" + Integer.numberOfTrailingZeros(pk.domainSize()) + ","
                + "\"k1\":\"" + pk.k1() + "\","
                + "\"k2\":\"" + pk.k2() + "\","
                + "\"Qm\":" + g1(pk.qmCommit()) + ","
                + "\"Ql\":" + g1(pk.qlCommit()) + ","
                + "\"Qr\":" + g1(pk.qrCommit()) + ","
                + "\"Qo\":" + g1(pk.qoCommit()) + ","
                + "\"Qc\":" + g1(pk.qcCommit()) + ","
                + "\"S1\":" + g1(pk.s1Commit()) + ","
                + "\"S2\":" + g1(pk.s2Commit()) + ","
                + "\"S3\":" + g1(pk.s3Commit()) + ","
                + "\"X_2\":" + g2(pk.x2()) + ","
                + "\"w\":\"" + pk.omega().toBigInteger() + "\""
                + "}";
    }

    private static String g1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) {
            return "[\"0\",\"1\",\"0\"]";
        }
        return "[\"" + p.xBigInt() + "\",\"" + p.yBigInt() + "\",\"1\"]";
    }

    private static String g2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) {
            return "[[\"0\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]";
        }
        return "[[\"" + p.x().reBigInt() + "\",\"" + p.x().imBigInt() + "\"],"
                + "[\"" + p.y().reBigInt() + "\",\"" + p.y().imBigInt() + "\"],"
                + "[\"1\",\"0\"]]";
    }
}
