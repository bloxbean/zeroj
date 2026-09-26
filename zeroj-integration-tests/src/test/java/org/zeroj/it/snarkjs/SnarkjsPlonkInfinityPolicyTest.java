package org.zeroj.it.snarkjs;

import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.VerificationResult;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.codec.CanonicalHash;
import org.zeroj.codec.SnarkjsPlonkCodec;
import org.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsPlonkJson;
import org.zeroj.verifier.plonk.PlonkBLS12381Verifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplier;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplierWitness;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0047 V3, differential form: for every G1 position of a PlonK verification key, the exporter
 * accepts the identity point <b>iff</b> {@code PlonkBLS12381Verifier} accepts {@code ["0","1","0"]}
 * in that position (i.e. does not reject the file as malformed). The two policies are written in
 * two modules; this test is what keeps them from drifting apart. Offline, default build.
 */
class SnarkjsPlonkInfinityPolicyTest {

    private static final Set<String> IDENTITY_ALLOWED = Set.of("Qm", "Ql", "Qr", "Qo", "Qc");
    private static final List<String> G1_POSITIONS = List.of("Qm", "Ql", "Qr", "Qo", "Qc", "S1", "S2", "S3");

    private static ZeroJPlonk.Run run;
    private static String vkJson;
    private static String proofJson;
    private static String publicJson;

    @BeforeAll
    static void proveOnce() {
        var circuit = multiplier();
        run = ZeroJPlonk.setupAndProve(circuit, multiplierWitness(circuit, 3, 11));
        vkJson = SnarkjsPlonkJson.verificationKeyJson(run.pk());
        proofJson = SnarkjsPlonkJson.proofJson(run.proof());
        publicJson = SnarkjsPlonkJson.publicJson(run.publicInputs());
        assertTrue(verify(vkJson).proofValid(), "baseline: the exported artifacts verify");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Qm", "Ql", "Qr", "Qo", "Qc", "S1", "S2", "S3"})
    void exporterAndVerifierAgreeOnWhereTheIdentityIsLegal(String position) {
        assertTrue(G1_POSITIONS.contains(position));
        boolean verifierAccepts;
        var result = verify(withIdentity(vkJson, position));
        verifierAccepts = result.reasonCode().map(r -> r != VerificationResult.ReasonCode.MALFORMED_ENVELOPE).orElse(true);

        boolean exporterAccepts;
        try {
            SnarkjsPlonkJson.verificationKeyJson(withIdentity(run.pk(), position));
            exporterAccepts = true;
        } catch (IllegalArgumentException e) {
            exporterAccepts = false;
        }

        assertEquals(verifierAccepts, exporterAccepts,
                position + ": exporter (" + exporterAccepts + ") and ZeroJ verifier (" + verifierAccepts + ") disagree on the identity point");
        assertEquals(IDENTITY_ALLOWED.contains(position), exporterAccepts, position + ": ADR-0047 V3 policy");
        if (!verifierAccepts) {
            assertEquals(Optional.of(VerificationResult.ReasonCode.MALFORMED_ENVELOPE), result.reasonCode());
        } else {
            // a selector at the identity changes the statement; the proof must then fail, not be malformed
            assertFalse(result.proofValid(), position + ": swapping in the identity must not leave the proof valid");
            assertNotEquals(Optional.of(VerificationResult.ReasonCode.MALFORMED_ENVELOPE), result.reasonCode());
        }
    }

    // ---------------------------------------------------------------- helpers

    private static VerificationResult verify(String vk) {
        var circuitId = new CircuitId("adr-0047-plonk-policy");
        var material = VerificationMaterial.of(vk.getBytes(StandardCharsets.UTF_8), ProofSystemId.PLONK,
                CurveId.BLS12_381, circuitId, CanonicalHash.sha256(vk.getBytes(StandardCharsets.UTF_8)));
        return new PlonkBLS12381Verifier().verify(SnarkjsPlonkCodec.toEnvelopeFromJson(proofJson, vk, publicJson, circuitId), material);
    }

    /** Replace the G1 array of {@code key} in exported snarkjs JSON with the identity encoding. */
    private static String withIdentity(String json, String key) {
        var p = Pattern.compile("(\"" + key + "\": \\[\\n)  \"\\d+\",\\n  \"\\d+\",\\n  \"1\"\\n");
        var m = p.matcher(json);
        assertTrue(m.find(), key + " must be a finite G1 point in the exported VK");
        return m.replaceFirst("$1  \"0\",\n  \"1\",\n  \"0\"\n");
    }

    private static PlonKProvingKeyBLS381 withIdentity(PlonKProvingKeyBLS381 pk, String key) {
        AffineG1 inf = AffineG1.INFINITY;
        return new PlonKProvingKeyBLS381(pk.domainSize(), pk.nPublic(), pk.nConstraints(), pk.k1(), pk.k2(), pk.omega(),
                pk.ql(), pk.qr(), pk.qm(), pk.qo(), pk.qc(), pk.s1(), pk.s2(), pk.s3(), pk.srsG1(), pk.srsG1Lagrange(), pk.x2(),
                key.equals("Qm") ? inf : pk.qmCommit(), key.equals("Ql") ? inf : pk.qlCommit(),
                key.equals("Qr") ? inf : pk.qrCommit(), key.equals("Qo") ? inf : pk.qoCommit(),
                key.equals("Qc") ? inf : pk.qcCommit(), key.equals("S1") ? inf : pk.s1Commit(),
                key.equals("S2") ? inf : pk.s2Commit(), key.equals("S3") ? inf : pk.s3Commit());
    }
}
