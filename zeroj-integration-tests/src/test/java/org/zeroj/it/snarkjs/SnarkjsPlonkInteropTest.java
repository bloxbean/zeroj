package org.zeroj.it.snarkjs;

import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.codec.CanonicalHash;
import org.zeroj.codec.SnarkjsPlonkCodec;
import org.zeroj.crypto.plonk.PlonKProofBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsPlonkJson;
import org.zeroj.examples.dsl.common.SnarkjsProver;
import org.zeroj.verifier.plonk.PlonkBLS12381Verifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.SNARKJS_CURVE;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplier;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplierWitness;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.publicInputs;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.r1csBytes;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.requireSnarkjs;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.verify;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.writeVerifyInputs;
import static org.zeroj.it.snarkjs.SnarkjsInteropSupport.wtnsBytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.zeroj.it.snarkjs.SnarkjsInteropSupport.Verdict;

/**
 * ADR-0047 M3 — PlonK BLS12-381 interop against the live snarkjs CLI, both directions, with
 * negatives. Skips without snarkjs; fails without it under {@code -PrequireSnarkjs}.
 *
 * <ul>
 *   <li>ZeroJ → snarkjs: a ZeroJ-native PlonK setup ({@code PlonKSetupBLS381}) and a proof from the
 *       snarkjs-transcript prover ({@code PlonKProverBLS381.prove}), exported as verification key
 *       + proof + public inputs, accepted by {@code snarkjs plonk verify}; tampering rejected.</li>
 *   <li>snarkjs → ZeroJ: a live {@code snarkjs plonk setup} + {@code plonk prove} over a ZeroJ
 *       R1CS accepted by {@code PlonkBLS12381Verifier}; tampering rejected; re-export byte-identical.</li>
 * </ul>
 *
 * <p>Not covered (ADR-0047 known gap): a ZeroJ proof under a snarkjs-generated PlonK zkey. The
 * snarkjs PlonK zkey importer does not expose the A/B/C wire maps, so ZeroJ cannot assign wires for
 * a snarkjs-arithmetised circuit.</p>
 */
@Timeout(value = 20, unit = TimeUnit.MINUTES)
class SnarkjsPlonkInteropTest {

    @TempDir
    static Path work;

    private static SnarkjsProver snarkjs;
    private static Path ptau;
    private static BigInteger[] witness;

    @BeforeAll
    static void setUpCeremony() throws Exception {
        snarkjs = requireSnarkjs();
        witness = multiplierWitness(multiplier(), 3, 11);
        ptau = snarkjs.powersOfTau(SNARKJS_CURVE, 8, Files.createDirectories(work.resolve("ptau")));
    }

    // ------------------------------------------------------------ ZeroJ setup + proof → snarkjs verify

    @Test
    void zeroJNativePlonkSetup_exportedVkAndProof_areAcceptedBySnarkjs_andTamperingIsRejected() throws Exception {
        var setup = ZeroJPlonk.setup(multiplier());
        var run = ZeroJPlonk.prove(setup, witness);
        String vkJson = SnarkjsPlonkJson.verificationKeyJson(run.pk());
        String proofJson = SnarkjsPlonkJson.proofJson(run.proof());
        String publicJson = SnarkjsPlonkJson.publicJson(run.publicInputs());

        Path dir = Files.createDirectories(work.resolve("p1-ok"));
        writeVerifyInputs(dir, vkJson, publicJson, proofJson);
        assertEquals(Verdict.VALID, verify("plonk", dir), "snarkjs must accept a ZeroJ-native PlonK VK + proof");

        Path wrongPublic = Files.createDirectories(work.resolve("p1-wrong-public"));
        writeVerifyInputs(wrongPublic, vkJson, SnarkjsPlonkJson.publicJson(new BigInteger[]{BigInteger.valueOf(34)}), proofJson);
        assertEquals(Verdict.INVALID, verify("plonk", wrongPublic), "snarkjs must reject a wrong public input");

        var p = run.proof();
        var swapped = new PlonKProofBLS381(p.commitB(), p.commitA(), p.commitC(), p.commitZ(), p.commitT1(), p.commitT2(),
                p.commitT3(), p.evalA(), p.evalB(), p.evalC(), p.evalS1(), p.evalS2(), p.evalZw(), p.commitWxi(), p.commitWxiw());
        Path swappedDir = Files.createDirectories(work.resolve("p1-swapped-ab"));
        writeVerifyInputs(swappedDir, vkJson, publicJson, SnarkjsPlonkJson.proofJson(swapped));
        assertEquals(Verdict.INVALID, verify("plonk", swappedDir), "snarkjs must reject swapped commitments");

        var evalTampered = new PlonKProofBLS381(p.commitA(), p.commitB(), p.commitC(), p.commitZ(), p.commitT1(), p.commitT2(),
                p.commitT3(), p.evalA().add(BigInteger.ONE).mod(SnarkjsInteropSupport.FR), p.evalB(), p.evalC(),
                p.evalS1(), p.evalS2(), p.evalZw(), p.commitWxi(), p.commitWxiw());
        Path evalDir = Files.createDirectories(work.resolve("p1-eval-a"));
        writeVerifyInputs(evalDir, vkJson, publicJson, SnarkjsPlonkJson.proofJson(evalTampered));
        assertEquals(Verdict.INVALID, verify("plonk", evalDir), "snarkjs must reject a tampered evaluation");

        // Same key, different witness: the rejection must come from the statement, not a key mismatch.
        var other = ZeroJPlonk.prove(setup, multiplierWitness(multiplier(), 2, 17));
        Path otherDir = Files.createDirectories(work.resolve("p1-other-witness"));
        writeVerifyInputs(otherDir, vkJson, publicJson, SnarkjsPlonkJson.proofJson(other.proof()));
        assertEquals(Verdict.INVALID, verify("plonk", otherDir), "a proof of 2*17 must not verify for c = 33");
    }

    // ------------------------------------------------------------ snarkjs setup + proof → ZeroJ verify

    @Test
    void snarkjsPlonkProof_isAcceptedByZeroJVerifier_andTamperingIsRejected() throws Exception {
        var compiled = multiplier().compileR1CS(CurveId.BLS12_381);
        Path dir = Files.createDirectories(work.resolve("p2"));
        var setup = snarkjs.plonkSetup(r1csBytes(compiled), ptau, dir);
        var result = snarkjs.plonkProve(setup.zkeyFile(), wtnsBytes(witness), dir, setup.vkJson());
        var circuitId = new CircuitId("adr-0047-multiplier-plonk");

        var verifier = new PlonkBLS12381Verifier();
        var envelope = SnarkjsPlonkCodec.toEnvelopeFromJson(result.proofJson(), result.vkJson(), result.publicJson(), circuitId);
        var material = VerificationMaterial.of(result.vkJson().getBytes(StandardCharsets.UTF_8), ProofSystemId.PLONK,
                CurveId.BLS12_381, circuitId, CanonicalHash.sha256(result.vkJson().getBytes(StandardCharsets.UTF_8)));
        assertTrue(verifier.verify(envelope, material).proofValid(), "ZeroJ must accept a live snarkjs PlonK proof");

        String wrongPublic = SnarkjsPlonkJson.publicJson(new BigInteger[]{BigInteger.valueOf(34)});
        var tampered = SnarkjsPlonkCodec.toEnvelopeFromJson(result.proofJson(), result.vkJson(), wrongPublic, circuitId);
        assertFalse(verifier.verify(tampered, material).proofValid());

        // Byte-identical re-export of fresh snarkjs output.
        var p = SnarkjsPlonkCodec.parseProof(result.proofJson());
        var proof = new PlonKProofBLS381(g1(p.A()), g1(p.B()), g1(p.C()), g1(p.Z()), g1(p.T1()), g1(p.T2()), g1(p.T3()),
                p.evalA(), p.evalB(), p.evalC(), p.evalS1(), p.evalS2(), p.evalZw(), g1(p.Wxi()), g1(p.Wxiw()));
        assertEquals(result.proofJson(), SnarkjsPlonkJson.proofJson(proof));
        assertEquals(result.publicJson(), SnarkjsPlonkJson.publicJson(publicInputs(witness, 1)));
        var vk = SnarkjsPlonkCodec.parseVerificationKey(result.vkJson());
        assertEquals(result.vkJson(), SnarkjsPlonkJson.verificationKeyJson(1 << vk.power(), vk.nPublic(), vk.k1(), vk.k2(), vk.w(),
                g1(vk.Qm()), g1(vk.Ql()), g1(vk.Qr()), g1(vk.Qo()), g1(vk.Qc()), g1(vk.S1()), g1(vk.S2()), g1(vk.S3()),
                new AffineG2(MontFp2_381.of(vk.X_2().get(0).get(0), vk.X_2().get(0).get(1)),
                        MontFp2_381.of(vk.X_2().get(1).get(0), vk.X_2().get(1).get(1)))));
    }

    private static AffineG1 g1(List<BigInteger> c) {
        if (c.size() == 3 && c.get(2).signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp381.fromBigInteger(c.get(0)), MontFp381.fromBigInteger(c.get(1)));
    }
}
