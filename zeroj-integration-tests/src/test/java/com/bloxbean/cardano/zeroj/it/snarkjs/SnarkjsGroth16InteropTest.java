package com.bloxbean.cardano.zeroj.it.snarkjs;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyImporterBLS381;
import com.bloxbean.cardano.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import com.bloxbean.cardano.zeroj.examples.dsl.common.SnarkjsProver;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381Verifier;
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

import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.SNARKJS_CURVE;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplier;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplierWitness;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.publicInputs;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.r1csBytes;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.requireSnarkjs;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.verify;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.writeVerifyInputs;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.wtnsBytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.Verdict;

/**
 * ADR-0047 M2 — Groth16 BLS12-381 interop against the live snarkjs CLI, in both directions, with
 * negatives. Skips without snarkjs; fails without it under {@code -PrequireSnarkjs} (assurance CI).
 *
 * <ul>
 *   <li>ZeroJ → snarkjs: a ZeroJ proof under a snarkjs-generated zkey, and a ZeroJ proof under a
 *       ZeroJ-native setup with the ZeroJ-exported verification key, both accepted by
 *       {@code snarkjs groth16 verify}; tampered proofs / public inputs rejected.</li>
 *   <li>snarkjs → ZeroJ: a live {@code snarkjs groth16 prove} accepted by the pure-Java and blst
 *       ZeroJ verifiers; tampered public inputs rejected; the proof re-exported by ZeroJ is
 *       byte-identical to what snarkjs wrote.</li>
 * </ul>
 */
@Timeout(value = 20, unit = TimeUnit.MINUTES)
class SnarkjsGroth16InteropTest {

    @TempDir
    static Path work;

    private static SnarkjsProver snarkjs;
    private static Path ptau;
    private static SnarkjsProver.SetupResult snarkjsSetup;   // zkey + VK produced by snarkjs
    private static BigInteger[] witness;
    private static byte[] r1cs;

    private final ZkVerifier pureJava = new Groth16BLS12381PureJavaVerifier();
    private final ZkVerifier blst = new Groth16BLS12381Verifier();

    @BeforeAll
    static void setUpCeremony() throws Exception {
        snarkjs = requireSnarkjs();
        var circuit = multiplier();
        var compiled = circuit.compileR1CS(CurveId.BLS12_381);
        witness = multiplierWitness(circuit, 3, 11);
        r1cs = r1csBytes(compiled);
        ptau = snarkjs.powersOfTau(SNARKJS_CURVE, 8, Files.createDirectories(work.resolve("ptau")));
        snarkjsSetup = snarkjs.groth16Setup(r1cs, ptau, Files.createDirectories(work.resolve("setup")));
    }

    // ------------------------------------------------------------ ZeroJ proof → snarkjs verify

    @Test
    void zeroJProof_underSnarkjsZkey_isAcceptedBySnarkjs_andTamperingIsRejected() throws Exception {
        var zkey = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(snarkjsSetup.zkeyFile()));
        var proof = Groth16ProverBLS381.prove(zkey.provingKey(), witness, zkey.constraints(), zkey.numWires());
        int nPublic = SnarkjsJsonCodec.parseVerificationKey(snarkjsSetup.vkJson()).nPublic();
        assertEquals(1, nPublic, "multiplier exposes exactly c");

        String proofJson = SnarkjsGroth16Json.proofJson(proof);
        String publicJson = SnarkjsGroth16Json.publicJson(publicInputs(witness, nPublic));

        Path dir = Files.createDirectories(work.resolve("t1-ok"));
        writeVerifyInputs(dir, snarkjsSetup.vkJson(), publicJson, proofJson);
        assertEquals(Verdict.VALID, verify("groth16", dir), "snarkjs must accept a ZeroJ proof under its own zkey/VK");

        Path wrongPublic = Files.createDirectories(work.resolve("t1-wrong-public"));
        writeVerifyInputs(wrongPublic, snarkjsSetup.vkJson(),
                SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.valueOf(34)}), proofJson);
        assertEquals(Verdict.INVALID, verify("groth16", wrongPublic), "snarkjs must reject a wrong public input");

        Path swapped = Files.createDirectories(work.resolve("t1-swapped-ac"));
        writeVerifyInputs(swapped, snarkjsSetup.vkJson(), publicJson,
                SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(proof.c(), proof.b(), proof.a())));
        assertEquals(Verdict.INVALID, verify("groth16", swapped), "snarkjs must reject valid-looking but wrong proof points");

        Path offCurve = Files.createDirectories(work.resolve("t1-off-curve"));
        writeVerifyInputs(offCurve, snarkjsSetup.vkJson(), publicJson, bumpFirstCoordinate(proofJson));
        assertEquals(Verdict.INVALID, verify("groth16", offCurve), "snarkjs must reject a proof point that is not on the curve");
    }

    @Test
    void zeroJNativeSetup_exportedVkAndProof_areAcceptedBySnarkjs_andTamperingIsRejected() throws Exception {
        var circuit = multiplier();
        var compiled = circuit.compileR1CS(CurveId.BLS12_381);
        var keys = Groth16Keys.setupInMemory(compiled.constraints(), compiled.numWires(),
                compiled.numPublicInputs(), BigInteger.valueOf(0x5eed));
        var proof = keys.prove(witness, compiled.constraints());

        String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
        String proofJson = SnarkjsGroth16Json.proofJson(proof);
        String publicJson = SnarkjsGroth16Json.publicJson(publicInputs(witness, compiled.numPublicInputs()));

        Path dir = Files.createDirectories(work.resolve("t2-ok"));
        writeVerifyInputs(dir, vkJson, publicJson, proofJson);
        assertEquals(Verdict.VALID, verify("groth16", dir), "snarkjs must accept a ZeroJ-native VK + proof");

        Path wrongPublic = Files.createDirectories(work.resolve("t2-wrong-public"));
        writeVerifyInputs(wrongPublic, vkJson, SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.valueOf(34)}), proofJson);
        assertEquals(Verdict.INVALID, verify("groth16", wrongPublic));

        // A proof for a different witness (2 * 17 = 34) must not verify against public input 33.
        var other = keys.prove(multiplierWitness(circuit, 2, 17), compiled.constraints());
        Path otherWitness = Files.createDirectories(work.resolve("t2-other-witness"));
        writeVerifyInputs(otherWitness, vkJson, publicJson, SnarkjsGroth16Json.proofJson(other));
        assertEquals(Verdict.INVALID, verify("groth16", otherWitness));

        // The proof under the ZeroJ-native key must not verify under snarkjs' own (different) key.
        Path wrongKey = Files.createDirectories(work.resolve("t2-wrong-key"));
        writeVerifyInputs(wrongKey, snarkjsSetup.vkJson(), publicJson, proofJson);
        assertEquals(Verdict.INVALID, verify("groth16", wrongKey));
    }

    // ------------------------------------------------------------ snarkjs proof → ZeroJ verify

    @Test
    void snarkjsProof_isAcceptedByBothZeroJVerifiers_andTamperingIsRejected() throws Exception {
        Path dir = Files.createDirectories(work.resolve("t3"));
        var result = snarkjs.groth16Prove(snarkjsSetup.zkeyFile(), wtnsBytes(witness), dir, snarkjsSetup.vkJson());
        var circuitId = new CircuitId("adr-0047-multiplier");

        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(result.proofJson(), result.vkJson(), result.publicJson(), circuitId);
        var material = VerificationMaterial.of(result.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, circuitId);
        assertTrue(pureJava.verify(envelope, material).proofValid(), "pure Java must accept a live snarkjs proof");
        assertTrue(blst.verify(envelope, material).proofValid(), "blst must accept a live snarkjs proof");

        String wrongPublic = SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.valueOf(34)});
        var tampered = SnarkjsJsonCodec.toEnvelopeFromJson(result.proofJson(), result.vkJson(), wrongPublic, circuitId);
        assertFalse(pureJava.verify(tampered, material).proofValid());
        assertFalse(blst.verify(tampered, material).proofValid());

        // The live snarkjs output re-exported by ZeroJ is byte-identical: the format pin holds on
        // fresh snarkjs output, not only on the checked-in vectors.
        var p = SnarkjsJsonCodec.parseProof(result.proofJson());
        var reexported = SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(g1(p.piA()), g2(p.piB()), g1(p.piC())));
        assertEquals(result.proofJson(), reexported);
        assertEquals(result.publicJson(), SnarkjsGroth16Json.publicJson(publicInputs(witness, 1)));
        var vk = SnarkjsJsonCodec.parseVerificationKey(result.vkJson());
        assertEquals(result.vkJson(), SnarkjsGroth16Json.verificationKeyJson(g1(vk.vkAlpha1()), g2(vk.vkBeta2()),
                g2(vk.vkGamma2()), g2(vk.vkDelta2()), vk.ic().stream().map(SnarkjsGroth16InteropTest::g1).toArray(AffineG1[]::new)));
    }

    // ------------------------------------------------------------ helpers

    /** Add one to the first decimal coordinate in a proof.json (pi_a.x): the point leaves the curve. */
    private static String bumpFirstCoordinate(String proofJson) {
        int q1 = proofJson.indexOf('"', proofJson.indexOf("\"pi_a\"") + 6);
        int q2 = proofJson.indexOf('"', q1 + 1);
        var x = new BigInteger(proofJson.substring(q1 + 1, q2)).add(BigInteger.ONE);
        return proofJson.substring(0, q1 + 1) + x + proofJson.substring(q2);
    }

    private static AffineG1 g1(List<BigInteger> c) {
        return new AffineG1(MontFp381.fromBigInteger(c.get(0)), MontFp381.fromBigInteger(c.get(1)));
    }

    private static AffineG2 g2(List<List<BigInteger>> c) {
        return new AffineG2(MontFp2_381.of(c.get(0).get(0), c.get(0).get(1)), MontFp2_381.of(c.get(1).get(0), c.get(1).get(1)));
    }
}
