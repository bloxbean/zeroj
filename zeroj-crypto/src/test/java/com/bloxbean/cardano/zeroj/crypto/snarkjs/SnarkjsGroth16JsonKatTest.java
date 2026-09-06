package com.bloxbean.cardano.zeroj.crypto.snarkjs;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.codec.SnarkjsVerificationKey;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyImporterBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0047 M1 known-answer tests for {@link SnarkjsGroth16Json}.
 *
 * <p>The oracle is snarkjs v0.7.6 itself: every BLS12-381 Groth16 artifact snarkjs wrote into this
 * repository is parsed, re-exported, and required to be <b>byte-identical</b> to the original. That
 * pins key order, point/scalar encoding, indentation, the missing trailing newline and — through
 * {@code vk_alphabeta_12} — the pairing-value convention (wasmcurves' final exponentiation is the
 * cube of ZeroJ's). Nothing here needs snarkjs installed; the live CLI round trips live in
 * zeroj-integration-tests.</p>
 */
class SnarkjsGroth16JsonKatTest {

    private static final String TV = "/test-vectors/groth16-bls12381/";
    private static final BigInteger FR = MontFr381.modulus();

    // ---------------------------------------------------------------- byte-identical re-export

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "/test-circuits/multiplier-bls381/verification_key.json",
            "/test-circuits/cubic-bls381/verification_key.json",
            "/test-vectors/groth16-bls12381/verification_key.json"})
    void verificationKey_reexportIsByteIdenticalToSnarkjs(String resource) throws IOException {
        String original = load(resource);
        var vk = SnarkjsJsonCodec.parseVerificationKey(original);
        String exported = SnarkjsGroth16Json.verificationKeyJson(
                g1(vk.vkAlpha1()), g2(vk.vkBeta2()), g2(vk.vkGamma2()), g2(vk.vkDelta2()), ic(vk));
        assertEquals(original, exported, "re-exported verification_key.json must equal snarkjs' bytes");
        assertArrayEquals(original.getBytes(StandardCharsets.UTF_8), exported.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void proof_reexportIsByteIdenticalToSnarkjs() throws IOException {
        String original = load(TV + "proof.json");
        var p = SnarkjsJsonCodec.parseProof(original);
        var proof = new Groth16ProofBLS381(g1(p.piA()), g2(p.piB()), g1(p.piC()));
        assertEquals(original, SnarkjsGroth16Json.proofJson(proof));
    }

    @Test
    void publicInputs_reexportIsByteIdenticalToSnarkjs() throws IOException {
        String original = load(TV + "public.json");
        assertEquals("[\n \"33\",\n \"3\"\n]", original, "fixture sanity: snarkjs public.json layout");
        assertEquals(original, SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.valueOf(33), BigInteger.valueOf(3)}));
    }

    @Test
    void exportedText_hasNoTrailingNewlineAndOneSpaceIndent() throws IOException {
        String original = load(TV + "verification_key.json");
        assertFalse(original.endsWith("\n"), "fixture sanity: snarkjs writes no trailing newline");
        assertTrue(original.startsWith("{\n \"protocol\": \"groth16\",\n \"curve\": \"bls12381\",\n \"nPublic\": 2,\n"));
    }

    // ---------------------------------------------------------------- vk_alphabeta_12 pairing convention

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "/test-circuits/multiplier-bls381/verification_key.json",
            "/test-circuits/cubic-bls381/verification_key.json",
            "/test-vectors/groth16-bls12381/verification_key.json"})
    void alphaBeta12_isTheCubeOfZeroJPairing(String resource) throws IOException {
        var vk = SnarkjsJsonCodec.parseVerificationKey(load(resource));
        var alpha = new G1Point(Fp.of(vk.vkAlpha1().get(0)), Fp.of(vk.vkAlpha1().get(1)));
        var beta = new G2Point(
                Fp2.of(Fp.of(vk.vkBeta2().get(0).get(0)), Fp.of(vk.vkBeta2().get(0).get(1))),
                Fp2.of(Fp.of(vk.vkBeta2().get(1).get(0)), Fp.of(vk.vkBeta2().get(1).get(1))));
        var e = BLS12381Pairing.finalExponentiation(BLS12381Pairing.millerLoop(alpha, beta));

        var expected = vk.vkAlphabeta12();
        var exported = SnarkjsGroth16Json.alphaBeta12(g1(vk.vkAlpha1()), g2(vk.vkBeta2()));
        assertEquals(strings(expected), exported, "exporter must emit snarkjs' vk_alphabeta_12");

        // Independent statement of the relation: snarkjs' value == e_ZeroJ^3, and != e_ZeroJ.
        var cubed = e.square().mul(e);
        assertEquals(expected.get(0).get(0).get(0), cubed.c0().c0().c0().value(), "c0.c0.c0 of e^3");
        assertEquals(expected.get(1).get(2).get(1), cubed.c1().c2().c1().value(), "c1.c2.c1 of e^3");
        assertNotEquals(expected.get(0).get(0).get(0), e.c0().c0().c0().value(),
                "the uncubed (p^12-1)/r exponent must NOT match — the cube is load-bearing, not incidental");
    }

    // ---------------------------------------------------------------- round trips inside the JVM

    @Test
    void nativeSetup_exportedArtifactsVerifyThroughSnarkjsCodecAndZeroJVerifier() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);
        var keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(0x5eed));
        var proof = keys.prove(witness, r1cs.constraints());
        BigInteger[] pub = new BigInteger[r1cs.numPublicInputs()];
        System.arraycopy(witness, 1, pub, 0, pub.length);

        String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
        String proofJson = SnarkjsGroth16Json.proofJson(proof);
        String publicJson = SnarkjsGroth16Json.publicJson(pub);

        var parsed = SnarkjsJsonCodec.parseVerificationKey(vkJson);
        assertEquals(r1cs.numPublicInputs(), parsed.nPublic());
        assertEquals(r1cs.numPublicInputs() + 1, parsed.ic().size());
        assertEquals("bls12381", parsed.curve());

        var verifier = new Groth16BLS12381PureJavaVerifier();
        assertTrue(verifier.verify(envelope(proofJson, vkJson, publicJson), material(vkJson)).proofValid(),
                "exported proof/VK/public must verify through the snarkjs codec + ZeroJ verifier");

        String wrongPublic = SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.valueOf(34)});
        assertFalse(verifier.verify(envelope(proofJson, vkJson, wrongPublic), material(vkJson)).proofValid(),
                "tampered public input must not verify");
    }

    @Test
    void storeLoadedKeys_exportTheSameVerificationKeyAsTheInHeapSetup(@TempDir Path dir) throws IOException {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var sr = Groth16SetupBLS381.setup(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(0x5eed));
        String fromSetup = SnarkjsGroth16Json.verificationKeyJson(sr);
        assertEquals(fromSetup, SnarkjsGroth16Json.verificationKeyJson(Groth16Keys.of(sr)));

        Groth16PkStore.save(sr, dir);
        try (var loaded = Groth16Keys.load(dir)) {
            assertEquals(fromSetup, SnarkjsGroth16Json.verificationKeyJson(loaded),
                    "a Groth16PkStore-loaded handle must export the same VK as the in-heap setup");
        }
    }

    @Test
    void zkeyProof_exportedWithSnarkjsOwnVerificationKey_verifies() throws IOException {
        var zkey = ZkeyImporterBLS381.importZkeyFull(
                getClass().getResourceAsStream("/test-circuits/multiplier-bls381/multiplier.zkey").readAllBytes());
        var witness = ZkeyImporterBLS381.importWtns(
                getClass().getResourceAsStream("/test-circuits/multiplier-bls381/witness.wtns"));
        String vkJson = load("/test-circuits/multiplier-bls381/verification_key.json");
        int nPublic = SnarkjsJsonCodec.parseVerificationKey(vkJson).nPublic();

        var proof = Groth16ProverBLS381.prove(zkey.provingKey(), witness, zkey.constraints(), zkey.numWires());
        BigInteger[] pub = new BigInteger[nPublic];
        System.arraycopy(witness, 1, pub, 0, nPublic);

        String proofJson = SnarkjsGroth16Json.proofJson(proof);
        String publicJson = SnarkjsGroth16Json.publicJson(pub);
        assertTrue(new Groth16BLS12381PureJavaVerifier()
                .verify(envelope(proofJson, vkJson, publicJson), material(vkJson)).proofValid());
    }

    // ---------------------------------------------------------------- egress checks fail closed

    @Test
    void rejectsInfinityPoints() throws IOException {
        var vk = SnarkjsJsonCodec.parseVerificationKey(load(TV + "verification_key.json"));
        var p = SnarkjsJsonCodec.parseProof(load(TV + "proof.json"));
        var a = g1(p.piA()); var b = g2(p.piB()); var c = g1(p.piC());

        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(AffineG1.INFINITY, b, c)));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(a, AffineG2.INFINITY, c)));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(a, b, AffineG1.INFINITY)));

        var icInf = ic(vk);
        icInf[1] = AffineG1.INFINITY;
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.verificationKeyJson(
                g1(vk.vkAlpha1()), g2(vk.vkBeta2()), g2(vk.vkGamma2()), g2(vk.vkDelta2()), icInf),
                "ADR-0045: an infinity IC entry is never exportable");
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.verificationKeyJson(
                AffineG1.INFINITY, g2(vk.vkBeta2()), g2(vk.vkGamma2()), g2(vk.vkDelta2()), ic(vk)));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.verificationKeyJson(
                g1(vk.vkAlpha1()), g2(vk.vkBeta2()), AffineG2.INFINITY, g2(vk.vkDelta2()), ic(vk)));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.verificationKeyJson(
                g1(vk.vkAlpha1()), g2(vk.vkBeta2()), g2(vk.vkGamma2()), g2(vk.vkDelta2()), new AffineG1[0]));
    }

    @Test
    void rejectsOffCurveAndOffSubgroupPoints() throws IOException {
        var p = SnarkjsJsonCodec.parseProof(load(TV + "proof.json"));
        var a = g1(p.piA()); var b = g2(p.piB()); var c = g1(p.piC());

        // off-curve: y + 1
        var offCurve = new AffineG1(a.x(), a.y().add(MontFp381.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(offCurve, b, c)));

        // on-curve but not in the prime-order subgroup: a point of order 3 on E(Fp) (x = 0, y = sqrt(4)),
        // which lies on y^2 = x^3 + 4 and is a classic small-subgroup point on BLS12-381.
        var smallOrder = new AffineG1(MontFp381.ZERO, MontFp381.fromBigInteger(BigInteger.TWO));
        assertTrue(new G1Point(Fp.ZERO, Fp.of(2)).isOnCurve(), "fixture sanity: (0, 2) is on the curve");
        assertFalse(new G1Point(Fp.ZERO, Fp.of(2)).isInSubgroup(), "fixture sanity: (0, 2) is not in G1");
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(smallOrder, b, c)));

        var offTwist = new AffineG2(b.x(), MontFp2_381.of(b.y().re().add(MontFp381.ONE), b.y().im()));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(a, offTwist, c)));
    }

    @Test
    void rejectsNonCanonicalScalars() {
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.publicJson(new BigInteger[]{FR}));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.publicJson(new BigInteger[]{FR.add(BigInteger.ONE)}));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.ONE.negate()}));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.ONE, null}));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsGroth16Json.publicJson(null));
        assertEquals("[\n \"0\",\n \"" + FR.subtract(BigInteger.ONE) + "\"\n]",
                SnarkjsGroth16Json.publicJson(new BigInteger[]{BigInteger.ZERO, FR.subtract(BigInteger.ONE)}));
        // nPublic = 0: snarkjs writes public.json through bfj, which spreads an empty array over two
        // lines ("[\n]"); JSON.stringify would give "[]". Verified against bfj 7.1.0 (snarkjs' dependency).
        assertEquals("[\n]", SnarkjsGroth16Json.publicJson(new BigInteger[0]));
    }

    // ---------------------------------------------------------------- helpers

    private static AffineG1 g1(List<BigInteger> c) {
        return new AffineG1(MontFp381.fromBigInteger(c.get(0)), MontFp381.fromBigInteger(c.get(1)));
    }

    private static AffineG2 g2(List<List<BigInteger>> c) {
        return new AffineG2(MontFp2_381.of(c.get(0).get(0), c.get(0).get(1)),
                MontFp2_381.of(c.get(1).get(0), c.get(1).get(1)));
    }

    private static AffineG1[] ic(SnarkjsVerificationKey vk) {
        return vk.ic().stream().map(SnarkjsGroth16JsonKatTest::g1).toArray(AffineG1[]::new);
    }

    private static List<List<List<String>>> strings(List<List<List<BigInteger>>> v) {
        return v.stream().map(f6 -> f6.stream().map(f2 -> f2.stream().map(BigInteger::toString).toList()).toList()).toList();
    }

    private static ZkProofEnvelope envelope(String proof, String vk, String pub) {
        return SnarkjsJsonCodec.toEnvelopeFromJson(proof, vk, pub, new CircuitId("adr-0047-kat"));
    }

    private static VerificationMaterial material(String vkJson) {
        return VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8), ProofSystemId.GROTH16,
                CurveId.BLS12_381, new CircuitId("adr-0047-kat"));
    }

    private String load(String resource) throws IOException {
        try (var in = getClass().getResourceAsStream(resource)) {
            if (in == null) throw new IOException("missing test resource " + resource);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
