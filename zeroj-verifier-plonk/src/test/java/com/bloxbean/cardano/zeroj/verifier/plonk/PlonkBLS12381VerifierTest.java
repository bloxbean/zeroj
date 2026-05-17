package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PlonkBLS12381VerifierTest {

    @Test
    void verify_javaGeneratedProof_accepts() {
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

        var proof = PlonKProverBLS381.prove(pk, wireA, wireB, wireC, publicInputs);
        String proofJson = proofJson(proof);
        String vkJson = vkJson(pk);
        String publicJson = "[\"33\"]";

        var envelope = SnarkjsPlonkCodec.toEnvelopeFromJson(
                proofJson, vkJson, publicJson, new CircuitId("bls381-plonk-multiplier"));
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.PLONK, CurveId.BLS12_381, new CircuitId("bls381-plonk-multiplier"));

        var result = new PlonkBLS12381Verifier().verify(envelope, material);
        assertTrue(result.proofValid(), () -> result.message().orElse("verification failed"));
    }

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
