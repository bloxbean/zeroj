package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PlonKProverTest {

    private static final String PTAU_PATH = "/test-circuits/plonk-multiplier/pot8_final.ptau";

    @Test
    void prover_producesStructurallyValidProof() throws IOException {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        var plonk = circuit.compilePlonK(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        var srs = PtauImporter.importPtau(getClass().getResourceAsStream(PTAU_PATH), 256);
        int numGates = plonk.numGates();
        BigInteger[][] gs = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var r = plonk.gateRows().get(i);
            gs[i] = new BigInteger[]{r.qL(), r.qR(), r.qO(), r.qM(), r.qC()};
        }
        var pk = PlonKSetup.setup(numGates, plonk.numPublicInputs(), gs,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);

        // Build wire evaluations from witness and gate rows
        var extWitness = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr254[] wireA = new MontFr254[n];
        MontFr254[] wireB = new MontFr254[n];
        MontFr254[] wireC = new MontFr254[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr254.fromBigInteger(extWitness[row.wireA()]);
                wireB[i] = MontFr254.fromBigInteger(extWitness[row.wireB()]);
                wireC[i] = MontFr254.fromBigInteger(extWitness[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr254.ZERO;
            }
        }

        BigInteger[] pubInputs = new BigInteger[plonk.numPublicInputs()];
        for (int i = 0; i < pubInputs.length; i++) pubInputs[i] = witness[i + 1];

        var proof = PlonKProver.prove(pk, wireA, wireB, wireC, pubInputs);

        assertNotNull(proof);
        assertTrue(proof.commitA().isOnCurve() || proof.commitA().isInfinity(), "A on curve");
        assertTrue(proof.commitZ().isOnCurve() || proof.commitZ().isInfinity(), "Z on curve");
        assertTrue(proof.commitWxi().isOnCurve() || proof.commitWxi().isInfinity(), "Wxi on curve");
        assertTrue(proof.commitWxiw().isOnCurve() || proof.commitWxiw().isInfinity(), "Wxiw on curve");

        BigInteger r = MontFr254.modulus();
        assertTrue(proof.evalA().compareTo(r) < 0, "evalA in field");
        assertTrue(proof.evalZw().compareTo(r) < 0, "evalZw in field");

        System.out.println("PlonK proof generated (pure Java DSL-native):");
        System.out.println("  A on curve: " + proof.commitA().isOnCurve());
        System.out.println("  Z on curve: " + proof.commitZ().isOnCurve());
        System.out.println("  evalA = " + proof.evalA());
    }
}
