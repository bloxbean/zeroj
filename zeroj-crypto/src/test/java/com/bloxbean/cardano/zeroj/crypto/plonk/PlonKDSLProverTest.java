package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the DSL-native PlonK proving pipeline.
 *
 * <p>Pipeline: CircuitBuilder → PlonKCompiler → PlonKSetup (with .ptau SRS)
 * → PlonKProver → verify</p>
 */
class PlonKDSLProverTest {

    private static final String PTAU_PATH = "/test-circuits/plonk-multiplier/pot8_final.ptau";

    @Test
    void ptauImport_generatorCorrect() throws IOException {
        var srs = PtauImporter.importPtau(getClass().getResourceAsStream(PTAU_PATH), 16);

        // tau^0 * G1 should be the generator (1, 2)
        var g1 = srs.tauG1()[0];
        assertEquals(BigInteger.ONE, g1.xBigInt(), "tau^0 * G1 should be generator x=1");
        assertEquals(BigInteger.TWO, g1.yBigInt(), "tau^0 * G1 should be generator y=2");
        assertTrue(g1.isOnCurve());

        // tau^1 * G1 should be on curve and not generator
        assertTrue(srs.tauG1()[1].isOnCurve());
        assertNotEquals(BigInteger.ONE, srs.tauG1()[1].xBigInt());

        // G2 points
        assertTrue(srs.tauG2()[0].isOnCurve(), "G2 generator on curve");
        assertTrue(srs.x2().isOnCurve(), "tau*G2 on curve");
    }

    @Test
    void dslSetup_multiplierCircuit() throws IOException {
        // Define circuit with our DSL
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        // Compile to PlonK
        var plonk = circuit.compilePlonK(CurveId.BN254);
        assertTrue(plonk.numGates() > 0);

        // Import SRS
        var srs = PtauImporter.importPtau(getClass().getResourceAsStream(PTAU_PATH), 256);

        // Extract gate selectors from PlonK constraint system
        int numGates = plonk.numGates();
        BigInteger[][] gateSelectors = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gateSelectors[i] = new BigInteger[]{
                    row.qL(), row.qR(), row.qO(), row.qM(), row.qC()
            };
        }

        // Run setup
        var pk = PlonKSetup.setup(
                numGates, plonk.numPublicInputs(),
                gateSelectors,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(),
                plonk.numWires(), srs);

        assertNotNull(pk);
        assertTrue(pk.domainSize() >= numGates);
        assertEquals(plonk.numPublicInputs(), pk.nPublic());

        // Commitments should be on curve
        assertTrue(pk.qlCommit().isOnCurve() || pk.qlCommit().isInfinity(), "Ql on curve");
        assertTrue(pk.qmCommit().isOnCurve() || pk.qmCommit().isInfinity(), "Qm on curve");
        assertTrue(pk.s1Commit().isOnCurve() || pk.s1Commit().isInfinity(), "S1 on curve");

        // Omega should satisfy omega^domainSize = 1
        var omegaN = pk.omega();
        for (int i = 1; i < pk.domainSize(); i++) omegaN = omegaN.mul(pk.omega());
        assertTrue(omegaN.isOne(), "omega^n should be 1");

        System.out.println("DSL PlonK setup complete:");
        System.out.println("  numGates=" + numGates + " domainSize=" + pk.domainSize());
        System.out.println("  numPublic=" + pk.nPublic());
        System.out.println("  Qm commit x=" + pk.qmCommit().xBigInt());
    }

    @Test
    void dslSetup_gateEquationSatisfied() throws IOException {
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
        BigInteger[][] gateSelectors = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gateSelectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }

        var pk = PlonKSetup.setup(numGates, plonk.numPublicInputs(),
                gateSelectors, plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(),
                plonk.numWires(), srs);

        // Verify: Ql[i]*a + Qr[i]*b + Qm[i]*a*b + Qo[i]*c + Qc[i] = 0
        // Skip public input rows (first nPublic) — they satisfy gate + PI = 0
        BigInteger p = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"); // Fr
        var gateRows = plonk.gateRows();
        int nPub = plonk.numPublicInputs();
        for (int i = nPub; i < numGates; i++) {
            var row = gateRows.get(i);
            BigInteger a = witness[row.wireA()];
            BigInteger b = witness[row.wireB()];
            BigInteger c = witness[row.wireC()];

            BigInteger gate = row.qL().multiply(a)
                    .add(row.qR().multiply(b))
                    .add(row.qO().multiply(c))
                    .add(row.qM().multiply(a).multiply(b))
                    .add(row.qC())
                    .mod(p);

            assertEquals(BigInteger.ZERO, gate,
                    "Gate " + i + " not satisfied: qL=" + row.qL() + " qM=" + row.qM()
                            + " a=" + a + " b=" + b + " c=" + c);
        }

        // Also verify the setup's selector evaluations match
        // pk.ql()[i] should equal the gate selector ql at omega^i
        // (since the setup builds evaluations on the domain from gate rows)
        for (int i = 0; i < numGates; i++) {
            assertEquals(gateSelectors[i][0].mod(p), pk.ql()[i].toBigInteger(),
                    "Ql mismatch at row " + i);
        }

        System.out.println("All " + numGates + " gate equations satisfied by witness");
    }
}
