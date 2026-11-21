package org.zeroj.crypto.plonk;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.plonk.PlonKConstraintSystem;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0068: Batched RLC SRS consistency checks, post-import mutation detection, and
 * medium-domain PlonK setup/prover scaling correctness.
 */
class PlonKSrsAndScalingTest {

    @Test
    void batchedSrsConsistencyAcceptsValidAndRejectsEveryTamperedPower() {
        BigInteger tau = BigInteger.valueOf(19);
        int count = 16;
        AffineG1[] tauG1 = new AffineG1[count];
        BigInteger power = BigInteger.ONE;
        BigInteger fr = MontFr381.modulus();
        for (int i = 0; i < count; i++) {
            tauG1[i] = JacobianG1BLS381.GENERATOR.scalarMul(power).toAffine();
            power = power.multiply(tau).mod(fr);
        }
        AffineG2[] tauG2 = {
                JacobianG2BLS381.GENERATOR.toAffine(),
                JacobianG2BLS381.GENERATOR.scalarMul(tau).toAffine()
        };

        // Valid at count=1, count=2, and full count=16
        assertDoesNotThrow(() -> SrsConsistencyBLS381.verifyConsistency(tauG1, tauG2, 1, "test"));
        assertDoesNotThrow(() -> SrsConsistencyBLS381.verifyConsistency(tauG1, tauG2, 2, "test"));
        assertDoesNotThrow(() -> SrsConsistencyBLS381.verifyConsistency(tauG1, tauG2, count, "test"));

        // Tampering any G1 power i >= 1 must fail
        for (int badIdx : new int[]{1, 2, 7, count - 1}) {
            AffineG1[] tampered = tauG1.clone();
            tampered[badIdx] = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(badIdx + 100)).toAffine();
            assertThrows(IllegalArgumentException.class,
                    () -> SrsConsistencyBLS381.verifyConsistency(tampered, tauG2, count, "test"),
                    "Expected tampered G1[" + badIdx + "] to be rejected");
        }

        // Swapping two powers must fail
        AffineG1[] swapped = tauG1.clone();
        AffineG1 tmp = swapped[3];
        swapped[3] = swapped[4];
        swapped[4] = tmp;
        assertThrows(IllegalArgumentException.class,
                () -> SrsConsistencyBLS381.verifyConsistency(swapped, tauG2, count, "test"));

        // Wrong generator anchor must fail
        AffineG1[] badGen = tauG1.clone();
        badGen[0] = tauG1[1];
        assertThrows(IllegalArgumentException.class,
                () -> SrsConsistencyBLS381.verifyConsistency(badGen, tauG2, count, "test"));

        // Wrong tauG2[1] must fail
        AffineG2[] badTauG2 = {
                tauG2[0],
                JacobianG2BLS381.GENERATOR.scalarMul(tau.add(BigInteger.ONE)).toAffine()
        };
        assertThrows(IllegalArgumentException.class,
                () -> SrsConsistencyBLS381.verifyConsistency(tauG1, badTauG2, count, "test"));
    }

    @Test
    void verifiedSrsCacheDetectsPostImportMutationAndRejectsInSetup() {
        BigInteger tau = BigInteger.valueOf(23);
        int count = 14; // domainSize 8 + 6
        AffineG1[] tauG1 = new AffineG1[count];
        BigInteger power = BigInteger.ONE;
        BigInteger fr = MontFr381.modulus();
        for (int i = 0; i < count; i++) {
            tauG1[i] = JacobianG1BLS381.GENERATOR.scalarMul(power).toAffine();
            power = power.multiply(tau).mod(fr);
        }
        AffineG2[] tauG2 = {
                JacobianG2BLS381.GENERATOR.toAffine(),
                JacobianG2BLS381.GENERATOR.scalarMul(tau).toAffine()
        };

        var srs = new PtauImporterBLS381.SRS(tauG1, tauG2, 3);
        SrsConsistencyBLS381.recordVerified(srs);
        assertTrue(SrsConsistencyBLS381.isUnmodifiedVerified(srs, Arrays.copyOf(tauG1, count), Arrays.copyOf(tauG2, 2)));

        // Setup must pin private copies so mutating caller-owned SRS arrays AFTER setup cannot alter the returned key.
        var circuit = CircuitBuilder.create("mutated-srs")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        PlonKConstraintSystem plonk = circuit.compilePlonK(CurveId.BLS12_381);
        BigInteger[][] selectors = selectorsOf(plonk);
        PlonKProvingKeyBLS381 pk = PlonKSetupBLS381.setup(
                plonk.numGates(), plonk.numPublicInputs(), selectors,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);
        AffineG1 originalG1At5 = pk.srsG1()[5];
        AffineG2 originalX2 = pk.x2();

        // Mutate caller's arrays after setup: returned key must stay immutable AND next setup must reject the mutated SRS
        tauG1[5] = tauG1[0];
        tauG2[1] = tauG2[0];
        assertEquals(originalG1At5, pk.srsG1()[5], "post-setup caller mutation must not alter returned pk.srsG1()");
        assertEquals(originalX2, pk.x2(), "post-setup caller mutation must not alter returned pk.x2()");
        assertFalse(SrsConsistencyBLS381.isUnmodifiedVerified(srs, Arrays.copyOf(tauG1, count), Arrays.copyOf(tauG2, 2)));
        assertThrows(IllegalArgumentException.class, () -> PlonKSetupBLS381.setup(
                plonk.numGates(), plonk.numPublicInputs(), selectors,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs));
    }

    @Test
    void mediumDomainPlonkSetupAndProveWithEliminatedQuadraticLoops() {
        // Build a 180-gate chain -> domainSize = 256 (n + 6 = 262 SRS points)
        var circuit = CircuitBuilder.create("chain-180")
                .publicVar("out").secretVar("x")
                .define(api -> {
                    var cur = api.var("x");
                    for (int i = 0; i < 180; i++) {
                        cur = api.add(api.mul(cur, cur), api.constant(1));
                    }
                    api.assertEqual(cur, api.var("out"));
                });

        BigInteger x = BigInteger.valueOf(5);
        BigInteger expected = x;
        BigInteger fr = MontFr381.modulus();
        for (int i = 0; i < 180; i++) {
            expected = expected.multiply(expected).add(BigInteger.ONE).mod(fr);
        }

        BigInteger[] witness = circuit.calculateWitness(
                Map.of("x", List.of(x), "out", List.of(expected)), CurveId.BLS12_381);
        PlonKConstraintSystem plonk = circuit.compilePlonK(CurveId.BLS12_381);
        int domainSize = Integer.highestOneBit(plonk.numGates() - 1) << 1;
        int srsCount = domainSize + 6;

        BigInteger tau = BigInteger.valueOf(31);
        AffineG1[] tauG1 = new AffineG1[srsCount];
        BigInteger pow = BigInteger.ONE;
        for (int i = 0; i < srsCount; i++) {
            tauG1[i] = JacobianG1BLS381.GENERATOR.scalarMul(pow).toAffine();
            pow = pow.multiply(tau).mod(fr);
        }
        AffineG2[] tauG2 = {
                JacobianG2BLS381.GENERATOR.toAffine(),
                JacobianG2BLS381.GENERATOR.scalarMul(tau).toAffine()
        };
        var srs = new PtauImporterBLS381.SRS(tauG1, tauG2, Integer.numberOfTrailingZeros(domainSize));

        PlonKProvingKeyBLS381 pk = PlonKSetupBLS381.setup(
                plonk.numGates(), plonk.numPublicInputs(), selectorsOf(plonk),
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);

        BigInteger[] ext = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr381[] wireA = new MontFr381[n];
        MontFr381[] wireB = new MontFr381[n];
        MontFr381[] wireC = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < plonk.numGates()) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(ext[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(ext[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(ext[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
            }
        }
        BigInteger[] pubInputs = Arrays.copyOfRange(witness, 1, 1 + plonk.numPublicInputs());
        PlonKProofBLS381 proof = PlonKProverBLS381.prove(pk, wireA, wireB, wireC, pubInputs, new SecureRandom());
        assertFalse(proof.commitA().isInfinity());
        assertFalse(proof.commitWxi().isInfinity());
    }

    private static BigInteger[][] selectorsOf(PlonKConstraintSystem plonk) {
        BigInteger[][] selectors = new BigInteger[plonk.numGates()][];
        for (int i = 0; i < plonk.numGates(); i++) {
            var row = plonk.gateRows().get(i);
            selectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }
        return selectors;
    }
}
