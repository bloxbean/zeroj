package org.zeroj.crypto.plonk;

import org.zeroj.api.CurveId;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.field.Fp;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PlonKBLS381InvariantTest {

    private static final BigInteger FR = MontFr381.modulus();

    private static Fixture fixture;

    @BeforeAll
    static void setUp() {
        fixture = buildFixture();
    }

    @Test
    void setup_rejectsSelectorOutsideScalarField() {
        BigInteger[][] selectors = copySelectors(fixture.gateSelectors());
        selectors[0][0] = FR;

        assertThrows(IllegalArgumentException.class, () -> setupWith(selectors,
                fixture.sigmaA(), fixture.sigmaB(), fixture.sigmaC(), fixture.srs()));
    }

    @Test
    void setup_rejectsSigmaTargetOutsidePermutationRange() {
        int[] sigmaA = fixture.sigmaA().clone();
        sigmaA[0] = 3 * fixture.numGates();

        assertThrows(IllegalArgumentException.class, () -> setupWith(fixture.gateSelectors(),
                sigmaA, fixture.sigmaB(), fixture.sigmaC(), fixture.srs()));
    }

    @Test
    void setup_rejectsSrsTooShortForBlindedPlonkPolynomials() {
        var shortSrs = new PtauImporterBLS381.SRS(
                Arrays.copyOf(fixture.srs().tauG1(), 15),
                fixture.srs().tauG2(),
                fixture.srs().power(),
                fixture.srs().tauScalar());

        assertThrows(IllegalArgumentException.class, () -> setupWith(fixture.gateSelectors(),
                fixture.sigmaA(), fixture.sigmaB(), fixture.sigmaC(), shortSrs));
    }

    @Test
    void setup_rejectsInconsistentSrsPowersOfTau() {
        var badTauG1 = fixture.srs().tauG1().clone();
        badTauG1[1] = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.TWO).toAffine();
        var badSrs = new PtauImporterBLS381.SRS(
                badTauG1,
                fixture.srs().tauG2(),
                fixture.srs().power(),
                fixture.srs().tauScalar());

        assertThrows(IllegalArgumentException.class, () -> setupWith(fixture.gateSelectors(),
                fixture.sigmaA(), fixture.sigmaB(), fixture.sigmaC(), badSrs));
    }

    @Test
    void prover_rejectsOversizedWireArray() {
        MontFr381[] oversizedWireA = Arrays.copyOf(fixture.wireA(), fixture.wireA().length + 1);
        oversizedWireA[oversizedWireA.length - 1] = MontFr381.ZERO;

        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.prove(
                fixture.provingKey(), oversizedWireA, fixture.wireB(), fixture.wireC(), fixture.pubInputs()));
    }

    @Test
    void prover_rejectsNullWireEntry() {
        MontFr381[] wireA = fixture.wireA().clone();
        wireA[0] = null;

        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.prove(
                fixture.provingKey(), wireA, fixture.wireB(), fixture.wireC(), fixture.pubInputs()));
    }

    @Test
    void prover_rejectsPublicInputOutsideScalarField() {
        BigInteger[] pubInputs = fixture.pubInputs().clone();
        pubInputs[0] = FR;

        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.prove(
                fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), pubInputs));
    }

    @Test
    void prover_rejectsNullSecureRandom() {
        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.prove(
                fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), fixture.pubInputs(), null));
    }

    @Test
    void cardanoV1Prover_rejectsMultiplePublicInputs() {
        BigInteger[] pubInputs = new BigInteger[]{BigInteger.ONE, BigInteger.TWO};

        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.proveCardano(
                fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), pubInputs));
    }

    @Test
    void cardanoMpiProver_rejectsEmptyPublicInputs() {
        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.proveCardanoMpi(
                fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), new BigInteger[0]));
    }

    @Test
    void cardanoMpiProver_rejectsMoreThanEightPublicInputs() {
        BigInteger[] pubInputs = new BigInteger[PlonKProverBLS381.MAX_CARDANO_MPI_PUBLIC_INPUTS + 1];
        Arrays.fill(pubInputs, BigInteger.ONE);

        assertThrows(IllegalArgumentException.class, () -> PlonKProverBLS381.proveCardanoMpi(
                fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), pubInputs));
    }

    @Test
    void quotientBlindersHaveReferenceCommitmentDeltasInEveryProfile() {
        for (int profile = 0; profile < 3; profile++) {
            var baseRng = new SplitBlinderRandom(0, 0);
            var base = proof(profile, baseRng);
            assertEquals(11, baseRng.draws, "every public profile must sample all eleven blinders");
            var ten = proof(profile, new SplitBlinderRandom(7, 0));
            var eleven = proof(profile, new SplitBlinderRandom(0, 13));
            assertEquals(base.commitA(), ten.commitA());
            assertEquals(base.commitB(), ten.commitB());
            assertEquals(base.commitC(), eleven.commitC());
            assertEquals(base.commitZ(), eleven.commitZ());
            G1Point gn = point(fixture.provingKey().srsG1()[fixture.provingKey().domainSize()]);
            G1Point g0 = point(fixture.provingKey().srsG1()[0]);
            assertEquals(point(base.commitT1()).add(gn.scalarMul(BigInteger.valueOf(7))), point(ten.commitT1()));
            assertEquals(point(base.commitT2()).add(g0.scalarMul(BigInteger.valueOf(-7))), point(ten.commitT2()));
            assertEquals(base.commitT3(), ten.commitT3());
            assertEquals(base.commitT1(), eleven.commitT1());
            assertEquals(point(base.commitT2()).add(gn.scalarMul(BigInteger.valueOf(13))), point(eleven.commitT2()));
            assertEquals(point(base.commitT3()).add(g0.scalarMul(BigInteger.valueOf(-13))), point(eleven.commitT3()));
        }
    }

    private static G1Point point(JacobianG1BLS381.AffineG1 p) {
        return p.isInfinity() ? G1Point.INFINITY : new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static PlonKProofBLS381 proof(int profile, SecureRandom rng) {
        return switch (profile) {
            case 0 -> PlonKProverBLS381.prove(fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), fixture.pubInputs(), rng);
            case 1 -> PlonKProverBLS381.proveCardano(fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), fixture.pubInputs(), rng);
            default -> PlonKProverBLS381.proveCardanoMpi(fixture.provingKey(), fixture.wireA(), fixture.wireB(), fixture.wireC(), fixture.pubInputs(), rng);
        };
    }

    // Test-only deterministic CSPRNG seam: first nine draws fixed; vary only quotient blinders.
    private static final class SplitBlinderRandom extends SecureRandom {
        private final int b10, b11;
        private int draws;
        SplitBlinderRandom(int b10, int b11) { this.b10 = b10; this.b11 = b11; }
        @Override public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, (byte) 0);
            draws++;
            int value = draws == 10 ? b10 : draws == 11 ? b11 : draws;
            bytes[bytes.length - 1] = (byte) value;
            if (draws > 11) throw new AssertionError("unexpected randomness draw");
        }
    }

    private static PlonKProvingKeyBLS381 setupWith(
            BigInteger[][] selectors,
            int[] sigmaA,
            int[] sigmaB,
            int[] sigmaC,
            PtauImporterBLS381.SRS srs) {
        return PlonKSetupBLS381.setup(
                fixture.numGates(),
                fixture.numPublicInputs(),
                copySelectors(selectors),
                sigmaA.clone(),
                sigmaB.clone(),
                sigmaC.clone(),
                fixture.numWires(),
                srs);
    }

    private static Fixture buildFixture() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });
        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);

        int numGates = plonk.numGates();
        BigInteger[][] selectors = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            selectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }

        var srs = PowersOfTauBLS381.generate(4);
        var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), copySelectors(selectors),
                plonk.sigmaA().clone(), plonk.sigmaB().clone(), plonk.sigmaC().clone(), plonk.numWires(), srs);

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

        BigInteger[] pubInputs = new BigInteger[plonk.numPublicInputs()];
        for (int i = 0; i < pubInputs.length; i++) {
            pubInputs[i] = witness[i + 1];
        }

        return new Fixture(numGates, plonk.numPublicInputs(), plonk.numWires(), selectors,
                plonk.sigmaA().clone(), plonk.sigmaB().clone(), plonk.sigmaC().clone(),
                srs, pk, wireA, wireB, wireC, pubInputs);
    }

    private static BigInteger[][] copySelectors(BigInteger[][] selectors) {
        BigInteger[][] copy = new BigInteger[selectors.length][];
        for (int i = 0; i < selectors.length; i++) {
            copy[i] = selectors[i].clone();
        }
        return copy;
    }

    private record Fixture(
            int numGates,
            int numPublicInputs,
            int numWires,
            BigInteger[][] gateSelectors,
            int[] sigmaA,
            int[] sigmaB,
            int[] sigmaC,
            PtauImporterBLS381.SRS srs,
            PlonKProvingKeyBLS381 provingKey,
            MontFr381[] wireA,
            MontFr381[] wireB,
            MontFr381[] wireC,
            BigInteger[] pubInputs) {
    }
}
