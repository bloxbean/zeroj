package org.zeroj.it.snarkjs;

import org.zeroj.api.CurveId;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.plonk.PlonKConstraintSystem;
import org.zeroj.crypto.plonk.PlonKProofBLS381;
import org.zeroj.crypto.plonk.PlonKProverBLS381;
import org.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import org.zeroj.crypto.plonk.PlonKSetupBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;

import java.math.BigInteger;

/** ZeroJ-native PlonK setup + snarkjs-transcript prove for a DSL circuit (test-only, insecure SRS). */
final class ZeroJPlonk {

    private ZeroJPlonk() {}

    /** One arithmetisation + one proving key; prove as many witnesses under it as needed. */
    record Setup(PlonKConstraintSystem plonk, PlonKProvingKeyBLS381 pk) {}

    record Run(PlonKProvingKeyBLS381 pk, PlonKProofBLS381 proof, BigInteger[] publicInputs) {}

    static Setup setup(CircuitBuilder circuit) {
        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        var srs = PowersOfTauBLS381.generate(8);
        int numGates = plonk.numGates();
        var gs = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var r = plonk.gateRows().get(i);
            gs[i] = new BigInteger[]{r.qL(), r.qR(), r.qO(), r.qM(), r.qC()};
        }
        var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), gs,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);
        return new Setup(plonk, pk);
    }

    /** Prove {@code witness} under an existing key — the only way to build a same-key negative. */
    static Run prove(Setup setup, BigInteger[] witness) {
        var plonk = setup.plonk();
        var pk = setup.pk();
        var ext = plonk.extendWitness(witness);
        int n = pk.domainSize();
        int numGates = plonk.numGates();
        var wireA = new MontFr381[n];
        var wireB = new MontFr381[n];
        var wireC = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(ext[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(ext[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(ext[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
            }
        }
        var pub = new BigInteger[plonk.numPublicInputs()];
        System.arraycopy(witness, 1, pub, 0, pub.length);
        return new Run(pk, PlonKProverBLS381.prove(pk, wireA, wireB, wireC, pub), pub);
    }

    static Run setupAndProve(CircuitBuilder circuit, BigInteger[] witness) {
        return prove(setup(circuit), witness);
    }
}
