package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ZkeyConstraintDebugTest {

    static final BigInteger R = MontFr254.modulus();

    @Test
    void zkeyConstraints_satisfiedByWtnsWitness() throws IOException {
        var witness = ZkeyImporter.importWtns(
                getClass().getResourceAsStream("/test-circuits/multiplier/multiplier_witness.wtns"));

        var r1csData = R1CSImporter.importR1CS(
                getClass().getResourceAsStream("/test-circuits/multiplier/multiplier.r1cs"));

        System.out.println("=== R1CS constraints from .r1cs file ===");
        System.out.println("nWires=" + r1csData.numWires() + " nConstraints=" + r1csData.numConstraints()
                + " nPublic=" + r1csData.numPublic());
        System.out.println("witness length=" + witness.length);
        for (int i = 0; i < witness.length; i++) {
            System.out.println("  w[" + i + "] = " + witness[i]);
        }

        for (int i = 0; i < r1csData.numConstraints(); i++) {
            var c = r1csData.constraints()[i];
            BigInteger aVal = evalLC(c.a(), witness);
            BigInteger bVal = evalLC(c.b(), witness);
            BigInteger cVal = evalLC(c.c(), witness);
            BigInteger lhs = aVal.multiply(bVal).mod(R);
            System.out.println("R1CS[" + i + "]: A·w=" + aVal + " B·w=" + bVal + " C·w=" + cVal
                    + " A*B=" + lhs + " sat=" + lhs.equals(cVal));
            System.out.println("  A=" + c.a() + " B=" + c.b() + " C=" + c.c());
            assertEquals(lhs, cVal, "R1CS constraint " + i + " not satisfied");
        }

        // Also check the .zkey constraints for comparison
        var zkeyData = ZkeyImporter.importZkeyFull(
                getClass().getResourceAsStream("/test-circuits/multiplier/multiplier.zkey").readAllBytes());

        System.out.println("nVars=" + zkeyData.numWires() + " nConstraints=" + zkeyData.numConstraints()
                + " domainSize=" + zkeyData.domainSize() + " nPublic=" + zkeyData.provingKey().numPublic());
        System.out.println("witness length=" + witness.length);
        for (int i = 0; i < witness.length; i++) {
            System.out.println("  w[" + i + "] = " + witness[i]);
        }

        int satisfied = 0, total = 0;
        for (int i = 0; i < zkeyData.constraints().length; i++) {
            var c = zkeyData.constraints()[i];
            if (c.a().isEmpty() && c.b().isEmpty() && c.c().isEmpty()) continue;
            total++;

            BigInteger aVal = evalLC(c.a(), witness);
            BigInteger bVal = evalLC(c.b(), witness);
            BigInteger cVal = evalLC(c.c(), witness);
            BigInteger lhs = aVal.multiply(bVal).mod(R);

            boolean ok = lhs.equals(cVal);
            if (ok) satisfied++;
            System.out.println("Constraint " + i + ": A·w=" + aVal + " B·w=" + bVal + " C·w=" + cVal
                    + " A*B=" + lhs + " satisfied=" + ok);
            if (!ok) {
                System.out.println("  A terms: " + c.a());
                System.out.println("  B terms: " + c.b());
                System.out.println("  C terms: " + c.c());
            }
        }
        System.out.println(satisfied + "/" + total + " constraints satisfied");
        assertEquals(total, satisfied, "All non-empty constraints must be satisfied");
    }

    private BigInteger evalLC(Map<Integer, BigInteger> lc, BigInteger[] witness) {
        BigInteger sum = BigInteger.ZERO;
        for (var e : lc.entrySet()) {
            if (e.getKey() < witness.length) {
                sum = sum.add(e.getValue().multiply(witness[e.getKey()]));
            }
        }
        return sum.mod(R);
    }
}
