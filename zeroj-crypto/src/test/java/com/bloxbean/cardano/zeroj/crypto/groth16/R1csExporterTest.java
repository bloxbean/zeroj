package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0031 M1: {@link R1csExporter} must be the byte-level inverse of {@link R1CSImporter} —
 * export → import returns the same prime, dimensions, and constraint maps (canonical coefficients).
 */
class R1csExporterTest {

    private static final BigInteger FR = MontFr381.modulus();

    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> c = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            c.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        c.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return c;
    }

    @Test
    void exportImport_roundTrip() throws Exception {
        int n = 64, numWires = n + 2, numPublic = 1;
        var cons = chain(n);

        var bos = new ByteArrayOutputStream();
        R1csExporter.export(cons, numWires, numPublic, bos);
        var data = R1CSImporter.importR1CS(new ByteArrayInputStream(bos.toByteArray()));

        assertEquals(FR, data.prime(), "prime = BLS12-381 Fr");
        assertEquals(numWires, data.numWires(), "wires");
        assertEquals(numPublic, data.numPublic(), "publics");
        assertEquals(cons.size(), data.numConstraints(), "constraints");
        for (int i = 0; i < cons.size(); i++) {
            assertEquals(cons.get(i).a(), data.constraints().get(i).a(), "A[" + i + "]");
            assertEquals(cons.get(i).b(), data.constraints().get(i).b(), "B[" + i + "]");
            assertEquals(cons.get(i).c(), data.constraints().get(i).c(), "C[" + i + "]");
        }
    }

    @Test
    void export_negativeAndZeroCoefficients_canonicalized() throws Exception {
        // -1 must round-trip as FR-1; explicit zero coefficients must be dropped
        var cons = List.of(new R1CSConstraint(
                Map.of(1, BigInteger.valueOf(-1), 2, BigInteger.ZERO),
                Map.of(0, BigInteger.ONE),
                Map.of(3, FR.add(BigInteger.TWO)))); // ≡ 2 mod FR
        var bos = new ByteArrayOutputStream();
        R1csExporter.export(cons, 5, 1, bos);
        var data = R1CSImporter.importR1CS(new ByteArrayInputStream(bos.toByteArray()));

        var a = data.constraints().get(0).a();
        assertEquals(FR.subtract(BigInteger.ONE), a.get(1), "-1 canonicalized");
        assertFalse(a.containsKey(2), "zero coefficient dropped");
        assertEquals(BigInteger.TWO, data.constraints().get(0).c().get(3), "over-modulus reduced");
    }
}
