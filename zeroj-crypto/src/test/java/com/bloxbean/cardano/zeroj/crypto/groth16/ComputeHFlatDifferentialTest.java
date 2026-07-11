package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0034 M2: {@code computeH} over the packed CSR matrices must produce exactly the same H
 * polynomial as the map-based path — including the snarkjs public-input binding rows, which the
 * CSR path handles as a row count instead of materialized {@code A={s:1},B={},C={}} rows.
 */
class ComputeHFlatDifferentialTest {

    private static final BigInteger FR = MontFr381.modulus();

    /** Squaring chain with an AssertEq output binding — mixed coefficient values. */
    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            cons.add(new R1CSConstraint(
                    Map.of(2 + i, one, 0, BigInteger.valueOf(i % 7)),  // multi-term A row
                    Map.of(2 + i, one),
                    Map.of(3 + i, one)));
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return cons;
    }

    private static BigInteger[] witness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) {
            w[2 + i] = a;
            a = a.multiply(a).add(BigInteger.valueOf(i)).mod(FR);
        }
        w[1] = w[n + 1];
        return w;
    }

    private static R1CSFlat toFlat(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    @Test
    void flatComputeH_equalsListComputeH() {
        int n = 300, domain = 512;
        var cons = chain(n);
        var w = witness(n);
        var flat = toFlat(cons);

        BigInteger[] hList = Groth16ProverBLS381.computeH(cons, w, cons.size(), domain);
        BigInteger[] hFlat = Groth16ProverBLS381.computeH(flat, w, 0, domain);
        assertArrayEquals(hList, hFlat, "CSR computeH must equal map-based computeH");
    }

    @Test
    void flatComputeH_bindingRows_equalSynthesizedRows() {
        int n = 300, domain = 512, numPublic = 1;
        var cons = chain(n);
        var w = witness(n);
        var flat = toFlat(cons);

        // Legacy path: materialized binding rows appended by snarkjsConstraints
        var synth = ZkeyPkStoreImporter.snarkjsConstraints(cons, numPublic);
        BigInteger[] hList = Groth16ProverBLS381.computeH(synth, w, synth.size(), domain);
        // CSR path: binding rows as a count
        BigInteger[] hFlat = Groth16ProverBLS381.computeH(flat, w, numPublic + 1, domain);
        assertArrayEquals(hList, hFlat, "CSR binding-row handling must equal snarkjsConstraints");
    }

    @Test
    void asList_roundTripsRows() {
        var cons = chain(64);
        var flat = toFlat(cons);
        var view = flat.asList();
        assertEquals(cons.size(), view.size());
        for (int i = 0; i < cons.size(); i++) {
            assertEquals(cons.get(i).a(), view.get(i).a(), "A row " + i);
            assertEquals(cons.get(i).b(), view.get(i).b(), "B row " + i);
            assertEquals(cons.get(i).c(), view.get(i).c(), "C row " + i);
        }
    }

    /** ADR-0034 M4: the r1cs.bin cache must round-trip to an identical H polynomial. */
    @Test
    void flatIO_roundTrip(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        int n = 300, domain = 512;
        var cons = chain(n);
        var w = witness(n);
        var flat = toFlat(cons);
        var file = dir.resolve("r1cs.bin");

        com.bloxbean.cardano.zeroj.api.R1CSFlatIO.write(flat, "c300-w302-p1", file);
        var back = com.bloxbean.cardano.zeroj.api.R1CSFlatIO.readIfMatches(file, "c300-w302-p1");
        assertNotNull(back, "matching fingerprint must load");
        assertNull(com.bloxbean.cardano.zeroj.api.R1CSFlatIO.readIfMatches(file, "c1-w2-p3"),
                "fingerprint mismatch must be a cache miss");
        assertNull(com.bloxbean.cardano.zeroj.api.R1CSFlatIO.readIfMatches(dir.resolve("absent.bin"), "x"),
                "missing file must be a cache miss");

        // structural equality via the adapter view + identical H polynomial
        assertEquals(flat.rows(), back.rows());
        for (int i = 0; i < flat.rows(); i++)
            assertEquals(flat.row(i), back.row(i), "row " + i);
        BigInteger[] hOrig = Groth16ProverBLS381.computeH(flat, w, 0, domain);
        BigInteger[] hBack = Groth16ProverBLS381.computeH(back, w, 0, domain);
        assertArrayEquals(hOrig, hBack, "cached constraints must produce the identical H polynomial");

        // ADR-0034 M6a: the mmap'd (segment-backed) read must be identical too
        try (var arena = java.lang.foreign.Arena.ofShared()) {
            var mapped = com.bloxbean.cardano.zeroj.api.R1CSFlatIO.readMapped(file, "c300-w302-p1", arena);
            assertNotNull(mapped, "matching fingerprint must map");
            assertNull(com.bloxbean.cardano.zeroj.api.R1CSFlatIO.readMapped(file, "c1-w2-p3", arena),
                    "fingerprint mismatch must be a mapped-read miss too");
            assertEquals(flat.rows(), mapped.rows());
            for (int i = 0; i < flat.rows(); i++)
                assertEquals(flat.row(i), mapped.row(i), "mapped row " + i);
            BigInteger[] hMapped = Groth16ProverBLS381.computeH(mapped, w, 0, domain);
            assertArrayEquals(hOrig, hMapped, "mapped constraints must produce the identical H polynomial");
        }
    }
}
