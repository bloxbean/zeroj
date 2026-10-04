package org.zeroj.examples.pedersen;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.lib.zk.ZkPedersenVector;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.crypto.groth16.Groth16Keys;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryType;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ADR-0051 performance gate for M3 and M4: end-to-end cost of {@code pedersen-jubjub-vector-v1}
 * commitments at representative dimensions and of the M4 confidential-note reference circuit,
 * beyond constraint counts.
 *
 * <p>For each dimension it records R1CS rows and nonzeros, the padded evaluation domain, and the
 * median witness-generation and pure-Java Groth16 proving times over several runs after warm-up,
 * the live heap before proving, and how far the heap peak rose above it during proving (after
 * an explicit collection, so leftover garbage is not counted). It asserts nothing; it prints a
 * Markdown table.
 *
 * <p>Runs in its own JVM, not a test JVM:
 * <pre>{@code ./gradlew :zeroj-integration-tests:pedersenVectorBenchmark}</pre>
 * Dev trusted setup only (the task sets the insecure-setup opt-in).
 */
public final class PedersenVectorBenchmark {

    private static final int WARMUP = 3;
    private static final int RUNS = 7;

    public static void main(String[] args) {
        int[] dimensions = args.length > 0
                ? Arrays.stream(args[0].split(",")).mapToInt(Integer::parseInt).toArray()
                : new int[]{1, 4, 16};
        System.out.println("| circuit | rows | nonzeros | domain | witness median (ms) | prove median (ms) | live heap before prove (MB) | peak heap growth during prove (MB) |");
        System.out.println("|---|---:|---:|---:|---:|---:|---:|---:|");
        for (int n : dimensions) {
            measureVector(n);
        }
        measureConfidentialNote();
        System.out.println();
        System.out.println("JVM: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.version")
                + ", processors: " + Runtime.getRuntime().availableProcessors()
                + ", max heap: " + Runtime.getRuntime().maxMemory() / (1024 * 1024) + " MB");
    }

    private static void measureVector(int n) {
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < n; i++) entries.add(new Entry("v" + i, 64));
        var schema = PedersenVectorSchema.of("zeroj.bench.n" + n, 1, entries);
        var builder = CircuitBuilder.create("bench-" + n).publicVar("schemaDigest").publicVar("u").publicVar("v");
        for (int i = 0; i < n; i++) builder.secretVar("x" + i);
        builder.secretVar("r");
        var circuit = builder.defineSignals(cs -> {
            var zk = new ZkContext(cs);
            var binding = ZkPedersenVector.bindSchema(zk, schema, ZkField.publicInput(cs, "schemaDigest"));
            List<ZkUInt> xs = new ArrayList<>();
            for (int i = 0; i < n; i++) xs.add(ZkUInt.secret(cs, "x" + i, 64));
            ZkPedersenVector.commit(zk, binding, xs, ZkUInt.secret(cs, "r", 252))
                    .assertAffineEquals(zk, ZkField.publicInput(cs, "u"), ZkField.publicInput(cs, "v"));
        });
        var random = new SecureRandom();
        List<BigInteger> values = new ArrayList<>();
        for (int i = 0; i < n; i++) values.add(new BigInteger(64, random));
        BigInteger r = PedersenCommitment.randomBlinding(random);
        var c = PedersenVectorCommitment.commit(schema, values, r);
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("schemaDigest", List.of(schema.digest()));
        inputs.put("u", List.of(c.point().affineU()));
        inputs.put("v", List.of(c.point().affineV()));
        for (int i = 0; i < n; i++) inputs.put("x" + i, List.of(values.get(i)));
        inputs.put("r", List.of(r));
        measure("vector n=" + n, circuit, inputs, 0xbe0c4L + n);
    }

    /** ADR-0051 M4 reference circuit: one input note split into two, 64-bit amounts. */
    private static void measureConfidentialNote() {
        var in = ConfidentialNoteOnChainTest.Note.of(new byte[28], 1_000);
        var out1 = ConfidentialNoteOnChainTest.Note.of(new byte[28], 700);
        var out2 = ConfidentialNoteOnChainTest.Note.of(new byte[28], 300);
        measure("confidential note (1 in, 2 out)", ConfidentialNoteOnChainTest.transferCircuit(64),
                ConfidentialNoteOnChainTest.witness(in, out1, out2), 0x4e07e5L);
    }

    private static void measure(String label, CircuitBuilder circuit, Map<String, List<BigInteger>> inputs,
                                long seed) {
        R1CSConstraintSystem r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        long nnz = r1cs.constraints().stream()
                .mapToLong(c -> (long) c.a().size() + c.b().size() + c.c().size()).sum();
        var keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(seed));

        long[] witnessNanos = new long[RUNS];
        long[] proveNanos = new long[RUNS];
        long peakGrowth = 0;
        long liveBefore = 0;
        BigInteger[] witness = null;
        for (int run = -WARMUP; run < RUNS; run++) {
            long t0 = System.nanoTime();
            witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
            long t1 = System.nanoTime();
            // Collect first, so the peak below reflects what proving allocates on top of the
            // live set (keys, circuit, witness), not leftover garbage.
            System.gc();
            long baseline = usedHeapBytes();
            resetPeaks();
            long t2 = System.nanoTime();
            keys.prove(witness, r1cs.constraints());
            long t3 = System.nanoTime();
            if (run >= 0) {
                witnessNanos[run] = t1 - t0;
                proveNanos[run] = t3 - t2;
                peakGrowth = Math.max(peakGrowth, peakHeapBytes() - baseline);
                liveBefore = Math.max(liveBefore, baseline);
            }
        }
        System.out.printf("| %s | %,d | %,d | %,d | %.1f | %.1f | %d | %d |%n",
                label, r1cs.constraints().size(), nnz, keys.domain(),
                median(witnessNanos) / 1e6, median(proveNanos) / 1e6,
                liveBefore / (1024 * 1024), peakGrowth / (1024 * 1024));
    }

    private static void resetPeaks() {
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == MemoryType.HEAP) pool.resetPeakUsage();
        }
    }

    private static long usedHeapBytes() {
        long total = 0;
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == MemoryType.HEAP) total += pool.getUsage().getUsed();
        }
        return total;
    }

    private static long peakHeapBytes() {
        long total = 0;
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == MemoryType.HEAP) total += pool.getPeakUsage().getUsed();
        }
        return total;
    }

    private static double median(long[] samples) {
        long[] sorted = samples.clone();
        Arrays.sort(sorted);
        return sorted[sorted.length / 2];
    }
}
