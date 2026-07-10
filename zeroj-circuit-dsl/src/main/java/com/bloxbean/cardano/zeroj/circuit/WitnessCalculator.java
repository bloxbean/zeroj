package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;
import java.util.BitSet;
import java.util.List;
import java.util.Map;

/**
 * Evaluates a {@link ConstraintGraph} on concrete inputs to produce the full witness.
 *
 * <p>The witness is an array of field elements: [1, public_inputs..., secret_inputs..., intermediates...]
 * where element 0 is always 1 (the constant wire).</p>
 *
 * <p>There is one evaluation path; only the <b>storage</b> is pluggable (ADR-0034 M7): the boxed
 * store is the classic {@code BigInteger[]}, and the flat store keeps canonical little-endian
 * 4-limb values (32 B/wire, no per-wire objects) for memory-constrained proving —
 * {@link #calculateFlat}. The arithmetic is identical by construction.</p>
 */
public final class WitnessCalculator {

    private WitnessCalculator() {}

    /**
     * Calculate the witness for the given inputs.
     *
     * @param graph  the constraint graph
     * @param inputs map of signal name → values
     * @param config field configuration (determines the prime for modular arithmetic)
     * @return the full witness array
     * @throws ArithmeticException if a constraint is violated
     */
    public static BigInteger[] calculate(ConstraintGraph graph, Map<String, List<BigInteger>> inputs,
                                          FieldConfig config) {
        var store = new BoxedStore(graph.numWires());
        evaluate(graph, inputs, config, store);
        return store.w;
    }

    /** Wires per storage chunk (2^17 wires × 32 B = 4 MB) — see {@link #calculateFlatChunked}. */
    public static final int WIRES_PER_CHUNK = 1 << 17;

    /**
     * {@link #calculate} into flat storage (ADR-0034 M7): wire {@code i}'s value is four canonical
     * little-endian 64-bit limbs at {@code i*4} — 32 B/wire, no boxed field elements. Same
     * evaluation path as {@link #calculate}; reads of unassigned wires fail loud.
     */
    public static long[] calculateFlat(ConstraintGraph graph, Map<String, List<BigInteger>> inputs,
                                        FieldConfig config) {
        long[][] chunks = calculateFlatChunked(graph, inputs, config);
        long[] limbs = new long[graph.numWires() * 4];
        int pos = 0;
        for (int c = 0; c < chunks.length; c++) {
            System.arraycopy(chunks[c], 0, limbs, pos, chunks[c].length);
            pos += chunks[c].length;
            chunks[c] = null;
        }
        return limbs;
    }

    /**
     * {@link #calculateFlat} into 4 MB chunks ({@link #WIRES_PER_CHUNK} wires each; the last chunk
     * is exact-sized). Near the memory floor a single ~1.4 GB contiguous witness array cannot be
     * allocated while the multi-GB circuit graph is alive (G1 humongous allocation); chunks can.
     * The caller releases the graph, then consolidates (ADR-0034 M7).
     */
    public static long[][] calculateFlatChunked(ConstraintGraph graph, Map<String, List<BigInteger>> inputs,
                                                 FieldConfig config) {
        int n = graph.numWires();
        int nChunks = (n + WIRES_PER_CHUNK - 1) / WIRES_PER_CHUNK;
        long[][] chunks = new long[nChunks][];
        for (int c = 0; c < nChunks; c++) {
            int wires = Math.min(WIRES_PER_CHUNK, n - c * WIRES_PER_CHUNK);
            chunks[c] = new long[wires * 4];
        }
        evaluate(graph, inputs, config, new FlatStore(chunks));
        return chunks;
    }

    /** Pluggable witness storage: the evaluator reads/writes wires only through this seam. */
    private interface Store {
        BigInteger get(int id);
        void set(int id, BigInteger v);
    }

    private static final class BoxedStore implements Store {
        final BigInteger[] w;
        BoxedStore(int n) { w = new BigInteger[n]; }
        @Override public BigInteger get(int id) { return w[id]; }
        @Override public void set(int id, BigInteger v) { w[id] = v; }
    }

    /** Canonical LE 4-limb chunked storage; a BitSet guards reads-before-writes (the boxed store NPEs there). */
    private static final class FlatStore implements Store {
        final long[][] chunks;
        final BitSet assigned;

        FlatStore(long[][] chunks) {
            this.chunks = chunks;
            this.assigned = new BitSet();
        }

        @Override
        public BigInteger get(int id) {
            if (!assigned.get(id))
                throw new IllegalStateException("wire " + id + " read before assignment");
            long[] limbs = chunks[id / WIRES_PER_CHUNK];
            int base = (id % WIRES_PER_CHUNK) * 4;
            byte[] be = new byte[32];
            for (int j = 0; j < 4; j++) {
                long l = limbs[base + j];
                int o = 24 - j * 8;
                for (int k = 0; k < 8; k++) be[o + 7 - k] = (byte) (l >>> (8 * k));
            }
            return new BigInteger(1, be);
        }

        @Override
        public void set(int id, BigInteger v) {
            if (v.signum() < 0 || v.bitLength() > 256)
                throw new IllegalArgumentException("witness value out of range at wire " + id + ": " + v.bitLength() + " bits");
            long[] limbs = chunks[id / WIRES_PER_CHUNK];
            int base = (id % WIRES_PER_CHUNK) * 4;
            limbs[base] = 0; limbs[base + 1] = 0; limbs[base + 2] = 0; limbs[base + 3] = 0;
            byte[] be = v.toByteArray(); // may carry one leading 0x00 sign byte
            int len = Math.min(be.length, 32);
            for (int k = 0; k < len; k++)
                limbs[base + (k >>> 3)] |= ((long) (be[be.length - 1 - k] & 0xff)) << ((k & 7) << 3);
            assigned.set(id);
        }
    }

    private static void evaluate(ConstraintGraph graph, Map<String, List<BigInteger>> inputs,
                                 FieldConfig config, Store witness) {
        BigInteger p = config.prime();

        // Wire 0 = 1
        witness.set(graph.oneWire().id(), BigInteger.ONE);

        // Set public inputs
        for (var v : graph.publicInputs()) {
            var vals = inputs.get(v.name());
            if (vals == null || vals.isEmpty())
                throw new IllegalArgumentException("Missing public input: " + v.name());
            witness.set(v.id(), vals.getFirst().mod(p));
        }

        // Set secret inputs
        for (var v : graph.secretInputs()) {
            var vals = inputs.get(v.name());
            if (vals == null || vals.isEmpty())
                throw new IllegalArgumentException("Missing secret input: " + v.name());
            witness.set(v.id(), vals.getFirst().mod(p));
        }

        // Evaluate gates in topological order
        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) ->
                        witness.set(out.id(), value.mod(p));

                case Gate.Add(var out, var left, var right) ->
                        witness.set(out.id(), witness.get(left.id()).add(witness.get(right.id())).mod(p));

                case Gate.Mul(var out, var left, var right) ->
                        witness.set(out.id(), witness.get(left.id()).multiply(witness.get(right.id())).mod(p));

                case Gate.LinComb(var out, var terms) -> {
                    BigInteger sum = BigInteger.ZERO;
                    for (var term : terms) {
                        sum = sum.add(term.coefficient().multiply(witness.get(term.variable().id())));
                    }
                    witness.set(out.id(), sum.mod(p));
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) -> {
                    var condVal = witness.get(cond.id());
                    witness.set(out.id(), condVal.equals(BigInteger.ONE)
                            ? witness.get(ifTrue.id()) : witness.get(ifFalse.id()));
                }

                case Gate.AssertEq(var left, var right) -> {
                    if (!witness.get(left.id()).equals(witness.get(right.id()))) {
                        throw new ArithmeticException("Constraint violation: "
                                + left + "=" + witness.get(left.id()) + " != " + right + "=" + witness.get(right.id()));
                    }
                }

                case Gate.BitDecompose(var outputs, var input, var nBits) -> {
                    var val = witness.get(input.id());
                    for (int i = 0; i < nBits; i++) {
                        witness.set(outputs[i].id(), val.testBit(i) ? BigInteger.ONE : BigInteger.ZERO);
                    }
                }

                case Gate.Hint(var out, var type, var input) -> {
                    var inputVal = witness.get(input.id());
                    witness.set(out.id(), switch (type) {
                        case INVERSE -> inputVal.signum() == 0
                                ? BigInteger.ZERO : inputVal.modInverse(p);
                        case IS_ZERO_RESULT -> inputVal.signum() == 0
                                ? BigInteger.ONE : BigInteger.ZERO;
                        case IS_ZERO_INVERSE -> inputVal.signum() == 0
                                ? BigInteger.ZERO : inputVal.modInverse(p);
                    });
                }

                case Gate.HintN(var hOut, var kind, var hIn, var params) -> {
                    switch (kind) {
                        case MUL_MOD_REDUCE -> {
                            // params: [modulus, radixBits, numLimbsAB, numLimbsQ]
                            // inputs: numLimbsAB a-limbs, then numLimbsAB b-limbs
                            // outputs: numLimbsQ q-limbs, then numLimbsAB r-limbs
                            BigInteger modulus = params[0];
                            int radixBits = params[1].intValueExact();
                            int nAB = params[2].intValueExact();
                            int nQ = params[3].intValueExact();
                            BigInteger mask = BigInteger.ONE.shiftLeft(radixBits).subtract(BigInteger.ONE);
                            BigInteger aVal = BigInteger.ZERO, bVal = BigInteger.ZERO;
                            for (int i = 0; i < nAB; i++) {
                                aVal = aVal.add(witness.get(hIn[i].id()).shiftLeft(radixBits * i));
                                bVal = bVal.add(witness.get(hIn[nAB + i].id()).shiftLeft(radixBits * i));
                            }
                            BigInteger prod = aVal.multiply(bVal);
                            BigInteger q = prod.divide(modulus);
                            BigInteger r = prod.mod(modulus);
                            for (int i = 0; i < nQ; i++) { witness.set(hOut[i].id(), q.and(mask)); q = q.shiftRight(radixBits); }
                            for (int i = 0; i < nAB; i++) { witness.set(hOut[nQ + i].id(), r.and(mask)); r = r.shiftRight(radixBits); }
                        }
                        case INV_MOD -> {
                            // params: [modulus, radixBits, numLimbs]; inputs: numLimbs a-limbs;
                            // outputs: numLimbs limbs of a^-1 mod modulus (0 if a % modulus == 0).
                            BigInteger modulus = params[0];
                            int radixBits = params[1].intValueExact();
                            int numLimbs = params[2].intValueExact();
                            BigInteger mask = BigInteger.ONE.shiftLeft(radixBits).subtract(BigInteger.ONE);
                            BigInteger aVal = BigInteger.ZERO;
                            for (int i = 0; i < numLimbs; i++) aVal = aVal.add(witness.get(hIn[i].id()).shiftLeft(radixBits * i));
                            aVal = aVal.mod(modulus);
                            BigInteger ainv = aVal.signum() == 0 ? BigInteger.ZERO : aVal.modInverse(modulus);
                            for (int i = 0; i < numLimbs; i++) { witness.set(hOut[i].id(), ainv.and(mask)); ainv = ainv.shiftRight(radixBits); }
                        }
                    }
                }
            }
        }
    }
}
