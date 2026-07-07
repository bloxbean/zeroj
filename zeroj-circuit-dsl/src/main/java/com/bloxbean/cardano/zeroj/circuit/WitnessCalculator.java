package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Evaluates a {@link ConstraintGraph} on concrete inputs to produce the full witness.
 *
 * <p>The witness is an array of field elements: [1, public_inputs..., secret_inputs..., intermediates...]
 * where element 0 is always 1 (the constant wire).</p>
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
        BigInteger p = config.prime();
        BigInteger[] witness = new BigInteger[graph.numWires()];

        // Wire 0 = 1
        witness[graph.oneWire().id()] = BigInteger.ONE;

        // Set public inputs
        for (var v : graph.publicInputs()) {
            var vals = inputs.get(v.name());
            if (vals == null || vals.isEmpty())
                throw new IllegalArgumentException("Missing public input: " + v.name());
            witness[v.id()] = vals.getFirst().mod(p);
        }

        // Set secret inputs
        for (var v : graph.secretInputs()) {
            var vals = inputs.get(v.name());
            if (vals == null || vals.isEmpty())
                throw new IllegalArgumentException("Missing secret input: " + v.name());
            witness[v.id()] = vals.getFirst().mod(p);
        }

        // Evaluate gates in topological order
        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) ->
                        witness[out.id()] = value.mod(p);

                case Gate.Add(var out, var left, var right) ->
                        witness[out.id()] = witness[left.id()].add(witness[right.id()]).mod(p);

                case Gate.Mul(var out, var left, var right) ->
                        witness[out.id()] = witness[left.id()].multiply(witness[right.id()]).mod(p);

                case Gate.LinComb(var out, var terms) -> {
                    BigInteger sum = BigInteger.ZERO;
                    for (var term : terms) {
                        sum = sum.add(term.coefficient().multiply(witness[term.variable().id()]));
                    }
                    witness[out.id()] = sum.mod(p);
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) -> {
                    var condVal = witness[cond.id()];
                    witness[out.id()] = condVal.equals(BigInteger.ONE)
                            ? witness[ifTrue.id()] : witness[ifFalse.id()];
                }

                case Gate.AssertEq(var left, var right) -> {
                    if (!witness[left.id()].equals(witness[right.id()])) {
                        throw new ArithmeticException("Constraint violation: "
                                + left + "=" + witness[left.id()] + " != " + right + "=" + witness[right.id()]);
                    }
                }

                case Gate.BitDecompose(var outputs, var input, var nBits) -> {
                    var val = witness[input.id()];
                    for (int i = 0; i < nBits; i++) {
                        witness[outputs[i].id()] = val.testBit(i) ? BigInteger.ONE : BigInteger.ZERO;
                    }
                }

                case Gate.Hint(var out, var type, var input) -> {
                    var inputVal = witness[input.id()];
                    witness[out.id()] = switch (type) {
                        case INVERSE -> inputVal.signum() == 0
                                ? BigInteger.ZERO : inputVal.modInverse(p);
                        case IS_ZERO_RESULT -> inputVal.signum() == 0
                                ? BigInteger.ONE : BigInteger.ZERO;
                        case IS_ZERO_INVERSE -> inputVal.signum() == 0
                                ? BigInteger.ZERO : inputVal.modInverse(p);
                    };
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
                                aVal = aVal.add(witness[hIn[i].id()].shiftLeft(radixBits * i));
                                bVal = bVal.add(witness[hIn[nAB + i].id()].shiftLeft(radixBits * i));
                            }
                            BigInteger prod = aVal.multiply(bVal);
                            BigInteger q = prod.divide(modulus);
                            BigInteger r = prod.mod(modulus);
                            for (int i = 0; i < nQ; i++) { witness[hOut[i].id()] = q.and(mask); q = q.shiftRight(radixBits); }
                            for (int i = 0; i < nAB; i++) { witness[hOut[nQ + i].id()] = r.and(mask); r = r.shiftRight(radixBits); }
                        }
                        case INV_MOD -> {
                            // params: [modulus, radixBits, numLimbs]; inputs: numLimbs a-limbs;
                            // outputs: numLimbs limbs of a^-1 mod modulus (0 if a % modulus == 0).
                            BigInteger modulus = params[0];
                            int radixBits = params[1].intValueExact();
                            int numLimbs = params[2].intValueExact();
                            BigInteger mask = BigInteger.ONE.shiftLeft(radixBits).subtract(BigInteger.ONE);
                            BigInteger aVal = BigInteger.ZERO;
                            for (int i = 0; i < numLimbs; i++) aVal = aVal.add(witness[hIn[i].id()].shiftLeft(radixBits * i));
                            aVal = aVal.mod(modulus);
                            BigInteger ainv = aVal.signum() == 0 ? BigInteger.ZERO : aVal.modInverse(modulus);
                            for (int i = 0; i < numLimbs; i++) { witness[hOut[i].id()] = ainv.and(mask); ainv = ainv.shiftRight(radixBits); }
                        }
                    }
                }
            }
        }

        return witness;
    }
}
