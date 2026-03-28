package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;
import java.util.List;

/**
 * An operation (gate) in the arithmetic circuit.
 *
 * <p>The gate types are proof-system agnostic — the R1CS and PlonK compilers
 * interpret them differently.</p>
 */
public sealed interface Gate {

    /** Field addition: output = left + right. Free in R1CS (linear combination). */
    record Add(Variable output, Variable left, Variable right) implements Gate {}

    /** Field multiplication: output = left * right. One constraint in R1CS. */
    record Mul(Variable output, Variable left, Variable right) implements Gate {}

    /** Constant assignment: output = value. */
    record Const(Variable output, BigInteger value) implements Gate {}

    /** Equality constraint: left == right. */
    record AssertEq(Variable left, Variable right) implements Gate {}

    /** Conditional selection: output = cond ? ifTrue : ifFalse. */
    record Select(Variable output, Variable cond, Variable ifTrue, Variable ifFalse) implements Gate {}

    /** Linear combination: output = sum(coefficient_i * variable_i). Free in R1CS. */
    record LinComb(Variable output, List<Term> terms) implements Gate {}

    /** A term in a linear combination. */
    record Term(BigInteger coefficient, Variable variable) {}

    /** Hint for witness calculator: how to compute a non-deterministic value. */
    record Hint(Variable output, HintType type, Variable input) implements Gate {}

    /** Bit decomposition hint: outputs[i] = (input >> i) & 1. */
    record BitDecompose(Variable[] outputs, Variable input, int nBits) implements Gate {}

    /** Types of hints for witness computation. */
    enum HintType {
        /** output = input^{-1} mod p (or 0 if input == 0) */
        INVERSE,
        /** output = 1 if input == 0, else 0 */
        IS_ZERO_RESULT,
        /** output = input^{-1} if input != 0, else 0 */
        IS_ZERO_INVERSE
    }
}
