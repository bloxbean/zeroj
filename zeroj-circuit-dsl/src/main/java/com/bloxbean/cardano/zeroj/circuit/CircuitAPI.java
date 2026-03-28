package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;

/**
 * The circuit construction API — the DSL surface that circuit authors program against.
 *
 * <p>All operations are symbolic — they add gates to the constraint graph rather than
 * computing values. The actual computation happens in the witness calculator.</p>
 *
 * <p>Mirrors gnark's {@code frontend.API} for proven completeness.</p>
 */
public interface CircuitAPI {

    // --- Core primitives (mathematically complete) ---

    /** Field addition: output = a + b. Free in R1CS (linear combination). */
    Variable add(Variable a, Variable b);

    /** Field multiplication: output = a * b. Creates one constraint. */
    Variable mul(Variable a, Variable b);

    /** Enforce equality constraint: a == b. */
    void assertEqual(Variable a, Variable b);

    /** Conditional selection: output = cond ? ifTrue : ifFalse. cond must be boolean (0 or 1). */
    Variable select(Variable cond, Variable ifTrue, Variable ifFalse);

    // --- Arithmetic (built from core) ---

    /** Field subtraction: output = a - b. */
    Variable sub(Variable a, Variable b);

    /** Field negation: output = -a. */
    Variable neg(Variable a);

    /** Multiplicative inverse: output = a^{-1} mod p. Fails if a == 0. */
    Variable inv(Variable a);

    /** Field division: output = a / b = a * b^{-1}. */
    Variable div(Variable a, Variable b);

    /** Introduce a constant value. */
    Variable constant(long value);

    /** Introduce a constant value. */
    Variable constant(BigInteger value);

    // --- Binary operations ---

    /** Decompose a field element to nBits binary variables (LSB first). */
    Variable[] toBinary(Variable a, int nBits);

    /** Recompose a field element from binary variables (LSB first). */
    Variable fromBinary(Variable[] bits);

    /** Bitwise XOR: a ^ b. Both must be boolean. */
    Variable xor(Variable a, Variable b);

    /** Bitwise AND: a & b. Both must be boolean. */
    Variable and(Variable a, Variable b);

    /** Bitwise OR: a | b. Both must be boolean. */
    Variable or(Variable a, Variable b);

    /** Bitwise NOT: !a. Must be boolean. Returns 1 - a. */
    Variable not(Variable a);

    // --- Assertions ---

    /** Assert that a is boolean (0 or 1): a * (a - 1) == 0. */
    void assertBoolean(Variable a);

    /** Assert that a fits in nBits: 0 <= a < 2^nBits. */
    void assertInRange(Variable a, int nBits);

    /** Assert that a != b. */
    void assertNotEqual(Variable a, Variable b);

    // --- Comparison ---

    /** Returns 1 if a == 0, else 0. */
    Variable isZero(Variable a);

    /** Returns 1 if a == b, else 0. */
    Variable isEqual(Variable a, Variable b);

    /** Returns 1 if a < b (unsigned, nBits-bit comparison), else 0. */
    Variable lessThan(Variable a, Variable b, int nBits);

    // --- Array ---

    /** Access arr[index] via MUX tree. */
    Variable arrayAccess(Variable[] arr, Variable index);

    // --- Variable access ---

    /** Look up a declared variable by name. */
    Variable var(String name);
}
