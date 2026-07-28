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

    /**
     * Decompose a field element to nBits binary variables (LSB first).
     *
     * @deprecated Prefer {@link #decompose(Variable, int)}, which returns a
     *         {@link BitDecomposition} binding the source variable, the width, and the bits
     *         together. The raw array returned here carries no evidence of which variable it
     *         decomposes or that its elements are boolean, so gadgets that consume it cannot
     *         verify their own soundness precondition. This method emits exactly the same
     *         constraints and remains supported; it is deprecated for expressiveness, not
     *         because it is unsound. See ADR-0037 Decision 2.
     */
    @Deprecated(since = "0.1.0")
    Variable[] toBinary(Variable a, int nBits);

    /**
     * Decompose {@code a} into {@code nBits} bits (LSB first), returning a
     * {@link BitDecomposition} that proves {@code a < 2^nBits}.
     *
     * <p>Emits the same constraints as {@link #toBinary(Variable, int)} — booleanity per bit
     * plus {@code sum(bits[i]*2^i) == a} — but returns a value that carries the range
     * guarantee with it, so downstream gadgets whose soundness depends on that bound can
     * demand the evidence rather than trust the caller.
     *
     * <p>Calling this repeatedly on the same variable and width is safe but wasteful; the
     * implementation records the resulting bound so that later range-checked operations on
     * the same wire do not re-emit it.
     */
    BitDecomposition decompose(Variable a, int nBits);

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

    /**
     * Returns 1 if {@code a < b} (unsigned, nBits-bit comparison), else 0.
     *
     * <p><b>Both operands must fit in {@code nBits} bits, and this method enforces that.</b>
     * The comparison forms {@code diff = (2^nBits - 1) + b - a} and inspects the top bit of an
     * {@code (nBits+1)}-bit decomposition; if either operand can exceed {@code 2^nBits}, the
     * subtraction wraps modulo the field prime and the result is meaningless. Both directions
     * are affected — an unconstrained left operand forges {@code a < b}, an unconstrained
     * right operand forges {@code a >= b}.
     *
     * <p>Therefore each <em>variable</em> operand is range-constrained to {@code nBits} here.
     * An operand that is a circuit constant is exempt and is instead validated statically:
     * a constant that does not fit in {@code nBits} throws at circuit-definition time rather
     * than producing a silently wrong comparison. Wires already proven to fit in
     * {@code nBits} or fewer — via {@link #decompose(Variable, int)},
     * {@link #toBinary(Variable, int)}, or {@link #assertInRange(Variable, int)} — are not
     * constrained twice.
     *
     * <p>Use {@link #lessThan(BitDecomposition, BitDecomposition)} when you already hold
     * decompositions and want to reuse them explicitly.
     *
     * @throws IllegalArgumentException if a constant operand does not fit in {@code nBits}
     * @see <a href="../../../../../../../../docs/adr/0037-jubjub-soundness-and-hardening.md">ADR-0037</a>
     */
    Variable lessThan(Variable a, Variable b, int nBits);

    /**
     * Returns 1 if {@code a.source() < b.source()}, else 0, reusing decompositions the caller
     * already holds instead of emitting fresh range constraints.
     *
     * <p>The comparison is performed at {@code max(a.width(), b.width())} bits. Both operands
     * already carry a proof that they fit within their own widths, so the soundness
     * precondition of {@link #lessThan(Variable, Variable, int)} is discharged by the types.
     *
     * <p><b>Both operands are ownership-checked first</b>
     * ({@link #requireOwned(BitDecomposition)}), before either width is read and before any
     * constraint is emitted. Because this overload emits no range constraints of its own,
     * authenticating the evidence <em>is</em> the range check: a decomposition minted in
     * another circuit proves nothing here, and since wire ids restart per circuit it could
     * otherwise be passed off as evidence about unrelated same-id wires — the
     * {@code p − 1 < 1,000,000} forgery ADR-0037 closed, reopened through a different door
     * (ADR-0038 Decision 1).
     *
     * @throws IllegalArgumentException if either operand was minted by a different circuit
     */
    Variable lessThan(BitDecomposition a, BitDecomposition b);

    // --- Array ---

    /** Access arr[index] via MUX tree. */
    Variable arrayAccess(Variable[] arr, Variable index);

    // --- Variable access ---

    /** Look up a declared variable by name. */
    Variable var(String name);

    /**
     * Look up a declared public input by name.
     *
     * <p>Implementations that track input visibility should reject secret
     * variables here. The default preserves compatibility with minimal
     * implementations by falling back to {@link #var(String)}.</p>
     */
    default Variable publicInputVar(String name) {
        return var(name);
    }

    /**
     * Look up a declared secret input by name.
     *
     * <p>Implementations that track input visibility should reject public
     * variables here. The default preserves compatibility with minimal
     * implementations by falling back to {@link #var(String)}.</p>
     */
    default Variable secretInputVar(String name) {
        return var(name);
    }

    /**
     * Asserts, at circuit-definition time, that {@code v} is a wire the verifier can see:
     * a declared public input, or a constant created by this circuit.
     *
     * <p>Gadgets whose security argument depends on a value being verifier-visible — rather
     * than chosen by the prover — call this instead of documenting the requirement. A
     * documented-only contract is unenforceable here: the caller passes whatever wire it
     * likes, and nothing at witness time distinguishes a public input from a secret one.
     *
     * <p><b>Provenance is resolved by wire id, never by {@link Variable#name()}.</b>
     * {@code Variable} is a public record, so any caller can construct
     * {@code new Variable(secretWire.id(), "someKnownPublicInputName")}. A name-based check
     * would classify that as public while every emitted constraint referenced the secret
     * wire. Implementations must therefore test membership against the circuit's own
     * public-input and constant wire ids.
     *
     * <p>The default throws, so an implementation that has not opted in cannot silently
     * accept anything.
     *
     * @throws IllegalArgumentException if {@code v} is a secret input, an intermediate or
     *         derived wire, or not a wire of this circuit at all
     * @see <a href="../../../../../../../../docs/adr/0037-jubjub-soundness-and-hardening.md">ADR-0037 Decision 4</a>
     */
    default void requirePublicOrConstant(Variable v) {
        throw new UnsupportedOperationException(
                "requirePublicOrConstant is not supported by this CircuitAPI implementation; "
                        + "a gadget that depends on verifier-visible inputs cannot be used here");
    }

    /**
     * Asserts, at circuit-definition time, that {@code decomposition} was minted by
     * <b>this</b> circuit — that the booleanity and recomposition constraints it stands for
     * were emitted into the constraint system now being built.
     *
     * <p>Every gadget that consumes a {@link BitDecomposition} must call this <b>first</b>,
     * before reading {@link BitDecomposition#bits()} and before emitting any constraint. Wire
     * ids restart at 1 in every circuit, so a foreign decomposition names wires that exist
     * here too and hold entirely unrelated values, while the constraints it attests to —
     * booleanity of the bits and {@code Σ bits[i]·2^i == source} — were emitted somewhere
     * else. A consumer that trusts it therefore operates on bits nothing in this circuit
     * binds: {@link #lessThan(BitDecomposition, BitDecomposition)} skips its range
     * constraints outright, reopening the {@code p − 1 < 1,000,000} forgery ADR-0037 closed,
     * and a scalar multiplication multiplies by prover-chosen bits that are not tied to the
     * intended scalar.
     *
     * <p>A consumer taking more than one decomposition validates <b>every</b> operand before
     * emitting anything, so a foreign operand cannot be rejected only after another operand's
     * constraints have already mutated the circuit.
     *
     * <p>Ownership is an object identity, compared by reference — not a name or an id, either
     * of which a caller can fabricate through the public API, since {@link Variable} is a
     * public record. Implementations must not disclose the identity through an accessor, an
     * exception message, or {@code toString()}.
     *
     * <p>The default throws, so a {@code CircuitAPI} implementation that has not opted into
     * provenance tracking fails closed rather than silently accepting typed evidence it
     * cannot authenticate.
     *
     * @throws IllegalArgumentException if {@code decomposition} was minted by a different
     *         circuit
     * @throws UnsupportedOperationException if this implementation does not track provenance
     * @see <a href="../../../../../../../../docs/adr/0038-jubjub-dsl-remediation-plan.md">ADR-0038 Decision 1</a>
     */
    default void requireOwned(BitDecomposition decomposition) {
        throw new UnsupportedOperationException(
                "requireOwned is not supported by this CircuitAPI implementation; a gadget "
                        + "that consumes a BitDecomposition cannot be used here, because this "
                        + "implementation cannot authenticate which circuit emitted it "
                        + "(ADR-0038 Decision 1)");
    }

    // --- Advice / hints (ADR-0028 Phase C) ---

    /**
     * Request {@code numOutputs} prover-advice values computed by the enumerated trusted-core
     * {@code kind} from {@code inputs} and {@code params}. The returned variables are
     * <b>unconstrained</b> — the caller MUST add constraints that fully pin them down; soundness
     * lives entirely in those constraints, not in the hint. Creates no constraints itself.
     *
     * <p>Default implementation throws; DSL implementations that support advice override it.</p>
     */
    default Variable[] hintN(Gate.HintKind kind, java.math.BigInteger[] params, int numOutputs, Variable[] inputs) {
        throw new UnsupportedOperationException("hintN not supported by this CircuitAPI implementation");
    }

    // --- Field expectation (checked at compile/witness time) ---

    /**
     * Declare that this circuit depends on constants tied to a specific scalar
     * field (e.g. Poseidon round constants). Calling this from a gadget records
     * the dependency on the circuit graph. At {@code compileR1CS(curve)} /
     * {@code calculateWitness(..., curve)} time, if the compile curve's field
     * differs from the recorded expectation, compilation throws.
     *
     * <p>Calling multiple times with the same {@code field} is fine; with
     * conflicting fields within one circuit, throws immediately at define time.
     *
     * <p>Default implementation is a no-op — legacy gadgets that do not
     * depend on field-specific constants need not implement it.
     */
    default void requireField(FieldConfig field) {
        // no-op by default
    }
}
