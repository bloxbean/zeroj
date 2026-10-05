package org.zeroj.circuit;

import java.math.BigInteger;
import java.util.*;

/**
 * Internal implementation of {@link CircuitAPI} that builds a {@link ConstraintGraph}.
 */
class CircuitAPIImpl implements CircuitAPI {

    // Max bit decomposition: 253 for BN254, safe upper bound for all supported curves.
    // BN254 ~253.6 bits, BLS12-381 ~254.8 bits, Pallas ~254.9 bits.
    // We use 253 because it's the tightest constraint (BN254 field order < 2^254).
    static final int MAX_SAFE_BITS = 253;

    private final List<Gate> gates = new ArrayList<>();
    private final Map<String, Variable> namedVars = new LinkedHashMap<>();
    private final Map<String, InputVisibility> inputVisibilities = new LinkedHashMap<>();
    private final Map<BigInteger, Variable> constantCache = new HashMap<>();
    private final List<Variable> publicInputs = new ArrayList<>();
    private final List<Variable> secretInputs = new ArrayList<>();
    private final List<Variable> intermediateVars = new ArrayList<>();

    /**
     * Wire id -> constant value, for every wire this circuit created as a constant,
     * including {@link #oneWire}. Keyed by <b>wire id</b>, never by name: {@link Variable}
     * is a public record, so a caller can fabricate one carrying any name it likes, while
     * every emitted constraint references the id. See ADR-0037 Decision 4.
     */
    private final Map<Integer, BigInteger> constantWireValues = new HashMap<>();

    /**
     * Wire id -> the smallest {@code n} for which this circuit has already emitted a proof
     * that the wire is {@code < 2^n}. Used to avoid re-emitting a range constraint that is
     * already implied. A recorded bound of {@code n} discharges any request for {@code m >= n};
     * a request for a strictly tighter {@code m < n} must still emit.
     */
    private final Map<Integer, Integer> rangeBounds = new HashMap<>();
    /** Wires that must keep at least this many bits of range (ADR-0051 D2); checked at freeze. */
    private final Map<Integer, Integer> hidingRanges = new HashMap<>();
    /** Decomposition bit wire id -> the source wire it was minted from. */
    private final Map<Integer, Integer> decompositionSource = new HashMap<>();
    /** fromBinary result wire id -> its bit wire ids, LSB first. */
    private final Map<Integer, int[]> recompositions = new HashMap<>();
    /** Bit wires that must not be forced to zero by a recorded range (ADR-0051 D2). */
    private final Set<Integer> hidingBits = new HashSet<>();

    /**
     * Wire ids already proven boolean by an emitted {@code a·(a−1) == 0} constraint.
     * Re-asserting booleanity on the same wire adds constraints without adding information;
     * a point-select over four coordinates used to pay for the same condition four times.
     */
    private final Set<Integer> booleanWires = new HashSet<>();

    /**
     * This circuit's provenance identity, stamped into every {@link BitDecomposition} it
     * mints and compared by reference in {@link #requireOwned}. A dedicated token rather than
     * {@code this}: a decomposition that escapes its circuit would otherwise retain the whole
     * builder and its gate list, ~19M constraints' worth on the largest circuits here.
     *
     * <p>Never exposed — no accessor, never in an exception message, never in
     * {@code toString()}. {@link BitDecomposition#isOwnedBy(Object)} returns a boolean so the
     * token cannot escape through the comparison either.
     */
    private final Object circuitToken = new Object();

    private final Variable oneWire;
    private int nextId;
    private FieldConfig expectedField;

    /** Set by {@link #buildGraph}; see {@link #requireNotFrozen()}. */
    private boolean frozen;

    CircuitAPIImpl(List<String> publicVarNames, List<String> secretVarNames) {
        // Wire 0 = constant "1"
        this.oneWire = new Variable(0, "_one");
        this.nextId = 1;
        gates.add(new Gate.Const(oneWire, BigInteger.ONE));
        constantWireValues.put(oneWire.id(), BigInteger.ONE);

        // Public inputs
        for (String name : publicVarNames) {
            var v = new Variable(nextId++, name);
            publicInputs.add(v);
            namedVars.put(name, v);
            inputVisibilities.put(name, InputVisibility.PUBLIC);
        }

        // Secret inputs
        for (String name : secretVarNames) {
            var v = new Variable(nextId++, name);
            secretInputs.add(v);
            namedVars.put(name, v);
            inputVisibilities.put(name, InputVisibility.SECRET);
        }
    }

    @Override
    public void requirePublicOrConstant(Variable v) {
        Objects.requireNonNull(v, "v");
        // Resolve by wire id, never by name. Variable is a public record, so a caller can
        // build new Variable(secretWire.id(), "aPublicInputName"); inputVisibilities is keyed
        // by name while every constraint references the id, so a name-based check would
        // authorise the secret wire. See ADR-0037 Decision 4.
        if (constantWireValues.containsKey(v.id())) return;   // includes oneWire
        for (Variable pub : publicInputs) {
            if (pub.id() == v.id()) return;
        }
        throw new IllegalArgumentException(
                "Variable " + v + " must be a public input or a circuit constant, but wire "
                        + v.id() + " is neither. A gadget that relies on this value being "
                        + "visible to the verifier cannot accept a secret or derived wire "
                        + "(ADR-0037 Decision 4).");
    }

    @Override
    public void requirePublicInput(Variable v) {
        Objects.requireNonNull(v, "v");
        for (Variable pub : publicInputs) {
            if (pub.id() == v.id()) return;
        }
        throw new IllegalArgumentException(
                "Variable " + v + " must be a declared public input, but wire " + v.id()
                        + " is not. A value the verifier compares with its own expected value "
                        + "must be in the public statement (ADR-0051 D5).");
    }

    @Override
    public void requireHidingRange(Variable v, int minBits) {
        Objects.requireNonNull(v, "v");
        if (v.id() < 0 || v.id() >= nextId) {
            throw new IllegalArgumentException(
                    "Variable " + v + " is not a wire of this circuit (wire id " + v.id()
                            + " was never allocated here).");
        }
        Integer bound = rangeBounds.get(v.id());
        if (bound != null && bound < minBits) {
            throw new IllegalArgumentException(
                    "Variable " + v + " must keep a " + minBits + "-bit range for hiding, but the "
                            + "circuit already proves it is below 2^" + bound + " (ADR-0051 D2)");
        }
        hidingRanges.merge(v.id(), minBits, Math::max);
    }

    @Override
    public void requireHidingBits(Variable[] bits, int minBits) {
        Objects.requireNonNull(bits, "bits");
        for (Variable bit : bits) {
            Objects.requireNonNull(bit, "bit");
            if (bit.id() < 0 || bit.id() >= nextId) {
                throw new IllegalArgumentException(
                        "Variable " + bit + " is not a wire of this circuit (wire id " + bit.id()
                                + " was never allocated here).");
            }
        }
        for (Variable bit : bits) {
            Integer source = decompositionSource.get(bit.id());
            if (source != null) {
                requireHidingRange(new Variable(source, "decomposition-source"), minBits);
            }
            hidingBits.add(bit.id());
        }
        requireNoForcedHidingBit();
    }

    /**
     * A recomposition {@code w = Σ bitᵢ·2^i} with a recorded bound {@code w < 2^b} forces every
     * bit at position {@code ≥ b} to zero. None of those may be a hiding bit.
     */
    private void requireNoForcedHidingBit() {
        if (hidingBits.isEmpty()) return;
        for (var entry : recompositions.entrySet()) {
            Integer bound = rangeBounds.get(entry.getKey());
            int[] ids = entry.getValue();
            if (bound == null || bound >= ids.length) continue;
            for (int k = bound; k < ids.length; k++) {
                if (hidingBits.contains(ids[k])) {
                    throw new IllegalArgumentException(
                            "bit wire " + ids[k] + " must not be forced to zero for hiding, but it "
                                    + "is bit " + k + " of a value the circuit proves is below 2^"
                                    + bound + " (ADR-0051 D2)");
                }
            }
        }
    }

    @Override
    public void requireNotPublicOrConstant(Variable v) {
        Objects.requireNonNull(v, "v");
        // Same wire-id resolution as requirePublicOrConstant: a name can be fabricated, an
        // id cannot be reassigned to a different wire.
        if (v.id() < 0 || v.id() >= nextId) {
            throw new IllegalArgumentException(
                    "Variable " + v + " is not a wire of this circuit (wire id " + v.id()
                            + " was never allocated here).");
        }
        if (constantWireValues.containsKey(v.id())) {
            throw new IllegalArgumentException(
                    "Variable " + v + " is a circuit constant. A gadget that relies on this "
                            + "value being unknown to the verifier cannot accept a constant "
                            + "(ADR-0051 D2).");
        }
        for (Variable pub : publicInputs) {
            if (pub.id() == v.id()) {
                throw new IllegalArgumentException(
                        "Variable " + v + " is a public input. A gadget that relies on this "
                                + "value being unknown to the verifier cannot accept a public "
                                + "input (ADR-0051 D2).");
            }
        }
    }

    private Variable newIntermediate() {
        // Every gate this class emits either allocates an intermediate output or is an
        // AssertEq, so guarding these two points covers all of them.
        requireNotFrozen();
        var v = Variable.intermediate(nextId++);
        intermediateVars.add(v);
        return v;
    }

    @Override
    public Variable[] hintN(Gate.HintKind kind, java.math.BigInteger[] params, int numOutputs, Variable[] inputs) {
        // Hoist the lifecycle guard: with zero outputs newIntermediate() is never called, so
        // relying on its guard would let a post-build HintN mutate the snapshotted gate list.
        requireNotFrozen();
        var outputs = new Variable[numOutputs];
        for (int i = 0; i < numOutputs; i++) outputs[i] = newIntermediate();
        gates.add(new Gate.HintN(outputs, kind, inputs.clone(), params.clone()));
        return outputs;
    }

    ConstraintGraph buildGraph(String name) {
        // A hiding-required wire or bit may have been narrowed after the gadget that registered
        // it ran.
        requireNoForcedHidingBit();
        for (var entry : hidingRanges.entrySet()) {
            Integer bound = rangeBounds.get(entry.getKey());
            if (bound != null && bound < entry.getValue()) {
                throw new IllegalArgumentException(
                        "wire " + entry.getKey() + " must keep a " + entry.getValue() + "-bit range "
                                + "for hiding, but the circuit proves it is below 2^" + bound
                                + " (ADR-0051 D2)");
            }
        }
        // The graph copies the gate list, so anything emitted after this point is silently
        // dropped. Freeze instead, so a symbolic value that escaped its define() block and is
        // later asked to add constraints fails loudly rather than appearing to succeed while
        // constraining nothing (ADR-0038 P2 review).
        frozen = true;
        return new ConstraintGraph(name, gates, oneWire, publicInputs, secretInputs,
                intermediateVars, nextId, expectedField);
    }

    /**
     * Rejects constraint emission after {@link #buildGraph} has snapshotted the gate list.
     *
     * <p>Without this, a {@code ZkValue} that outlived its circuit could call an emitting
     * method — {@code assertWellFormed()} is the dangerous one, because {@link ZkValue} gives
     * it no context to validate — and return normally having added nothing, while marking
     * itself as checked. The circuit would then carry a value believed constrained that is not.
     */
    private void requireNotFrozen() {
        if (frozen) {
            throw new IllegalStateException(
                    "This circuit has already been built; no further constraints can be added. "
                            + "A symbolic value that escaped its define()/defineSignals() block "
                            + "cannot emit constraints afterwards — they would be silently "
                            + "discarded (ADR-0038 P2).");
        }
    }

    @Override
    public void requireField(FieldConfig field) {
        requireNotFrozen();
        java.util.Objects.requireNonNull(field, "field");
        if (expectedField == null) {
            expectedField = field;
        } else if (!expectedField.equals(field)) {
            throw new IllegalStateException(
                    "Conflicting field expectations within one circuit: "
                            + expectedField.name() + " vs " + field.name()
                            + ". A circuit may only depend on constants for a single scalar field.");
        }
    }

    // --- Core primitives ---

    @Override
    public Variable add(Variable a, Variable b) {
        var out = newIntermediate();
        gates.add(new Gate.Add(out, a, b));
        return out;
    }

    @Override
    public Variable mul(Variable a, Variable b) {
        var out = newIntermediate();
        gates.add(new Gate.Mul(out, a, b));
        return out;
    }

    @Override
    public void assertEqual(Variable a, Variable b) {
        requireNotFrozen();
        gates.add(new Gate.AssertEq(a, b));
    }

    @Override
    public Variable select(Variable cond, Variable ifTrue, Variable ifFalse) {
        assertBoolean(cond);
        // output = cond * (ifTrue - ifFalse) + ifFalse
        var diff = sub(ifTrue, ifFalse);
        var condDiff = mul(cond, diff);
        return add(ifFalse, condDiff);
    }

    // --- Arithmetic ---

    @Override
    public Variable sub(Variable a, Variable b) {
        return add(a, neg(b));
    }

    @Override
    public Variable neg(Variable a) {
        // -a = (-1) * a — but we represent it as (0 - a) via linear combination
        var out = newIntermediate();
        gates.add(new Gate.LinComb(out, List.of(
                new Gate.Term(BigInteger.ONE.negate(), a))));
        return out;
    }

    @Override
    public Variable inv(Variable a) {
        // Create hint: output = a^{-1}
        var out = newIntermediate();
        gates.add(new Gate.Hint(out, Gate.HintType.INVERSE, a));
        // Constraint: a * out = 1
        var product = mul(a, out);
        assertEqual(product, oneWire);
        return out;
    }

    @Override
    public Variable div(Variable a, Variable b) {
        return mul(a, inv(b));
    }

    @Override
    public Variable constant(long value) {
        return constant(BigInteger.valueOf(value));
    }

    @Override
    public Variable constant(BigInteger value) {
        return constantCache.computeIfAbsent(value, v -> {
            var out = newIntermediate();
            gates.add(new Gate.Const(out, v));
            constantWireValues.put(out.id(), v);
            return out;
        });
    }

    // --- Binary ---

    @Override
    public Variable[] toBinary(Variable a, int nBits) {
        return decompose(a, nBits).bitsNoCopy();
    }

    @Override
    public BitDecomposition decompose(Variable a, int nBits) {
        if (nBits <= 0 || nBits > MAX_SAFE_BITS)
            throw new IllegalArgumentException("nBits must be in [1, " + MAX_SAFE_BITS + "], got " + nBits);
        // Resolve the source by wire id against this circuit's own allocation. Variable is a
        // public record, so a caller can fabricate new Variable(9999, "ghost") for a wire this
        // circuit never allocated; decomposing it would record a range bound — and emit gates
        // referencing an id outside the wire array — for a wire that does not exist. This
        // makes the guarantee requireOwned carries the stronger one: not merely "this circuit
        // emitted these constraints" but "…about a wire of this circuit" (ADR-0038 Decision 1,
        // same wire-id resolution ADR-0037 Decision 4 applied to requirePublicOrConstant).
        Objects.requireNonNull(a, "a");
        if (a.id() < 0 || a.id() >= nextId) {
            throw new IllegalArgumentException(
                    "Variable " + a + " is not a wire of this circuit (wire id " + a.id()
                            + " was never allocated here); it cannot be decomposed.");
        }
        var bits = new Variable[nBits];
        for (int i = 0; i < nBits; i++) {
            bits[i] = newIntermediate();
            decompositionSource.put(bits[i].id(), a.id());
        }
        // Hint: tell witness calculator how to compute bit values from a
        gates.add(new Gate.BitDecompose(bits, a, nBits));
        // Constraints: each bit is boolean
        for (int i = 0; i < nBits; i++) {
            assertBoolean(bits[i]);
        }
        // Constraint: sum(bits[i] * 2^i) == a
        var reconstructed = fromBinary(bits);
        assertEqual(reconstructed, a);
        // These constraints prove a < 2^nBits; record it so range-checked operations on the
        // same wire need not re-emit an implied bound.
        recordRangeBound(a, nBits);
        // Stamp the evidence with this circuit's identity: the constraints just emitted are
        // what the decomposition attests to, and they live in THIS constraint system.
        return new BitDecomposition(circuitToken, a, nBits, bits);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Compares the decomposition's owner token against this circuit's by reference. The
     * token is not read out of the decomposition — {@link BitDecomposition#isOwnedBy(Object)}
     * answers the question without letting the identity escape — and the rejection message
     * deliberately names only the source wire and width, never the token.
     */
    @Override
    public void requireOwned(BitDecomposition decomposition) {
        Objects.requireNonNull(decomposition, "decomposition");
        if (!decomposition.isOwnedBy(circuitToken)) {
            throw new IllegalArgumentException(
                    "BitDecomposition " + decomposition + " was minted by a different circuit. "
                            + "Its booleanity and recomposition constraints were emitted into "
                            + "another constraint system, so it proves nothing about wire "
                            + decomposition.source().id() + " here — wire ids restart at 1 in "
                            + "every circuit, so the ids may coincide by accident. Decompose "
                            + "the value in this circuit instead (ADR-0038 Decision 1).");
        }
    }

    /** Note that the circuit now proves {@code v < 2^nBits}, keeping the tightest known bound. */
    private void recordRangeBound(Variable v, int nBits) {
        rangeBounds.merge(v.id(), nBits, Math::min);
    }

    /**
     * Ensure the circuit proves {@code v < 2^nBits}, emitting a decomposition only if that is
     * not already established.
     *
     * <p>A constant operand is never decomposed: its value is known at definition time, so we
     * validate it statically and fail loudly rather than emit constraints that would encode a
     * wrong comparison.
     */
    private void requireRange(Variable v, int nBits, String role) {
        BigInteger constValue = constantWireValues.get(v.id());
        if (constValue != null) {
            if (constValue.signum() < 0 || constValue.bitLength() > nBits) {
                throw new IllegalArgumentException(
                        "lessThan " + role + " operand is the constant " + constValue
                                + ", which does not fit in " + nBits + " bits; the comparison "
                                + "would wrap modulo the field prime and return a wrong result");
            }
            return;
        }
        Integer existing = rangeBounds.get(v.id());
        if (existing != null && existing <= nBits) {
            return; // already proven < 2^existing <= 2^nBits
        }
        decompose(v, nBits);
    }

    @Override
    public Variable fromBinary(Variable[] bits) {
        var terms = new ArrayList<Gate.Term>();
        BigInteger pow2 = BigInteger.ONE;
        for (Variable bit : bits) {
            terms.add(new Gate.Term(pow2, bit));
            pow2 = pow2.shiftLeft(1);
        }
        var out = newIntermediate();
        gates.add(new Gate.LinComb(out, terms));
        int[] ids = new int[bits.length];
        for (int i = 0; i < bits.length; i++) ids[i] = bits[i].id();
        recompositions.put(out.id(), ids);
        return out;
    }

    @Override
    public Variable xor(Variable a, Variable b) {
        // a ^ b = a + b - 2*a*b (both must be boolean)
        var ab = mul(a, b);
        var twoAb = add(ab, ab);
        return sub(add(a, b), twoAb);
    }

    @Override
    public Variable and(Variable a, Variable b) {
        return mul(a, b);
    }

    @Override
    public Variable or(Variable a, Variable b) {
        // a | b = a + b - a*b
        return sub(add(a, b), mul(a, b));
    }

    @Override
    public Variable not(Variable a) {
        return sub(oneWire, a);
    }

    // --- Assertions ---

    @Override
    public void assertBoolean(Variable a) {
        // Check before consulting the idempotency cache. Otherwise an escaped value whose wire
        // was already proven boolean could return normally after buildGraph(), falsely making
        // a post-build assertion look effective.
        requireNotFrozen();
        // Already proven boolean by an earlier constraint on this wire: re-emitting adds
        // constraints without adding information. This is what makes a four-coordinate
        // point-select cost one booleanity check instead of four.
        if (!booleanWires.add(a.id())) return;
        // a * (a - 1) = 0
        var aMinusOne = sub(a, oneWire);
        var product = mul(a, aMinusOne);
        assertEqual(product, constant(0));
    }

    @Override
    public void assertInRange(Variable a, int nBits) {
        toBinary(a, nBits); // decompose + boolean constraints enforce range
    }

    @Override
    public void assertNotEqual(Variable a, Variable b) {
        // (a - b) has an inverse → a != b
        inv(sub(a, b));
    }

    // --- Comparison ---

    @Override
    public Variable isZero(Variable a) {
        var result = newIntermediate();
        var invA = newIntermediate();
        gates.add(new Gate.Hint(result, Gate.HintType.IS_ZERO_RESULT, a));
        gates.add(new Gate.Hint(invA, Gate.HintType.IS_ZERO_INVERSE, a));
        // Constraints: a * invA = 1 - result, and a * result = 0
        var aTimesInv = mul(a, invA);
        assertEqual(aTimesInv, sub(oneWire, result));
        var aTimesResult = mul(a, result);
        assertEqual(aTimesResult, constant(0));
        return result;
    }

    @Override
    public Variable isEqual(Variable a, Variable b) {
        return isZero(sub(a, b));
    }

    @Override
    public Variable lessThan(Variable a, Variable b, int nBits) {
        if (nBits <= 0 || nBits >= MAX_SAFE_BITS)
            throw new IllegalArgumentException(
                    "lessThan nBits must be in [1, " + (MAX_SAFE_BITS - 1) + "], got " + nBits);
        // Soundness precondition: both operands must fit in nBits. Without it the subtraction
        // below wraps modulo p and the comparison is forgeable in BOTH directions --
        // an unbounded left operand forges a < b, an unbounded right operand forges a >= b.
        // See ADR-0037 Context item 11.
        requireRange(a, nBits, "left");
        requireRange(b, nBits, "right");
        return lessThanUnchecked(a, b, nBits);
    }

    @Override
    public Variable lessThan(BitDecomposition a, BitDecomposition b) {
        Objects.requireNonNull(a, "a");
        Objects.requireNonNull(b, "b");
        // Ownership first, BOTH operands, before reading widths or sources. This overload
        // skips requireRange entirely on the strength of the typed evidence, so authenticating
        // that evidence IS the range check here: a foreign operand would leave the comparison
        // with no bound at all. Validating both up front keeps the rejection atomic — a
        // foreign right-hand operand cannot be rejected only after the left one has emitted
        // constraints (ADR-0038 Decision 1).
        requireOwned(a);
        requireOwned(b);
        int nBits = Math.max(a.width(), b.width());
        if (nBits >= MAX_SAFE_BITS)
            throw new IllegalArgumentException(
                    "lessThan width must be at most " + (MAX_SAFE_BITS - 1) + ", got " + nBits);
        // Both operands are this circuit's own evidence that they are < 2^width <= 2^nBits,
        // so the precondition is discharged and no new range constraints are needed.
        return lessThanUnchecked(a.source(), b.source(), nBits);
    }

    /**
     * The comparison itself. Callers are responsible for having established that both
     * operands fit in {@code nBits}.
     */
    private Variable lessThanUnchecked(Variable a, Variable b, int nBits) {
        // diff = (2^nBits - 1) + b - a.
        // If a < b: diff >= 2^nBits, MSB of (nBits+1)-bit decomposition is 1
        // If a == b: diff = 2^nBits - 1 < 2^nBits, MSB is 0
        // If a > b: diff < 2^nBits, MSB is 0
        var offset = constant(BigInteger.ONE.shiftLeft(nBits).subtract(BigInteger.ONE));
        var diff = add(offset, sub(b, a));
        var bits = decompose(diff, nBits + 1).bitsNoCopy();
        return bits[nBits]; // MSB
    }

    // --- Array ---

    @Override
    public Variable arrayAccess(Variable[] arr, Variable index) {
        // MUX: sum(arr[i] * isEqual(index, i))
        Variable result = constant(0);
        for (int i = 0; i < arr.length; i++) {
            var selector = isEqual(index, constant(i));
            result = add(result, mul(arr[i], selector));
        }
        return result;
    }

    // --- Variable access ---

    @Override
    public Variable var(String name) {
        var v = namedVars.get(name);
        if (v == null) throw new IllegalArgumentException("Unknown variable: " + name);
        return v;
    }

    @Override
    public Variable publicInputVar(String name) {
        return inputVar(name, InputVisibility.PUBLIC);
    }

    @Override
    public Variable secretInputVar(String name) {
        return inputVar(name, InputVisibility.SECRET);
    }

    private Variable inputVar(String name, InputVisibility expected) {
        var v = namedVars.get(name);
        if (v == null) throw new IllegalArgumentException("Unknown variable: " + name);

        var actual = inputVisibilities.get(name);
        if (actual != expected) {
            throw new IllegalArgumentException(
                    "Variable " + name + " is declared as " + actual.label()
                            + " but was requested as " + expected.label());
        }
        return v;
    }

    private enum InputVisibility {
        PUBLIC("public"),
        SECRET("secret");

        private final String label;

        InputVisibility(String label) {
            this.label = label;
        }

        String label() {
            return label;
        }
    }
}
