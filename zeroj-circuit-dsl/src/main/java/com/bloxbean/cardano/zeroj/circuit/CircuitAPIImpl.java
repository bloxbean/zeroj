package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;
import java.util.*;

/**
 * Internal implementation of {@link CircuitAPI} that builds a {@link ConstraintGraph}.
 */
class CircuitAPIImpl implements CircuitAPI {

    private final List<Gate> gates = new ArrayList<>();
    private final Map<String, Variable> namedVars = new LinkedHashMap<>();
    private final Map<BigInteger, Variable> constantCache = new HashMap<>();
    private final List<Variable> publicInputs = new ArrayList<>();
    private final List<Variable> secretInputs = new ArrayList<>();
    private final List<Variable> intermediateVars = new ArrayList<>();
    private final Variable oneWire;
    private int nextId;

    CircuitAPIImpl(List<String> publicVarNames, List<String> secretVarNames) {
        // Wire 0 = constant "1"
        this.oneWire = new Variable(0, "_one");
        this.nextId = 1;
        gates.add(new Gate.Const(oneWire, BigInteger.ONE));

        // Public inputs
        for (String name : publicVarNames) {
            var v = new Variable(nextId++, name);
            publicInputs.add(v);
            namedVars.put(name, v);
        }

        // Secret inputs
        for (String name : secretVarNames) {
            var v = new Variable(nextId++, name);
            secretInputs.add(v);
            namedVars.put(name, v);
        }
    }

    private Variable newIntermediate() {
        var v = Variable.intermediate(nextId++);
        intermediateVars.add(v);
        return v;
    }

    ConstraintGraph buildGraph(String name) {
        return new ConstraintGraph(name, gates, oneWire, publicInputs, secretInputs,
                intermediateVars, nextId);
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
            return out;
        });
    }

    // --- Binary ---

    @Override
    public Variable[] toBinary(Variable a, int nBits) {
        var bits = new Variable[nBits];
        for (int i = 0; i < nBits; i++) {
            bits[i] = newIntermediate();
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
        return bits;
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
        // diff = (2^nBits - 1) + b - a.
        // If a < b: diff >= 2^nBits, MSB of (nBits+1)-bit decomposition is 1
        // If a == b: diff = 2^nBits - 1 < 2^nBits, MSB is 0
        // If a > b: diff < 2^nBits, MSB is 0
        var offset = constant(BigInteger.ONE.shiftLeft(nBits).subtract(BigInteger.ONE));
        var diff = add(offset, sub(b, a));
        var bits = toBinary(diff, nBits + 1);
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
}
