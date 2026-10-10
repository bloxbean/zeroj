package org.zeroj.onchain.julc.groth16.validator;

import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.crypto.groth16.Groth16ProverBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Issue #84, ADR-0056: {@code Groth16BLS12381Lib} decompresses every point once instead of twice:
 * the proof and key points (A, B, C, alpha, beta, gamma, delta) and every IC entry, which is still
 * fully validated before any scalar multiplication (ADR-0045 V1). This differential test runs the
 * library and the pre-change reference copy ({@code Groth16BLS12381LibReference}, test sources) on
 * the same honest and adversarial vectors and requires the same outcome for each: accept,
 * {@code false}, or a builtin failure (told apart by the probe validators' expected-result
 * redeemer), except for the divergences listed in {@link #DIVERGENCES}, which only swap
 * {@code false} and a builtin failure on malformed key data. An accepted proof must save exactly
 * the removed decompressions, (n + 4) G1 and 4 G2, to within half a G1 decompression.
 * Pairing-preserving vectors (all inputs zero, every IC entry the generator) isolate each proof
 * and key point's infinity check, with explicit expected outcomes.
 */
class Groth16SingleDecompressionDifferentialTest extends ContractTest {

    /** Plutus V3 (PV11) CPU cost of {@code bls12_381_G1_uncompress} and {@code bls12_381_G2_uncompress}. */
    private static final long G1_UNCOMPRESS = 52_948_122L;
    private static final long G2_UNCOMPRESS = 74_698_472L;
    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    enum Outcome { ACCEPT, FALSE, ERROR }

    record Run(Outcome outcome, long cpu) {}

    record Vector(String label, SnarkjsToCardano.VkCompressed vk, List<byte[]> ic,
                  SnarkjsToCardano.ProofCompressed proof, BigInteger[] inputs) {}

    record TestProof(SnarkjsToCardano.VkCompressed vk, SnarkjsToCardano.ProofCompressed proof, BigInteger[] inputs) {}

    /**
     * The only outcome differences ADR-0056 allows: the IC byte checks (length, infinity) run over
     * the whole list before any IC entry is decompressed, so a wrong-length entry after an
     * undecodable one returns {@code false} where the reference failed at the undecodable entry.
     * Both reject the transaction.
     */
    private static final Map<String, List<Outcome>> DIVERGENCES = Map.of(
            "IC[0] flag cleared, then IC[last] 49 bytes", List.of(Outcome.ERROR, Outcome.FALSE));

    private static final Map<Class<?>, CompileResult> COMPILED = new HashMap<>();
    private static final Map<String, TestProof> PROOFS = new LinkedHashMap<>();

    @BeforeAll
    static void setup() throws Exception {
        PROOFS.put("sealed-bid (2 inputs, snarkjs)", new TestProof(
                SnarkjsToCardano.parseVk(resource("/test-circuits/sealed-bid-bls12381/verification_key.json")),
                SnarkjsToCardano.parseProof(resource("/test-circuits/sealed-bid-bls12381/proof.json")),
                SnarkjsToCardano.parsePublicInputs(resource("/test-circuits/sealed-bid-bls12381/public.json"))
                        .toArray(new BigInteger[0])));
        PROOFS.put("linear (3 inputs)", linearProof(3));
        PROOFS.put("linear (4 inputs)", linearProof(4));
        PROOFS.put("linear (9 inputs)", linearProof(9));
        PROOFS.put("zero input (3 inputs, p1 = 0)", linearProof(3, 1));
    }

    @Test
    @DisplayName("verify: same outcome as the reference on every vector (listed divergences aside); each accepted proof saves exactly (n + 4) G1 + 4 G2 decompressions")
    void verifyMatchesReference() {
        int vectors = 0;
        Map<Outcome, Integer> outcomes = new EnumMap<>(Outcome.class);
        for (var entry : PROOFS.entrySet()) {
            TestProof tp = entry.getValue();
            for (Vector v : vectors(entry.getKey(), tp)) {
                Run optimized = run(Groth16VerifyOutcomeProbe.class, v);
                Run reference = run(Groth16VerifyOutcomeProbeReference.class, v);
                assertExpected(v.label(), reference.outcome(), optimized.outcome());
                if (v.label().endsWith(": honest")) {
                    assertEquals(Outcome.ACCEPT, optimized.outcome(), v.label());
                    assertSaving(v.label(), tp.inputs().length + 4, reference.cpu() - optimized.cpu());
                }
                outcomes.merge(optimized.outcome(), 1, Integer::sum);
                vectors++;
            }
        }
        System.out.printf("[issue #84] verify: %d vectors, identical outcomes except the listed divergences %s%n", vectors, outcomes);
        // Every outcome class is exercised, so agreement is not vacuous.
        for (Outcome o : Outcome.values()) assertTrue(outcomes.getOrDefault(o, 0) > 0, "no vector yields " + o);
    }

    @Test
    @DisplayName("verifyFour: same outcome as the reference on every vector; an accepted proof saves exactly 8 G1 + 4 G2 decompressions")
    void verifyFourMatchesReference() {
        TestProof tp = PROOFS.get("linear (4 inputs)");
        List<Vector> four = new ArrayList<>(vectors("four", tp));
        four.removeIf(v -> v.inputs().length != 4); // the probe requires exactly four inputs
        List<byte[]> ic = tp.vk().ic();
        four.add(new Vector("four: IC has 4 entries", tp.vk(), ic.subList(0, 4), tp.proof(), tp.inputs()));
        List<byte[]> six = new ArrayList<>(ic);
        six.add(ic.get(1));
        four.add(new Vector("four: IC has 6 entries", tp.vk(), six, tp.proof(), tp.inputs()));
        // The count checks come before any IC point is decompressed.
        four.add(new Vector("four: IC has 4 entries, the last flag-cleared", tp.vk(),
                with(ic.subList(0, 4), 3, flag(ic.get(3), 0x7F, 0)), tp.proof(), tp.inputs()));
        List<byte[]> sixBad = new ArrayList<>(six);
        sixBad.set(2, flag(ic.get(2), 0x7F, 0));
        four.add(new Vector("four: IC has 6 entries, one flag-cleared", tp.vk(), sixBad, tp.proof(), tp.inputs()));
        TestProof zero = linearProof(4, 2);
        four.add(new Vector("four, zero input: honest", zero.vk(), zero.vk().ic(), zero.proof(), zero.inputs()));
        four.add(new Vector("four, zero input: IC[3] infinity", zero.vk(), with(zero.vk().ic(), 3, infinityG1()),
                zero.proof(), zero.inputs()));
        for (Vector v : four) {
            Run optimized = run(Groth16VerifyFourOutcomeProbe.class, v);
            Run reference = run(Groth16VerifyFourOutcomeProbeReference.class, v);
            assertEquals(reference.outcome(), optimized.outcome(), v.label());
            if (v.label().endsWith(": honest")) {
                assertEquals(Outcome.ACCEPT, optimized.outcome(), v.label());
                assertSaving(v.label(), 8, reference.cpu() - optimized.cpu());
            }
        }
        System.out.printf("[issue #84] verifyFour: %d vectors, identical outcomes%n", four.size());
    }

    /** Exactly the {@code g1} G1 decompressions (A, C, alpha and the IC entries) and 4 G2 (B, beta, gamma, delta) removed. */
    private static void assertSaving(String label, int g1, long saved) {
        long expected = g1 * G1_UNCOMPRESS + 4L * G2_UNCOMPRESS;
        System.out.printf("[issue #84] %s: %,d steps saved (removed decompressions: %,d)%n", label, saved, expected);
        assertTrue(Math.abs(saved - expected) < G1_UNCOMPRESS / 2,
                label + ": saved " + saved + " steps, expected " + expected + " (" + g1 + " G1 + 4 G2)");
    }

    /** The same outcome as the reference, or exactly a listed divergence. */
    private static void assertExpected(String label, Outcome reference, Outcome optimized) {
        String key = label.substring(label.indexOf(": ") + 2);
        List<Outcome> divergence = DIVERGENCES.get(key);
        if (divergence != null) {
            assertEquals(divergence, List.of(reference, optimized), label + " (listed divergence)");
        } else {
            assertEquals(reference, optimized, label);
        }
    }

    @Test
    @DisplayName("Pairing-preserving infinity (review F1): with inputs 0 and every IC entry G the pairing holds, so only the infinity check refuses each point")
    void pairingPreservingInfinity() {
        for (int inputs : new int[]{3, 4}) {
            boolean four = inputs == 4;
            Class<?> optimized = four ? Groth16VerifyFourOutcomeProbe.class : Groth16VerifyOutcomeProbe.class;
            Class<?> reference = four ? Groth16VerifyFourOutcomeProbeReference.class : Groth16VerifyOutcomeProbeReference.class;
            for (int position = -1; position < 7; position++) {
                Vector v = pairingPreserving(inputs, position);
                Outcome expected = position < 0 ? Outcome.ACCEPT : Outcome.FALSE;
                assertEquals(expected, run(reference, v).outcome(), "reference: " + v.label());
                assertEquals(expected, run(optimized, v).outcome(), v.label());
            }
        }
    }

    /**
     * Generators G, H; every IC entry G and every input 0, so {@code vk_x = G}. With
     * {@code A = a·G, B = b·H, C = c·G, alpha = α·G, beta = β·H, gamma = γ·H, delta = δ·H} the
     * equation {@code e(A, B) = e(alpha, beta) · e(vk_x, gamma) · e(C, delta)} holds iff
     * {@code a·b = α·β + γ + c·δ}. {@code position} 0 to 6 sets that point to infinity (its
     * exponent 0) with the others chosen so the equation still holds; -1 is the all-nonzero
     * baseline {@code (3, 1, 1, 1, 1, 1, 1)}.
     */
    private static Vector pairingPreserving(int inputs, int position) {
        long[][] exponents = {
                {0, 1, -2, 1, 1, 1, 1},  // A
                {1, 0, -2, 1, 1, 1, 1},  // B
                {2, 1, 0, 1, 1, 1, 1},   // C
                {2, 1, 1, 0, 1, 1, 1},   // alpha
                {2, 1, 1, 1, 0, 1, 1},   // beta
                {2, 1, 1, 1, 1, 0, 1},   // gamma
                {2, 1, 1, 1, 1, 1, 0}};  // delta
        long[] e = position < 0 ? new long[]{3, 1, 1, 1, 1, 1, 1} : exponents[position];
        String[] names = {"A", "B", "C", "alpha", "beta", "gamma", "delta"};
        byte[] g = g1(1);
        List<byte[]> ic = new ArrayList<>();
        for (int i = 0; i <= inputs; i++) ic.add(g);
        var vk = new SnarkjsToCardano.VkCompressed(g1(e[3]), g2(e[4]), g2(e[5]), g2(e[6]), ic);
        var proof = proof(g1(e[0]), g2(e[1]), g1(e[2]));
        BigInteger[] zeros = new BigInteger[inputs];
        Arrays.fill(zeros, BigInteger.ZERO);
        String label = "pairing-preserving (" + inputs + " inputs): " + (position < 0 ? "baseline" : names[position] + " infinity");
        return new Vector(label, vk, ic, proof, zeros);
    }

    /** {@code k·G} compressed; {@code 0} gives the compressed point at infinity. */
    private static byte[] g1(long k) {
        if (k == 0) return infinityG1();
        var p = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(Math.abs(k)));
        return ProverToCardano.g1Compress((k < 0 ? p.negate() : p).toAffine());
    }

    /** {@code k·H} compressed; {@code 0} gives the compressed point at infinity. */
    private static byte[] g2(long k) {
        if (k == 0) return infinityG2();
        var p = JacobianG2BLS381.GENERATOR.scalarMul(BigInteger.valueOf(Math.abs(k)));
        return ProverToCardano.g2Compress((k < 0 ? p.negate() : p).toAffine());
    }

    // ------------------------------------------------------------------ vectors

    private static List<Vector> vectors(String name, TestProof tp) {
        var vk = tp.vk();
        var p = tp.proof();
        List<byte[]> ic = tp.vk().ic();
        BigInteger[] in = tp.inputs();
        int last = ic.size() - 1;
        List<Vector> out = new ArrayList<>();
        out.add(new Vector(name + ": honest", vk, ic, p, in));

        // Public inputs.
        out.add(new Vector(name + ": wrong input", vk, ic, p, with(in, 0, in[0].add(BigInteger.ONE))));
        out.add(new Vector(name + ": input = r", vk, ic, p, with(in, 0, FR)));
        out.add(new Vector(name + ": input = -1", vk, ic, p, with(in, in.length - 1, BigInteger.ONE.negate())));
        out.add(new Vector(name + ": too few inputs", vk, ic, p, Arrays.copyOf(in, in.length - 1)));
        out.add(new Vector(name + ": too many inputs", vk, ic, p, append(in, BigInteger.ONE)));
        out.add(new Vector(name + ": empty IC", vk, List.of(), p, in));

        // Proof points.
        out.add(new Vector(name + ": A infinity", vk, ic, proof(infinityG1(), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": B infinity", vk, ic, proof(p.piA(), infinityG2(), p.piC()), in));
        out.add(new Vector(name + ": C infinity", vk, ic, proof(p.piA(), p.piB(), infinityG1()), in));
        out.add(new Vector(name + ": A 47 bytes", vk, ic, proof(Arrays.copyOf(p.piA(), 47), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": A 49 bytes", vk, ic, proof(Arrays.copyOf(p.piA(), 49), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": B 95 bytes", vk, ic, proof(p.piA(), Arrays.copyOf(p.piB(), 95), p.piC()), in));
        out.add(new Vector(name + ": C 49 bytes", vk, ic, proof(p.piA(), p.piB(), Arrays.copyOf(p.piC(), 49)), in));
        out.add(new Vector(name + ": A compression flag cleared", vk, ic, proof(flag(p.piA(), 0x7F, 0), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": B compression flag cleared", vk, ic, proof(p.piA(), flag(p.piB(), 0x7F, 0), p.piC()), in));
        out.add(new Vector(name + ": A negated (sort flag)", vk, ic, proof(flag(p.piA(), 0xFF, 0x20), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": A last byte changed", vk, ic, proof(lastByte(p.piA()), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": B last byte changed", vk, ic, proof(p.piA(), lastByte(p.piB()), p.piC()), in));
        out.add(new Vector(name + ": A infinity with sort flag", vk, ic, proof(sortedInfinity(48), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": B infinity with sort flag", vk, ic, proof(p.piA(), sortedInfinity(96), p.piC()), in));
        out.add(new Vector(name + ": A infinity with a non-zero body", vk, ic, proof(dirtyInfinity(48), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": A and C swapped", vk, ic, proof(p.piC(), p.piB(), p.piA()), in));

        // Key points.
        out.add(new Vector(name + ": alpha infinity", key(vk, infinityG1(), vk.beta(), vk.gamma(), vk.delta()), ic, p, in));
        out.add(new Vector(name + ": beta infinity", key(vk, vk.alpha(), infinityG2(), vk.gamma(), vk.delta()), ic, p, in));
        out.add(new Vector(name + ": gamma infinity", key(vk, vk.alpha(), vk.beta(), infinityG2(), vk.delta()), ic, p, in));
        out.add(new Vector(name + ": delta infinity", key(vk, vk.alpha(), vk.beta(), vk.gamma(), infinityG2()), ic, p, in));
        out.add(new Vector(name + ": alpha 47 bytes", key(vk, Arrays.copyOf(vk.alpha(), 47), vk.beta(), vk.gamma(), vk.delta()), ic, p, in));
        out.add(new Vector(name + ": gamma 95 bytes", key(vk, vk.alpha(), vk.beta(), Arrays.copyOf(vk.gamma(), 95), vk.delta()), ic, p, in));
        out.add(new Vector(name + ": delta flag cleared", key(vk, vk.alpha(), vk.beta(), vk.gamma(), flag(vk.delta(), 0x7F, 0)), ic, p, in));
        out.add(new Vector(name + ": beta negated", key(vk, vk.alpha(), flag(vk.beta(), 0xFF, 0x20), vk.gamma(), vk.delta()), ic, p, in));

        // IC points, including the order of IC validation against the count check.
        for (int i = 0; i <= last; i++) {
            out.add(new Vector(name + ": IC[" + i + "] infinity", vk, with(ic, i, infinityG1()), p, in));
        }
        out.add(new Vector(name + ": IC[0] 47 bytes", vk, with(ic, 0, Arrays.copyOf(ic.get(0), 47)), p, in));
        out.add(new Vector(name + ": IC[last] 49 bytes", vk, with(ic, last, Arrays.copyOf(ic.get(last), 49)), p, in));
        out.add(new Vector(name + ": IC[last] flag cleared", vk, with(ic, last, flag(ic.get(last), 0x7F, 0)), p, in));
        out.add(new Vector(name + ": IC[1] negated", vk, with(ic, 1, flag(ic.get(1), 0xFF, 0x20)), p, in));
        out.add(new Vector(name + ": IC[last] infinity with sort flag", vk, with(ic, last, sortedInfinity(48)), p, in));
        out.add(new Vector(name + ": too many inputs and IC[last] flag cleared", vk,
                with(ic, last, flag(ic.get(last), 0x7F, 0)), p, append(in, BigInteger.ONE)));
        out.add(new Vector(name + ": too few inputs and IC[last] flag cleared", vk,
                with(ic, last, flag(ic.get(last), 0x7F, 0)), p, Arrays.copyOf(in, in.length - 1)));
        out.add(new Vector(name + ": too few inputs and IC[last] infinity", vk,
                with(ic, last, infinityG1()), p, Arrays.copyOf(in, in.length - 1)));
        out.add(new Vector(name + ": input = r and IC[last] flag cleared", vk,
                with(ic, last, flag(ic.get(last), 0x7F, 0)), p, with(in, 0, FR)));
        out.add(new Vector(name + ": too many inputs and A flag cleared", vk, ic,
                proof(flag(p.piA(), 0x7F, 0), p.piB(), p.piC()), append(in, BigInteger.ONE)));

        // Check order across points: an early false must win over a later malformed point, and an
        // early malformed point must fail even when a later point would be false.
        byte[] zeroG2 = new byte[96];
        out.add(new Vector(name + ": A 47 bytes, then B all zero", vk, ic, proof(Arrays.copyOf(p.piA(), 47), zeroG2, p.piC()), in));
        out.add(new Vector(name + ": A infinity, then B flag cleared", vk, ic,
                proof(infinityG1(), flag(p.piB(), 0x7F, 0), p.piC()), in));
        out.add(new Vector(name + ": A flag cleared, then B 95 bytes", vk, ic,
                proof(flag(p.piA(), 0x7F, 0), Arrays.copyOf(p.piB(), 95), p.piC()), in));
        out.add(new Vector(name + ": C infinity, then alpha flag cleared", key(vk, flag(vk.alpha(), 0x7F, 0), vk.beta(),
                vk.gamma(), vk.delta()), ic, proof(p.piA(), p.piB(), infinityG1()), in));
        out.add(new Vector(name + ": gamma flag cleared, then delta 95 bytes", key(vk, vk.alpha(), vk.beta(),
                flag(vk.gamma(), 0x7F, 0), Arrays.copyOf(vk.delta(), 95)), ic, p, in));
        out.add(new Vector(name + ": beta infinity, then gamma all zero", key(vk, vk.alpha(), infinityG2(), zeroG2,
                vk.delta()), ic, p, in));
        out.add(new Vector(name + ": IC[1] infinity, then A flag cleared", vk, with(ic, 1, infinityG1()),
                proof(flag(p.piA(), 0x7F, 0), p.piB(), p.piC()), in));
        out.add(new Vector(name + ": IC[0] flag cleared, then IC[last] 49 bytes", vk,
                with(with(ic, 0, flag(ic.get(0), 0x7F, 0)), last, Arrays.copyOf(ic.get(last), 49)), p, in));

        // An infinity IC entry whose input is 0 adds nothing to vk_x, so the pairing still holds:
        // only the explicit infinity check (ADR-0045 V1) refuses it.
        for (int i = 0; i < in.length; i++) {
            if (in[i].signum() == 0) {
                out.add(new Vector(name + ": IC[" + (i + 1) + "] infinity for a zero input", vk,
                        with(ic, i + 1, infinityG1()), p, in));
            }
        }
        return out;
    }

    // ------------------------------------------------------------------ running

    private Run run(Class<?> probe, Vector v) {
        CompileResult compiled = COMPILED.computeIfAbsent(probe, c -> compileValidator(c, Path.of("src/test/java")));
        assertNotNull(compiled);
        Program program = compiled.program().applyParams(
                PlutusData.bytes(v.vk().alpha()), PlutusData.bytes(v.vk().beta()),
                PlutusData.bytes(v.vk().gamma()), PlutusData.bytes(v.vk().delta()), icData(v.ic()));
        EvalResult expectTrue = evaluate(program, context(v, 1));
        EvalResult expectFalse = evaluate(program, context(v, 0));
        boolean t = expectTrue instanceof EvalResult.Success;
        boolean f = expectFalse instanceof EvalResult.Success;
        if (t && f) fail(v.label() + ": both expectations succeeded");
        if (t) return new Run(Outcome.ACCEPT, expectTrue.budgetConsumed().cpuSteps());
        if (f) return new Run(Outcome.FALSE, expectFalse.budgetConsumed().cpuSteps());
        return new Run(Outcome.ERROR, 0);
    }

    private PlutusData context(Vector v, int expect) {
        PlutusData[] inputs = new PlutusData[v.inputs().length];
        for (int i = 0; i < inputs.length; i++) inputs[i] = PlutusData.integer(v.inputs()[i]);
        PlutusData redeemer = PlutusData.constr(0, PlutusData.bytes(v.proof().piA()), PlutusData.bytes(v.proof().piB()),
                PlutusData.bytes(v.proof().piC()), PlutusData.integer(BigInteger.valueOf(expect)));
        return spendingContext(TestDataBuilder.randomTxOutRef_typed(), PlutusData.list(inputs))
                .redeemer(redeemer)
                .buildPlutusData();
    }

    // ------------------------------------------------------------------ encodings

    private static PlutusData icData(List<byte[]> ic) {
        return PlutusData.list(ic.stream().map(PlutusData::bytes).toArray(PlutusData[]::new));
    }

    private static SnarkjsToCardano.ProofCompressed proof(byte[] a, byte[] b, byte[] c) {
        return new SnarkjsToCardano.ProofCompressed(a, b, c);
    }

    private static SnarkjsToCardano.VkCompressed key(SnarkjsToCardano.VkCompressed vk, byte[] alpha, byte[] beta,
                                                      byte[] gamma, byte[] delta) {
        return new SnarkjsToCardano.VkCompressed(alpha, beta, gamma, delta, vk.ic());
    }

    private static byte[] infinityG1() {
        byte[] b = new byte[48];
        b[0] = (byte) 0xC0;
        return b;
    }

    private static byte[] infinityG2() {
        byte[] b = new byte[96];
        b[0] = (byte) 0xC0;
        return b;
    }

    /** The infinity flag with the sort flag also set: not the canonical encoding of infinity. */
    private static byte[] sortedInfinity(int length) {
        byte[] b = new byte[length];
        b[0] = (byte) 0xE0;
        return b;
    }

    /** The infinity flag with a non-zero body. */
    private static byte[] dirtyInfinity(int length) {
        byte[] b = new byte[length];
        b[0] = (byte) 0xC0;
        b[length - 1] = 1;
        return b;
    }

    /** {@code (b[0] & and) ^ xor}. */
    private static byte[] flag(byte[] point, int and, int xor) {
        byte[] b = point.clone();
        b[0] = (byte) ((b[0] & and) ^ xor);
        return b;
    }

    private static byte[] lastByte(byte[] point) {
        byte[] b = point.clone();
        b[b.length - 1] ^= 1;
        return b;
    }

    private static <T> List<T> with(List<T> list, int index, T value) {
        List<T> copy = new ArrayList<>(list);
        copy.set(index, value);
        return copy;
    }

    private static BigInteger[] with(BigInteger[] values, int index, BigInteger value) {
        BigInteger[] copy = values.clone();
        copy[index] = value;
        return copy;
    }

    private static BigInteger[] append(BigInteger[] values, BigInteger value) {
        BigInteger[] copy = Arrays.copyOf(values, values.length + 1);
        copy[values.length] = value;
        return copy;
    }

    // ------------------------------------------------------------------ proofs

    /** {@code p_0 · x + p_1 + … + p_{n-2} = p_{n-1}} with a secret {@code x}: n public inputs. */
    private static TestProof linearProof(int n) {
        return linearProof(n, -1);
    }

    /** As {@link #linearProof(int)}, with public input {@code zero} (1 to n - 2) set to 0. */
    private static TestProof linearProof(int n, int zero) {
        var builder = CircuitBuilder.create("linear-" + n + "-" + zero);
        for (int i = 0; i < n; i++) builder = builder.publicVar("p" + i);
        builder = builder.secretVar("x");
        var circuit = builder.define(api -> {
            var sum = api.mul(api.var("p0"), api.var("x"));
            for (int i = 1; i < n - 1; i++) sum = api.add(sum, api.var("p" + i));
            api.assertEqual(sum, api.var("p" + (n - 1)));
        });
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(n, r1cs.numPublicInputs());
        Map<String, List<BigInteger>> values = new HashMap<>();
        BigInteger x = BigInteger.valueOf(7);
        BigInteger total = BigInteger.valueOf(3).multiply(x);
        values.put("p0", List.of(BigInteger.valueOf(3)));
        for (int i = 1; i < n - 1; i++) {
            BigInteger value = i == zero ? BigInteger.ZERO : BigInteger.valueOf(10L + i);
            values.put("p" + i, List.of(value));
            total = total.add(value);
        }
        values.put("p" + (n - 1), List.of(total));
        values.put("x", List.of(x));
        BigInteger[] witness = circuit.calculateWitness(values, CurveId.BLS12_381);
        var srs = PowersOfTauBLS381.generate(8);
        var setup = Groth16SetupBLS381.setup(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), srs.tauScalar());
        var proof = Groth16ProverBLS381.prove(setup.provingKey(), witness, r1cs.constraints(), r1cs.numWires());
        return new TestProof(ProverToCardano.compressVk(setup), ProverToCardano.compressProof(proof),
                Arrays.copyOfRange(witness, 1, n + 1));
    }

    private static String resource(String path) throws IOException {
        try (InputStream in = Groth16SingleDecompressionDifferentialTest.class.getResourceAsStream(path)) {
            assertNotNull(in, path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
