package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.CircuitBuilder;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0052 M2 at the {@link org.zeroj.circuit.CircuitAPI} level: the library's own host
 * encryption, {@link ElGamal}, against {@link InCircuitElGamal} on the same {@code (m, k)}
 * (the differential the ADR's verification section asks for), and the low-level guard rails.
 */
class InCircuitElGamalTest {

    private static CircuitBuilder circuit(int width) {
        return CircuitBuilder.create("in-circuit-elgamal-w" + width)
                .publicVar("pkU").publicVar("pkV")
                .publicVar("aU").publicVar("aV").publicVar("bU").publicVar("bV")
                .secretVar("m").secretVar("k")
                .define(api -> {
                    var key = InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV"));
                    var ct = InCircuitElGamal.encrypt(api, key,
                            api.decompose(api.var("m"), width), api.decompose(api.var("k"), 252));
                    InCircuitElGamal.assertAffineEquals(api, ct.handle(), api.var("aU"), api.var("aV"));
                    InCircuitElGamal.assertAffineEquals(api, ct.blinded(), api.var("bU"), api.var("bV"));
                });
    }

    private static Map<String, List<BigInteger>> witness(ElGamalCiphertext c, BigInteger m, BigInteger k) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        List<BigInteger> key = c.context().jointKey().publicInputs();
        List<BigInteger> ct = c.publicInputs();
        w.put("pkU", List.of(key.get(0)));
        w.put("pkV", List.of(key.get(1)));
        w.put("aU", List.of(ct.get(0)));
        w.put("aV", List.of(ct.get(1)));
        w.put("bU", List.of(ct.get(2)));
        w.put("bV", List.of(ct.get(3)));
        w.put("m", List.of(m));
        w.put("k", List.of(k));
        return w;
    }

    @Test
    @DisplayName("Differential: ElGamal.encrypt output verifies in-circuit for the same (m, k), widths 1, 8, 64")
    void hostVersusCircuit() {
        Random rnd = new Random(61);
        NOfNKeyContext ctx = NOfNKeyContext.singleKey(ElGamalSecretKey.generate(new SecureRandom()));
        for (int width : new int[]{1, 8, 64}) {
            CircuitBuilder circuit = circuit(width);
            for (int i = 0; i < 3; i++) {
                BigInteger m = new BigInteger(width, rnd);
                BigInteger k = ElGamal.sample(new SecureRandom());
                ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, m, width, k);
                assertDoesNotThrow(() -> circuit.calculateWitness(witness(c, m, k), CurveId.BLS12_381),
                        "w=" + width + " m=" + m);
                assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                        witness(c, m, k.add(BigInteger.ONE).mod(JubjubCurve.SUBGROUP_ORDER)), CurveId.BLS12_381));
            }
        }
    }

    @Test
    @DisplayName("Foreign decompositions, wrong widths and a constant randomness wire are refused at definition")
    void guardRails() {
        var captured = new AtomicReference<BitDecomposition>();
        CircuitBuilder.create("foreign").secretVar("k")
                .define(api -> captured.set(api.decompose(api.var("k"), 252)));
        BitDecomposition foreign = captured.get();
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("victim")
                .publicVar("pkU").publicVar("pkV").secretVar("m")
                .define(api -> InCircuitElGamal.encrypt(api,
                        InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV")),
                        api.decompose(api.var("m"), 1), foreign)), "foreign randomness");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("constant-k")
                .publicVar("pkU").publicVar("pkV").secretVar("m")
                .define(api -> InCircuitElGamal.encrypt(api,
                        InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV")),
                        api.decompose(api.var("m"), 1), api.decompose(api.constant(BigInteger.TEN), 252))),
                "constant randomness");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zero-width")
                .publicVar("pkU").publicVar("pkV").secretVar("m").secretVar("k")
                .define(api -> InCircuitElGamal.encrypt(api,
                        InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV")),
                        api.decompose(api.var("m"), 65), api.decompose(api.var("k"), 252))), "width 65");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("secret-key")
                .secretVar("pkU").secretVar("pkV")
                .define(api -> InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV"))));
    }

    // ------------------------------------------------------------------ review round 1 (M2)

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger K = new BigInteger("0e6e9d50fbbb41bd6191632fcbf588bd6843f389aa856195f9a69d8cff98a304", 16);

    private static CircuitBuilder declare(String name, boolean keyPublic) {
        CircuitBuilder b = CircuitBuilder.create(name);
        b = keyPublic ? b.publicVar("pkU").publicVar("pkV") : b.secretVar("pkU").secretVar("pkV");
        return b.publicVar("aU").publicVar("aV").publicVar("bU").publicVar("bV").secretVar("m").secretVar("k");
    }

    private static CircuitBuilder encryption(String name, boolean keyPublic, int width) {
        return declare(name, keyPublic).define(api -> {
            var key = keyPublic
                    ? InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV"))
                    : InCircuitElGamal.keyWitnessedInSubgroup(api, api.var("pkU"), api.var("pkV"));
            var ct = InCircuitElGamal.encrypt(api, key, api.decompose(api.var("m"), width), api.decompose(api.var("k"), 252));
            InCircuitElGamal.assertAffineEquals(api, ct.handle(), api.var("aU"), api.var("aV"));
            InCircuitElGamal.assertAffineEquals(api, ct.blinded(), api.var("bU"), api.var("bV"));
        });
    }

    /**
     * The same computation as {@link InCircuitElGamal#encrypt} with no key checks at all (no
     * curve equation, no identity, no subgroup), but with the (A, B) binding. It yields the
     * (A, B) the real circuit computes for an arbitrary (u, v). A witness this twin accepts and
     * the real circuit rejects fails only on a key check: the negative is isolated.
     */
    private static CircuitBuilder twin(int width) {
        return declare("twin-w" + width, true).define(api -> {
            var u = api.var("pkU");
            var v = api.var("pkV");
            var key = new InCircuitJubjub.Point(u, v, api.constant(BigInteger.ONE), api.mul(u, v));
            var k = api.decompose(api.var("k"), 252);
            var m = api.decompose(api.var("m"), width);
            var handle = InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, k);
            var mask = InCircuitJubjub.scalarMulVariableBase(api, key, k);
            var encoded = width == 1
                    ? InCircuitJubjub.select(api, m.bit(0), InCircuitJubjub.constant(api, JubjubPoint.SUBGROUP_GENERATOR),
                            InCircuitJubjub.identity(api))
                    : InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, m);
            var blinded = InCircuitJubjub.add(api, encoded, mask);
            InCircuitElGamal.assertAffineEquals(api, handle, api.var("aU"), api.var("aV"));
            InCircuitElGamal.assertAffineEquals(api, blinded, api.var("bU"), api.var("bV"));
        });
    }

    /** Runs the twin unbound to learn the (A, B) it computes for (u, v), then binds them. */
    private static Map<String, List<BigInteger>> consistentWitness(int width, BigInteger u, BigInteger v,
                                                                   BigInteger m, BigInteger k) {
        AtomicReference<InCircuitJubjub.Point[]> out = new AtomicReference<>();
        CircuitBuilder probe = declare("probe", true).define(api -> {
            var pu = api.var("pkU");
            var pv = api.var("pkV");
            var key = new InCircuitJubjub.Point(pu, pv, api.constant(BigInteger.ONE), api.mul(pu, pv));
            var kd = api.decompose(api.var("k"), 252);
            var md = api.decompose(api.var("m"), width);
            var handle = InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, kd);
            var mask = InCircuitJubjub.scalarMulVariableBase(api, key, kd);
            var encoded = width == 1
                    ? InCircuitJubjub.select(api, md.bit(0), InCircuitJubjub.constant(api, JubjubPoint.SUBGROUP_GENERATOR),
                            InCircuitJubjub.identity(api))
                    : InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, md);
            out.set(new InCircuitJubjub.Point[]{handle, InCircuitJubjub.add(api, encoded, mask)});
            api.assertEqual(api.var("aU"), api.var("aU")); // keep the public wires referenced
        });
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(u));
        w.put("pkV", List.of(v));
        w.put("m", List.of(m));
        w.put("k", List.of(k));
        for (String n : List.of("aU", "aV", "bU", "bV")) w.put(n, List.of(BigInteger.ZERO));
        BigInteger[] full = probe.calculateWitness(w, CurveId.BLS12_381);
        String[][] names = {{"aU", "aV"}, {"bU", "bV"}};
        for (int i = 0; i < 2; i++) {
            InCircuitJubjub.Point p = out.get()[i];
            BigInteger zi = full[p.z().id()].modInverse(P);
            w.put(names[i][0], List.of(full[p.u().id()].multiply(zi).mod(P)));
            w.put(names[i][1], List.of(full[p.v().id()].multiply(zi).mod(P)));
        }
        return w;
    }

    @Test
    @DisplayName("I8: a Key admitted in one circuit is refused in another (both origins)")
    void foreignKeyRefused() {
        for (boolean keyPublic : new boolean[]{true, false}) {
            AtomicReference<InCircuitElGamal.Key> captured = new AtomicReference<>();
            declare("A", keyPublic).define(api -> captured.set(keyPublic
                    ? InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV"))
                    : InCircuitElGamal.keyWitnessedInSubgroup(api, api.var("pkU"), api.var("pkV"))));
            InCircuitElGamal.Key foreign = captured.get();
            var e = assertThrows(IllegalArgumentException.class, () -> declare("B", keyPublic).define(api ->
                    InCircuitElGamal.encrypt(api, foreign, api.decompose(api.var("m"), 1), api.decompose(api.var("k"), 252))));
            assertTrue(e.getMessage().contains("different circuit"), e.getMessage());
        }
    }

    @Test
    @DisplayName("Isolated negatives: an off-curve key with consistent (A, B) passes the unchecked twin and fails only the key checks")
    void offCurveKeyIsolated() {
        Map<String, List<BigInteger>> w = consistentWitness(1, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, K);
        assertDoesNotThrow(() -> twin(1).calculateWitness(w, CurveId.BLS12_381), "the twin accepts it");
        assertThrows(ArithmeticException.class, () -> encryption("real-fixed", true, 1).calculateWitness(w, CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> encryption("real-witnessed", false, 1).calculateWitness(w, CurveId.BLS12_381));
        // Positive control: the same construction for a valid key is accepted by the real circuit,
        // so the twin still computes exactly what encrypt computes.
        JubjubPoint valid = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(77)).normalized();
        Map<String, List<BigInteger>> control = consistentWitness(1, valid.u(), valid.v(), BigInteger.ONE, K);
        assertDoesNotThrow(() -> encryption("real-fixed", true, 1).calculateWitness(control, CurveId.BLS12_381));
        assertDoesNotThrow(() -> encryption("real-witnessed", false, 1).calculateWitness(control, CurveId.BLS12_381));
        Map<String, List<BigInteger>> identity = consistentWitness(1, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, K);
        assertDoesNotThrow(() -> twin(1).calculateWitness(identity, CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> encryption("real-fixed", true, 1).calculateWitness(identity, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Isolated DLEQ negative: an off-curve base with consistent D fails only the base's curve check")
    void offCurveBaseIsolated() {
        BigInteger x = BigInteger.valueOf(123456789);
        AtomicReference<InCircuitJubjub.Point[]> out = new AtomicReference<>();
        CircuitBuilder probe = CircuitBuilder.create("dleq-probe").secretVar("xu").secretVar("xv").secretVar("x")
                .define(api -> {
                    var xu = api.var("xu");
                    var xv = api.var("xv");
                    var base = new InCircuitJubjub.Point(xu, xv, api.constant(BigInteger.ONE), api.mul(xu, xv));
                    var xd = api.decompose(api.var("x"), 252);
                    out.set(new InCircuitJubjub.Point[]{
                            InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, xd),
                            InCircuitJubjub.scalarMulVariableBase(api, base, xd)});
                });
        Map<String, List<BigInteger>> pw = new HashMap<>();
        pw.put("xu", List.of(BigInteger.ONE));
        pw.put("xv", List.of(BigInteger.ONE));
        pw.put("x", List.of(x));
        BigInteger[] full = probe.calculateWitness(pw, CurveId.BLS12_381);
        BigInteger[] coords = new BigInteger[4];
        for (int i = 0; i < 2; i++) {
            InCircuitJubjub.Point p = out.get()[i];
            BigInteger zi = full[p.z().id()].modInverse(P);
            coords[2 * i] = full[p.u().id()].multiply(zi).mod(P);
            coords[2 * i + 1] = full[p.v().id()].multiply(zi).mod(P);
        }
        CircuitBuilder real = CircuitBuilder.create("dleq-real")
                .publicVar("xU").publicVar("xV").publicVar("pU").publicVar("pV").publicVar("dU").publicVar("dV").secretVar("x")
                .define(api -> InCircuitElGamal.assertDiscreteLogEquality(api, api.decompose(api.var("x"), 252),
                        api.var("xU"), api.var("xV"), api.var("pU"), api.var("pV"), api.var("dU"), api.var("dV")));
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("xU", List.of(BigInteger.ONE));
        w.put("xV", List.of(BigInteger.ONE));
        w.put("pU", List.of(coords[0]));
        w.put("pV", List.of(coords[1]));
        w.put("dU", List.of(coords[2]));
        w.put("dV", List.of(coords[3]));
        w.put("x", List.of(x));
        var e = assertThrows(ArithmeticException.class, () -> real.calculateWitness(w, CurveId.BLS12_381));
        assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(x).normalized().u().equals(coords[0]), "P itself is honest");
        // With an on-curve base the same construction is accepted: only the curve row rejected it.
        JubjubPoint onCurve = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(K).normalized();
        JubjubPoint d = onCurve.scalarMul(x).normalized();
        w.put("xU", List.of(onCurve.u()));
        w.put("xV", List.of(onCurve.v()));
        w.put("dU", List.of(d.u()));
        w.put("dV", List.of(d.v()));
        assertDoesNotThrow(() -> real.calculateWitness(w, CurveId.BLS12_381), e.getMessage());
    }

    @Test
    @DisplayName("Hiding guard rails: randomness confined below 252 bits via its range or a recomposition of its bits is refused")
    void hidingGuardRails() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("confined-range")
                .publicVar("pkU").publicVar("pkV").secretVar("m").secretVar("k")
                .define(api -> {
                    api.decompose(api.var("k"), 64); // proves k < 2^64
                    InCircuitElGamal.encrypt(api,
                            InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV")),
                            api.decompose(api.var("m"), 1), api.decompose(api.var("k"), 252));
                }), "k range-confined by its own decomposition");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("confined-bits")
                .publicVar("pkU").publicVar("pkV").secretVar("m").secretVar("k")
                .define(api -> {
                    var kd = api.decompose(api.var("k"), 252);
                    api.decompose(api.fromBinary(kd.bits()), 128); // confines the recomposed k to 128 bits
                    InCircuitElGamal.encrypt(api,
                            InCircuitElGamal.keyFromVerifierFixedPublic(api, api.var("pkU"), api.var("pkV")),
                            api.decompose(api.var("m"), 1), kd);
                }), "k confined through a recomposition of its bits");
    }
}
