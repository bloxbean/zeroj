package org.zeroj.circuit.lib.zk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0052 M2: the {@code elgamal-jubjub-v1} relations (spec §9) through the typed adapter.
 * Covers every M2 negative in the ADR: mismatched scalars, a message above its width, a width
 * above 64 refused at definition, an identity or off-curve key, a wrong share or base, and
 * public or narrow randomness. Also covers the I8/I9 provenance rules and the constraint pins.
 */
class ZkElGamalTest {

    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final JubjubPoint T8 = JubjubPoint.FULL_GENERATOR.scalarMul(L);
    private static final JubjubPoint ORDER_2 = JubjubPoint.fromAffine(BigInteger.ZERO, P.subtract(BigInteger.ONE));

    // ------------------------------------------------------------------ circuits

    private static CircuitBuilder encryptionCircuit(int width, boolean keyPublic, boolean randomnessPublic) {
        CircuitBuilder b = CircuitBuilder.create("elgamal-enc-w" + width);
        b = keyPublic ? b.publicVar("pkU").publicVar("pkV") : b.secretVar("pkU").secretVar("pkV");
        b = b.publicVar("aU").publicVar("aV").publicVar("bU").publicVar("bV").secretVar("m");
        b = randomnessPublic ? b.publicVar("k") : b.secretVar("k");
        return b.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkField pkU = keyPublic ? ZkField.publicInput(c, "pkU") : ZkField.secret(c, "pkU");
            ZkField pkV = keyPublic ? ZkField.publicInput(c, "pkV") : ZkField.secret(c, "pkV");
            var key = keyPublic
                    ? ZkElGamalPublicKey.fromVerifierFixedPublic(zk, pkU, pkV)
                    : ZkElGamalPublicKey.witnessInSubgroup(zk, pkU, pkV);
            ZkUInt m = ZkUInt.secret(c, "m", width);
            ZkUInt k = randomnessPublic ? ZkUInt.publicInput(c, "k", 252) : ZkUInt.secret(c, "k", 252);
            ZkElGamal.encrypt(zk, m, k, key).assertAffineEquals(zk,
                    ZkField.publicInput(c, "aU"), ZkField.publicInput(c, "aV"),
                    ZkField.publicInput(c, "bU"), ZkField.publicInput(c, "bV"));
        });
    }

    private static CircuitBuilder dleqCircuit() {
        return CircuitBuilder.create("elgamal-dleq")
                .publicVar("xU").publicVar("xV").publicVar("pU").publicVar("pV")
                .publicVar("dU").publicVar("dV").secretVar("x")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkElGamal.assertDiscreteLogEquality(zk, ZkUInt.secret(c, "x", 252),
                            ZkField.publicInput(c, "xU"), ZkField.publicInput(c, "xV"),
                            ZkField.publicInput(c, "pU"), ZkField.publicInput(c, "pV"),
                            ZkField.publicInput(c, "dU"), ZkField.publicInput(c, "dV"));
                });
    }

    // ------------------------------------------------------------------ witnesses

    private static void put(Map<String, List<BigInteger>> w, String prefix, JubjubPoint p) {
        JubjubPoint n = p.normalized();
        w.put(prefix + "U", List.of(n.u()));
        w.put(prefix + "V", List.of(n.v()));
    }

    private static Map<String, List<BigInteger>> encWitness(JubjubPoint pk, BigInteger m, BigInteger k,
                                                            JubjubPoint a, JubjubPoint b) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        put(w, "pk", pk);
        put(w, "a", a);
        put(w, "b", b);
        w.put("m", List.of(m));
        w.put("k", List.of(k));
        return w;
    }

    private static Map<String, List<BigInteger>> honestEnc(JubjubPoint pk, BigInteger m, BigInteger k) {
        return encWitness(pk, m, k, G.scalarMul(k), G.scalarMul(m).add(pk.scalarMul(k)));
    }

    private static Map<String, List<BigInteger>> dleqWitness(JubjubPoint base, BigInteger x,
                                                             JubjubPoint key, JubjubPoint share) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        put(w, "x", base);
        put(w, "p", key);
        put(w, "d", share);
        w.put("x", List.of(x));
        return w;
    }

    private static final BigInteger SK = new BigInteger("0281799c40fb5bca4f8cc6af4812fae96cdf7113e1ab203ea4d73fb7027e8343", 16);
    private static final JubjubPoint PK = G.scalarMul(SK);
    private static final BigInteger K = new BigInteger("0e6e9d50fbbb41bd6191632fcbf588bd6843f389aa856195f9a69d8cff98a304", 16);

    // ------------------------------------------------------------------ encryption

    @Test
    @DisplayName("Honest encryptions have a witness at widths 1, 16 and 64, including m = 0 and m = 2^w − 1")
    void honestEncryption() {
        for (int w : new int[]{1, 16, 64}) {
            CircuitBuilder circuit = encryptionCircuit(w, true, false);
            for (BigInteger m : List.of(BigInteger.ZERO, BigInteger.ONE,
                    BigInteger.ONE.shiftLeft(w).subtract(BigInteger.ONE))) {
                assertDoesNotThrow(() -> circuit.calculateWitness(honestEnc(PK, m, K), CurveId.BLS12_381),
                        "w=" + w + " m=" + m);
            }
        }
        // k ≥ l (still below 2^252) gives the same points as k mod l, because both bases lie in
        // the subgroup: harmless. A k that does not fit 252 bits has no witness at all.
        CircuitBuilder circuit = encryptionCircuit(1, true, false);
        BigInteger small = BigInteger.valueOf(5);
        assertDoesNotThrow(() -> circuit.calculateWitness(encWitness(PK, BigInteger.ONE, small.add(L),
                G.scalarMul(small), G.add(PK.scalarMul(small))), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(encWitness(PK, BigInteger.ONE, K.add(L),
                G.scalarMul(K), G.add(PK.scalarMul(K))), CurveId.BLS12_381), "k + l ≥ 2^252");
    }

    @Test
    @DisplayName("Mismatched scalars, a wrong key and a wrong message have no witness")
    void mismatchedScalars() {
        CircuitBuilder circuit = encryptionCircuit(16, true, false);
        BigInteger m = BigInteger.valueOf(12345);
        BigInteger k2 = K.add(BigInteger.ONE);
        // A from k, B from k + 1.
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                encWitness(PK, m, K, G.scalarMul(K), G.scalarMul(m).add(PK.scalarMul(k2))), CurveId.BLS12_381));
        // B under another key.
        JubjubPoint other = G.scalarMul(BigInteger.valueOf(7));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                encWitness(PK, m, K, G.scalarMul(K), G.scalarMul(m).add(other.scalarMul(K))), CurveId.BLS12_381));
        // Witness message differs from the encrypted one.
        Map<String, List<BigInteger>> w = honestEnc(PK, m, K);
        w.put("m", List.of(m.add(BigInteger.ONE)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("A message above its width has no witness, even when the points match it")
    void messageAboveWidth() {
        CircuitBuilder circuit = encryptionCircuit(1, true, false);
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                honestEnc(PK, BigInteger.TWO, K), CurveId.BLS12_381));
        CircuitBuilder wide = encryptionCircuit(64, true, false);
        assertThrows(ArithmeticException.class, () -> wide.calculateWitness(
                honestEnc(PK, BigInteger.ONE.shiftLeft(64), K), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("A message width above 64 is refused at definition (at 252, m = l would alias m = 0)")
    void widthAbove64Refused() {
        assertThrows(IllegalArgumentException.class, () -> encryptionCircuit(65, true, false));
        assertThrows(IllegalArgumentException.class, () -> encryptionCircuit(252, true, false));
    }

    @Test
    @DisplayName("Public or narrow randomness is refused at definition")
    void randomnessGuardRails() {
        assertThrows(IllegalArgumentException.class, () -> encryptionCircuit(1, true, true), "public k");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("narrow-k")
                .publicVar("pkU").publicVar("pkV").secretVar("m").secretVar("k")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk,
                            ZkField.publicInput(c, "pkU"), ZkField.publicInput(c, "pkV"));
                    ZkElGamal.encrypt(zk, ZkUInt.secret(c, "m", 1), ZkUInt.secret(c, "k", 128), key);
                }), "128-bit k");
    }

    @Test
    @DisplayName("I8: identity, off-curve and order-2 keys have no witness; secret coordinates cannot be 'verifier-fixed'")
    void keyProvenance() {
        CircuitBuilder fixed = encryptionCircuit(1, true, false);
        assertThrows(ArithmeticException.class, () -> fixed.calculateWitness(
                honestEnc(JubjubPoint.IDENTITY, BigInteger.ONE, K), CurveId.BLS12_381), "identity key");
        assertThrows(ArithmeticException.class, () -> fixed.calculateWitness(
                honestEnc(ORDER_2, BigInteger.ONE, K), CurveId.BLS12_381), "order-2 key");
        Map<String, List<BigInteger>> offCurve = honestEnc(PK, BigInteger.ONE, K);
        offCurve.put("pkU", List.of(BigInteger.ONE));
        offCurve.put("pkV", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> fixed.calculateWitness(offCurve, CurveId.BLS12_381), "off-curve key");

        CircuitBuilder witnessed = encryptionCircuit(1, false, false);
        assertDoesNotThrow(() -> witnessed.calculateWitness(honestEnc(PK, BigInteger.ONE, K), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> witnessed.calculateWitness(
                honestEnc(JubjubPoint.IDENTITY, BigInteger.ONE, K), CurveId.BLS12_381), "identity key");
        assertThrows(ArithmeticException.class, () -> witnessed.calculateWitness(
                honestEnc(PK.add(T8), BigInteger.ONE, K), CurveId.BLS12_381), "torsion-shifted key");
        // With verifier-fixed public coordinates the subgroup check is the verifier's job: the
        // circuit alone accepts a torsion-shifted key (documented obligation, spec §9.3).
        assertDoesNotThrow(() -> fixed.calculateWitness(honestEnc(PK.add(T8), BigInteger.ONE, K), CurveId.BLS12_381));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("secret-key-coords")
                .secretVar("pkU").secretVar("pkV")
                .defineSignals(c -> ZkElGamalPublicKey.fromVerifierFixedPublic(new ZkContext(c),
                        ZkField.secret(c, "pkU"), ZkField.secret(c, "pkV"))));
    }

    @Test
    @DisplayName("A ZkElGamalPublicKey from another circuit is refused")
    void foreignTypedKeyRefused() {
        var captured = new AtomicReference<ZkElGamalPublicKey>();
        CircuitBuilder.create("key-source").publicVar("pkU").publicVar("pkV").defineSignals(c -> {
            var zk = new ZkContext(c);
            captured.set(ZkElGamalPublicKey.fromVerifierFixedPublic(zk, ZkField.publicInput(c, "pkU"), ZkField.publicInput(c, "pkV")));
        });
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("key-sink")
                .secretVar("m").secretVar("k").defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkElGamal.encrypt(zk, ZkUInt.secret(c, "m", 1), ZkUInt.secret(c, "k", 252), captured.get());
                }));
    }

    // ------------------------------------------------------------------ DLEQ

    @Test
    @DisplayName("DLEQ: possession and share statements have witnesses; a wrong share, base or secret has none")
    void dleq() {
        CircuitBuilder circuit = dleqCircuit();
        BigInteger x = SK;
        assertDoesNotThrow(() -> circuit.calculateWitness(dleqWitness(G, x, PK, PK), CurveId.BLS12_381), "possession");
        JubjubPoint a = G.scalarMul(K);
        JubjubPoint d = a.scalarMul(x);
        assertDoesNotThrow(() -> circuit.calculateWitness(dleqWitness(a, x, PK, d), CurveId.BLS12_381), "share");
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                dleqWitness(a, x, PK, d.add(G)), CurveId.BLS12_381), "wrong share");
        JubjubPoint otherBase = G.scalarMul(K.add(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                dleqWitness(otherBase, x, PK, d), CurveId.BLS12_381), "wrong base");
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                dleqWitness(a, x.add(BigInteger.ONE), PK, d), CurveId.BLS12_381), "secret of another key");
        Map<String, List<BigInteger>> offCurve = dleqWitness(a, x, PK, d);
        offCurve.put("xU", List.of(BigInteger.ONE));
        offCurve.put("xV", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(offCurve, CurveId.BLS12_381), "off-curve base");
    }

    @Test
    @DisplayName("DLEQ identity values: x = 0 gives P = D = O, which is a valid statement (threshold shares)")
    void dleqIdentity() {
        CircuitBuilder circuit = dleqCircuit();
        JubjubPoint a = G.scalarMul(K);
        assertDoesNotThrow(() -> circuit.calculateWitness(
                dleqWitness(a, BigInteger.ZERO, JubjubPoint.IDENTITY, JubjubPoint.IDENTITY), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.calculateWitness(
                dleqWitness(JubjubPoint.IDENTITY, SK, PK, JubjubPoint.IDENTITY), CurveId.BLS12_381),
                "an identity handle A = O is a valid base");
    }

    @Test
    @DisplayName("I9: every DLEQ coordinate must be a declared public input; narrow x is refused")
    void dleqProvenance() {
        String[] names = {"xU", "xV", "pU", "pV", "dU", "dV"};
        for (String secretName : names) {
            assertThrows(IllegalArgumentException.class, () -> {
                CircuitBuilder b = CircuitBuilder.create("dleq-secret-" + secretName);
                for (String n : names) b = n.equals(secretName) ? b.secretVar(n) : b.publicVar(n);
                b.secretVar("x").defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkField[] f = new ZkField[6];
                    for (int i = 0; i < 6; i++) {
                        f[i] = names[i].equals(secretName) ? ZkField.secret(c, names[i]) : ZkField.publicInput(c, names[i]);
                    }
                    ZkElGamal.assertDiscreteLogEquality(zk, ZkUInt.secret(c, "x", 252), f[0], f[1], f[2], f[3], f[4], f[5]);
                });
            }, "secret " + secretName);
        }
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("dleq-derived-base")
                .publicVar("xU").publicVar("xV").publicVar("pU").publicVar("pV").publicVar("dU").publicVar("dV").secretVar("x")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var xU = ZkField.publicInput(c, "xU");
                    ZkField derived = ZkField.wrap(zk, c.wrap(c.api().add(xU.signal().variable(), c.api().constant(BigInteger.ZERO))));
                    ZkElGamal.assertDiscreteLogEquality(zk, ZkUInt.secret(c, "x", 252), derived,
                            ZkField.publicInput(c, "xV"), ZkField.publicInput(c, "pU"), ZkField.publicInput(c, "pV"),
                            ZkField.publicInput(c, "dU"), ZkField.publicInput(c, "dV"));
                }), "derived base coordinate");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("dleq-narrow")
                .publicVar("xU").publicVar("xV").publicVar("pU").publicVar("pV").publicVar("dU").publicVar("dV").secretVar("x")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkElGamal.assertDiscreteLogEquality(zk, ZkUInt.secret(c, "x", 200),
                            ZkField.publicInput(c, "xU"), ZkField.publicInput(c, "xV"),
                            ZkField.publicInput(c, "pU"), ZkField.publicInput(c, "pV"),
                            ZkField.publicInput(c, "dU"), ZkField.publicInput(c, "dV"));
                }), "200-bit x");
    }

    // ------------------------------------------------------------------ host vs circuit

    @Test
    @DisplayName("Differential: random (m, k) encrypted by the host formula verify in-circuit at width 32")
    void differential() {
        CircuitBuilder circuit = encryptionCircuit(32, true, false);
        Random rnd = new Random(60);
        for (int i = 0; i < 4; i++) {
            BigInteger m = new BigInteger(32, rnd);
            BigInteger k = new BigInteger(252, rnd).mod(L);
            JubjubPoint pk = G.scalarMul(new BigInteger(250, rnd).add(BigInteger.ONE));
            assertDoesNotThrow(() -> circuit.calculateWitness(honestEnc(pk, m, k), CurveId.BLS12_381));
        }
    }

    // ------------------------------------------------------------------ cost

    private static long nnz(R1CSConstraintSystem cs) {
        long n = 0;
        for (var row : cs.constraints()) n += row.a().size() + row.b().size() + row.c().size();
        return n;
    }

    @Test
    @DisplayName("Constraint pins: encryption at widths 1/16/64 (verifier-fixed key), witnessed key, DLEQ")
    void constraintPins() {
        R1CSConstraintSystem w1 = encryptionCircuit(1, true, false).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem w16 = encryptionCircuit(16, true, false).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem w64 = encryptionCircuit(64, true, false).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem witnessed = encryptionCircuit(1, false, false).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem dleq = dleqCircuit().compileR1CS(CurveId.BLS12_381);
        System.out.printf("elgamal rows/nnz: w1 %d/%d, w16 %d/%d, w64 %d/%d, witnessed-key %d/%d, dleq %d/%d%n",
                w1.constraints().size(), nnz(w1), w16.constraints().size(), nnz(w16),
                w64.constraints().size(), nnz(w64), witnessed.constraints().size(), nnz(witnessed),
                dleq.constraints().size(), nnz(dleq));
        assertAll(
                () -> assertEquals(PIN_W1, w1.constraints().size(), "w1 rows"),
                () -> assertEquals(PIN_W16, w16.constraints().size(), "w16 rows"),
                () -> assertEquals(PIN_W64, w64.constraints().size(), "w64 rows"),
                () -> assertEquals(PIN_WITNESSED, witnessed.constraints().size(), "witnessed-key rows"),
                () -> assertEquals(PIN_DLEQ, dleq.constraints().size(), "dleq rows"));
    }

    // Measured 2026-10-05. The width-1 path selects [m]·G; wider messages use the windowed
    // fixed-base multiplication over the message's own decomposition. DLEQ equals the usecase
    // prototype's trustee-dleq circuit (6,546), the same relation.
    private static final int PIN_W1 = 6_558;
    private static final int PIN_W16 = 6_650;
    private static final int PIN_W64 = 6_938;
    private static final int PIN_WITNESSED = 12_105;
    private static final int PIN_DLEQ = 6_546;
}
