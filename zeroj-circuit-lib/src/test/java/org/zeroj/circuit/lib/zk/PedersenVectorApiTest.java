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
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenSchemaRegistry;
import org.zeroj.circuit.lib.jubjub.PedersenVectorBases;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 D5 / milestone M3: the {@code pedersen-jubjub-vector-v1} profile — schema encoding and
 * digest, off-circuit and in-circuit commitments, schema binding into the public statement, and
 * the verifier registry. Cross-schema reuse through a real Groth16 verifier and the adversarial
 * relabelling test live in {@code zeroj-integration-tests}.
 */
class PedersenVectorApiTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final PedersenVectorSchema BALANCE = PedersenVectorSchema.of(
            "zeroj.example.balance", 1, List.of(new Entry("amount", 64), new Entry("asset", 32)));

    // ------------------------------------------------------------------
    //  Schema (spec §4)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Schema encodings and digests match spec §4.3")
    void schemaVectors() {
        assertEquals("706564657273656e2d6a75626a75622d766563746f722d763100157a65726f6a2e6578616d706c652e62616c616e63650001024006616d6f756e7420056173736574",
                HexFormat.of().formatHex(BALANCE.encode()));
        assertEquals(new BigInteger("26a0f201bd5af51641a74a2b9193d2a361dfa1b629e358f99ae97ff72fe2870d", 16), BALANCE.digest());
        assertEquals(new BigInteger("1acbc92525173b9be489f9eac5df349cccf41db6a9343d5d8bd2cdc695146857", 16),
                PedersenVectorSchema.of("zeroj.example.balance", 2, BALANCE.entries()).digest());
        assertEquals(new BigInteger("31ec633914dff2bcda6e69d694320b168a556d0de3377b5aa53aabfc5169e7a2", 16),
                PedersenVectorSchema.of("zeroj.example.balance", 1,
                        List.of(new Entry("asset", 64), new Entry("amount", 32))).digest());
        assertEquals(new BigInteger("1260c5c7d40c4b2ef61cc43a2b1210006546e6da4e4eff625000c785edd9c6d8", 16),
                PedersenVectorSchema.of("zeroj.example.balance", 1,
                        List.of(new Entry("amount", 64), new Entry("asset", 33))).digest());
        assertEquals(BALANCE, PedersenVectorSchema.decode(BALANCE.encode()));
    }

    @Test
    @DisplayName("Schema validation and strict decoding reject every malformed field")
    void schemaNegatives() {
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("Upper", 1, BALANCE.entries()));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of(".dot", 1, BALANCE.entries()));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("", 1, BALANCE.entries()));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("a".repeat(65), 1, BALANCE.entries()));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("ok", 0x10000, BALANCE.entries()));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("ok", 1, List.of()));
        List<Entry> seventeen = new ArrayList<>();
        for (int i = 0; i < 17; i++) seventeen.add(new Entry("e" + i, 8));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("ok", 1, seventeen));
        assertThrows(IllegalArgumentException.class, () -> new Entry("w", 0));
        assertThrows(IllegalArgumentException.class, () -> new Entry("w", 253));
        assertThrows(IllegalArgumentException.class, () -> new Entry("x".repeat(33), 8));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.of("ok", 1,
                List.of(new Entry("dup", 8), new Entry("dup", 8))));

        byte[] good = BALANCE.encode();
        byte[] trailing = Arrays.copyOf(good, good.length + 1);
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.decode(trailing));
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.decode(Arrays.copyOf(good, good.length - 1)));
        byte[] wrongTag = good.clone();
        wrongTag[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.decode(wrongTag));
    }

    // ------------------------------------------------------------------
    //  Off-circuit commitment (spec §3)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Commitment test vectors and zero-padding behaviour match spec §3.1")
    void commitmentVectors() {
        var c2 = PedersenVectorCommitment.commit(BALANCE, List.of(BigInteger.valueOf(1000), BigInteger.valueOf(7)),
                BigInteger.valueOf(12345));
        assertEquals(new BigInteger("4ce6f49eec1e5fc89b3d3fc3932c6f6823c240e21a19bb89b580304cb7ed1d36", 16), c2.point().affineU());
        assertEquals(new BigInteger("4306903aeb81cc5b6a5ac517fa9e48a7dbcab0b6920ef58cfb7ef85f569c48b8", 16), c2.point().affineV());
        assertEquals("b8489c565ff87efb8cf50e92b6b0cadba7489efa17c55a6a5bcc81eb3a900643", HexFormat.of().formatHex(c2.toBytes()));
        assertTrue(c2.verify(List.of(BigInteger.valueOf(1000), BigInteger.valueOf(7)), BigInteger.valueOf(12345)));

        var one = PedersenVectorSchema.of("zeroj.example.one", 1, List.of(new Entry("amount", 64)));
        var c1 = PedersenVectorCommitment.commit(one, List.of(BigInteger.valueOf(1000)), BigInteger.valueOf(12345));
        var c1padded = PedersenVectorCommitment.commit(BALANCE, List.of(BigInteger.valueOf(1000), BigInteger.ZERO),
                BigInteger.valueOf(12345));
        assertEquals("258119dd13e51c79d80b108918c6bc3d2117b83eb0a9068e4ce8b158d7a1ffe7", HexFormat.of().formatHex(c1.toBytes()));
        assertArrayEquals(c1.toBytes(), c1padded.toBytes(),
                "the point binds neither length nor schema — this is the documented zero-padding behaviour");
    }

    @Test
    @DisplayName("Typed off-circuit API: same-schema homomorphism, cross-schema refusal, range and decode checks")
    void offCircuitTypedApi() {
        BigInteger r = blinding(), s = blinding();
        var a = PedersenVectorCommitment.commit(BALANCE, List.of(BigInteger.valueOf(3), BigInteger.valueOf(4)), r);
        var b = PedersenVectorCommitment.commit(BALANCE, List.of(BigInteger.valueOf(10), BigInteger.valueOf(20)), s);
        assertTrue(a.add(b).verify(List.of(BigInteger.valueOf(13), BigInteger.valueOf(24)), r.add(s)));
        assertTrue(b.subtract(a).verify(List.of(BigInteger.valueOf(7), BigInteger.valueOf(16)), s.subtract(r)));

        var v2 = PedersenVectorSchema.of("zeroj.example.balance", 2, BALANCE.entries());
        var other = PedersenVectorCommitment.commit(v2, List.of(BigInteger.ONE, BigInteger.ONE), blinding());
        assertThrows(IllegalArgumentException.class, () -> a.add(other));

        assertThrows(IllegalArgumentException.class, () -> PedersenVectorCommitment.commit(BALANCE,
                List.of(BigInteger.ONE.shiftLeft(64), BigInteger.ONE), blinding()), "value above its width");
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorCommitment.commit(BALANCE,
                List.of(BigInteger.ONE), blinding()), "wrong dimension");
        assertThrows(IllegalArgumentException.class, () -> PedersenVectorCommitment.commit(BALANCE,
                List.of(BigInteger.valueOf(-1), BigInteger.ONE), blinding()), "negative value");
        assertFalse(a.verify(List.of(BigInteger.valueOf(4), BigInteger.valueOf(3)), r), "permuted indices");

        assertArrayEquals(a.toBytes(), PedersenVectorCommitment.decode(BALANCE, a.toBytes()).toBytes());
        JubjubPoint t8 = JubjubPoint.fromAffine(
                new BigInteger("71d4df38ba9e7973eaaae086a16618d17aa41ac43dae8582d92e6a7927200d43", 16),
                new BigInteger("4958bdb21966982e16a13035ad4d72669106ee90f384a4a1ff0d2068eff496dd", 16));
        assertThrows(IllegalArgumentException.class,
                () -> PedersenVectorCommitment.decode(BALANCE, a.point().add(t8).toBytes()));
    }

    // ------------------------------------------------------------------
    //  In-circuit (spec §5)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("In-circuit vector commitment matches off-circuit; wrong values, blinding, order or digest fail")
    void inCircuitMatchesOffCircuit() {
        var circuit = balanceCircuit(BALANCE);
        BigInteger amount = BigInteger.valueOf(1_234_567), asset = BigInteger.valueOf(42), r = blinding();
        var c = PedersenVectorCommitment.commit(BALANCE, List.of(amount, asset), r);

        Map<String, List<BigInteger>> ok = witness(BALANCE.digest(), c, amount, asset, r);
        assertDoesNotThrow(() -> circuit.calculateWitness(ok, CurveId.BLS12_381));

        assertWitnessRejected(circuit, ok, "amount", amount.add(BigInteger.ONE));
        assertWitnessRejected(circuit, ok, "r", r.add(BigInteger.ONE));
        assertWitnessRejected(circuit, ok, "schemaDigest", BALANCE.digest().add(BigInteger.ONE));
        Map<String, List<BigInteger>> permuted = witness(BALANCE.digest(), c, asset, amount, r);
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(permuted, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("All 16 bases: a full-dimension commitment matches off-circuit")
    void fullDimension() {
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < PedersenVectorBases.MAX_DIMENSION; i++) entries.add(new Entry("v" + i, 32));
        var schema = PedersenVectorSchema.of("zeroj.example.sixteen", 1, entries);
        List<BigInteger> values = new ArrayList<>();
        for (int i = 0; i < 16; i++) values.add(BigInteger.valueOf(1000L * i + 7));
        BigInteger r = blinding();
        var c = PedersenVectorCommitment.commit(schema, values, r);

        var builder = CircuitBuilder.create("sixteen").publicVar("schemaDigest").publicVar("u").publicVar("v");
        for (int i = 0; i < 16; i++) builder.secretVar("x" + i);
        builder.secretVar("r");
        var circuit = builder.defineSignals(cs -> {
            var zk = new ZkContext(cs);
            var binding = ZkPedersenVector.bindSchema(zk, schema, ZkField.publicInput(cs, "schemaDigest"));
            List<ZkUInt> xs = new ArrayList<>();
            for (int i = 0; i < 16; i++) xs.add(ZkUInt.secret(cs, "x" + i, 32));
            ZkPedersenVector.commit(zk, binding, xs, ZkUInt.secret(cs, "r", 252))
                    .assertAffineEquals(zk, ZkField.publicInput(cs, "u"), ZkField.publicInput(cs, "v"));
        });
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("schemaDigest", List.of(schema.digest()));
        w.put("u", List.of(c.point().affineU()));
        w.put("v", List.of(c.point().affineV()));
        for (int i = 0; i < 16; i++) w.put("x" + i, List.of(values.get(i)));
        w.put("r", List.of(r));
        assertDoesNotThrow(() -> circuit.calculateWitness(w, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Definition-time refusals: secret or constant digest, width mismatch, dimension, blinding, cross-binding")
    void definitionTimeRefusals() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("secret-digest")
                .secretVar("schemaDigest")
                .defineSignals(cs -> ZkPedersenVector.bindSchema(new ZkContext(cs), BALANCE,
                        ZkField.secret(cs, "schemaDigest"))), "digest must be a public input");
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("const-digest")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    ZkPedersenVector.bindSchema(zk, BALANCE, zk.constant(BALANCE.digest()));
                }), "a constant digest is not in the public statement");
        assertThrows(IllegalArgumentException.class, () -> defineCommit(BALANCE, 64, 33, 252, false), "width mismatch");
        assertThrows(IllegalArgumentException.class, () -> defineCommit(BALANCE, 63, 32, 252, false), "width mismatch");
        assertThrows(IllegalArgumentException.class, () -> defineCommit(BALANCE, 64, 32, 128, false), "narrow blinding");
        assertThrows(IllegalArgumentException.class, () -> defineCommit(BALANCE, 64, 32, 252, true), "public blinding");
        assertDoesNotThrow(() -> defineCommit(BALANCE, 64, 32, 252, false));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("cross-binding")
                .publicVar("d1").publicVar("d2").secretVar("a").secretVar("b").secretVar("c").secretVar("d")
                .secretVar("r").secretVar("s")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    var v2 = PedersenVectorSchema.of("zeroj.example.balance", 2, BALANCE.entries());
                    var b1 = ZkPedersenVector.bindSchema(zk, BALANCE, ZkField.publicInput(cs, "d1"));
                    var b2 = ZkPedersenVector.bindSchema(zk, v2, ZkField.publicInput(cs, "d2"));
                    var x = ZkPedersenVector.commit(zk, b1, List.of(ZkUInt.secret(cs, "a", 64), ZkUInt.secret(cs, "b", 32)),
                            ZkUInt.secret(cs, "r", 252));
                    var y = ZkPedersenVector.commit(zk, b2, List.of(ZkUInt.secret(cs, "c", 64), ZkUInt.secret(cs, "d", 32)),
                            ZkUInt.secret(cs, "s", 252));
                    x.add(zk, y);
                }), "homomorphism only within one schema binding");
    }

    @Test
    @DisplayName("Same-binding homomorphism holds in-circuit")
    void inCircuitHomomorphism() {
        BigInteger r = blinding(), s = blinding();
        var circuit = CircuitBuilder.create("vector-homomorphism")
                .publicVar("schemaDigest")
                .secretVar("a0").secretVar("a1").secretVar("b0").secretVar("b1").secretVar("c0").secretVar("c1")
                .secretVar("r").secretVar("s").secretVar("t")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    var binding = ZkPedersenVector.bindSchema(zk, BALANCE, ZkField.publicInput(cs, "schemaDigest"));
                    var a = ZkPedersenVector.commit(zk, binding, List.of(ZkUInt.secret(cs, "a0", 64), ZkUInt.secret(cs, "a1", 32)), ZkUInt.secret(cs, "r", 252));
                    var b = ZkPedersenVector.commit(zk, binding, List.of(ZkUInt.secret(cs, "b0", 64), ZkUInt.secret(cs, "b1", 32)), ZkUInt.secret(cs, "s", 252));
                    var c = ZkPedersenVector.commit(zk, binding, List.of(ZkUInt.secret(cs, "c0", 64), ZkUInt.secret(cs, "c1", 32)), ZkUInt.secret(cs, "t", 252));
                    a.add(zk, b).assertEqual(zk, c);
                });
        Map<String, List<BigInteger>> w = new HashMap<>(Map.of(
                "schemaDigest", List.of(BALANCE.digest()),
                "a0", List.of(BigInteger.valueOf(3)), "a1", List.of(BigInteger.valueOf(4)),
                "b0", List.of(BigInteger.valueOf(10)), "b1", List.of(BigInteger.valueOf(20)),
                "c0", List.of(BigInteger.valueOf(13)), "c1", List.of(BigInteger.valueOf(24)),
                "r", List.of(r), "s", List.of(s), "t", List.of(r.add(s).mod(L))));
        assertDoesNotThrow(() -> circuit.calculateWitness(w, CurveId.BLS12_381));
        w.put("c1", List.of(BigInteger.valueOf(25)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Registry (spec §5)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Registry accepts only the registered digest for a registered key")
    void registry() {
        var v2 = PedersenVectorSchema.of("zeroj.example.balance", 2, BALANCE.entries());
        byte[] keyA = {1, 2, 3};
        byte[] keyB = {4, 5, 6};
        var registry = PedersenSchemaRegistry.builder().accept(keyA, BALANCE).accept(keyB, v2).build();
        assertDoesNotThrow(() -> registry.requireStatement(keyA, BALANCE.digest()));
        assertThrows(IllegalArgumentException.class, () -> registry.requireStatement(keyA, v2.digest()));
        assertThrows(IllegalArgumentException.class, () -> registry.requireStatement(new byte[]{9}, BALANCE.digest()));
        assertThrows(IllegalArgumentException.class,
                () -> PedersenSchemaRegistry.builder().accept(keyA, BALANCE).accept(keyA, v2));
        assertNotEquals(BALANCE.digest(), v2.digest());
    }

    // ------------------------------------------------------------------
    //  Cost pins (ADR-0051 performance gates)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Vector commitment cost pins at dimensions 1, 4 and 16 (64-bit values)")
    void costPins() {
        R1CSConstraintSystem n1 = dimensionCircuit(1).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem n4 = dimensionCircuit(4).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem n16 = dimensionCircuit(16).compileR1CS(CurveId.BLS12_381);
        // Complete operation: schema-digest binding, decompositions, canonical blinding, the
        // multi-scalar sum and the affine public binding. About 390 rows per extra 64-bit value.
        // n = 1 is cheaper than the v1 64/252 commitment (2,918) because a value narrower than
        // 252 bits is canonical by its width and needs no comparator.
        assertAll(
                () -> assertEquals(2_411, n1.constraints().size(), "n=1 rows"),
                () -> assertEquals(11_686, nnz(n1), "n=1 nonzeros"),
                () -> assertEquals(3_581, n4.constraints().size(), "n=4 rows"),
                () -> assertEquals(17_755, nnz(n4), "n=4 nonzeros"),
                () -> assertEquals(8_261, n16.constraints().size(), "n=16 rows"),
                () -> assertEquals(42_031, nnz(n16), "n=16 nonzeros"));
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    static CircuitBuilder balanceCircuit(PedersenVectorSchema schema) {
        return CircuitBuilder.create("vector-balance-" + schema.id())
                .publicVar("schemaDigest").publicVar("u").publicVar("v")
                .secretVar("amount").secretVar("asset").secretVar("r")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    var binding = ZkPedersenVector.bindSchema(zk, schema, ZkField.publicInput(cs, "schemaDigest"));
                    ZkPedersenVector.commit(zk, binding,
                                    List.of(ZkUInt.secret(cs, "amount", schema.width(0)),
                                            ZkUInt.secret(cs, "asset", schema.width(1))),
                                    ZkUInt.secret(cs, "r", 252))
                            .assertAffineEquals(zk, ZkField.publicInput(cs, "u"), ZkField.publicInput(cs, "v"));
                });
    }

    static Map<String, List<BigInteger>> witness(BigInteger digest, PedersenVectorCommitment c,
                                                 BigInteger amount, BigInteger asset, BigInteger r) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("schemaDigest", List.of(digest));
        w.put("u", List.of(c.point().affineU()));
        w.put("v", List.of(c.point().affineV()));
        w.put("amount", List.of(amount));
        w.put("asset", List.of(asset));
        w.put("r", List.of(r));
        return w;
    }

    private static CircuitBuilder dimensionCircuit(int n) {
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < n; i++) entries.add(new Entry("v" + i, 64));
        var schema = PedersenVectorSchema.of("zeroj.bench.n" + n, 1, entries);
        var builder = CircuitBuilder.create("dimension-" + n).publicVar("schemaDigest").publicVar("u").publicVar("v");
        for (int i = 0; i < n; i++) builder.secretVar("x" + i);
        builder.secretVar("r");
        return builder.defineSignals(cs -> {
            var zk = new ZkContext(cs);
            var binding = ZkPedersenVector.bindSchema(zk, schema, ZkField.publicInput(cs, "schemaDigest"));
            List<ZkUInt> xs = new ArrayList<>();
            for (int i = 0; i < n; i++) xs.add(ZkUInt.secret(cs, "x" + i, 64));
            ZkPedersenVector.commit(zk, binding, xs, ZkUInt.secret(cs, "r", 252))
                    .assertAffineEquals(zk, ZkField.publicInput(cs, "u"), ZkField.publicInput(cs, "v"));
        });
    }

    private static void defineCommit(PedersenVectorSchema schema, int amountBits, int assetBits,
                                     int blindingBits, boolean publicBlinding) {
        var builder = CircuitBuilder.create("define").publicVar("schemaDigest").secretVar("amount").secretVar("asset");
        if (publicBlinding) builder.publicVar("r"); else builder.secretVar("r");
        builder.defineSignals(cs -> {
            var zk = new ZkContext(cs);
            var binding = ZkPedersenVector.bindSchema(zk, schema, ZkField.publicInput(cs, "schemaDigest"));
            ZkUInt r = publicBlinding ? ZkUInt.publicInput(cs, "r", blindingBits) : ZkUInt.secret(cs, "r", blindingBits);
            ZkPedersenVector.commit(zk, binding,
                    List.of(ZkUInt.secret(cs, "amount", amountBits), ZkUInt.secret(cs, "asset", assetBits)), r);
        });
    }

    private static void assertWitnessRejected(CircuitBuilder circuit, Map<String, List<BigInteger>> ok,
                                              String key, BigInteger value) {
        Map<String, List<BigInteger>> w = new HashMap<>(ok);
        w.put(key, List.of(value));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381), key);
    }

    private static BigInteger blinding() {
        return PedersenCommitment.randomBlinding(RANDOM);
    }

    private static long nnz(R1CSConstraintSystem system) {
        return system.constraints().stream()
                .mapToLong(c -> (long) c.a().size() + c.b().size() + c.c().size())
                .sum();
    }
}
