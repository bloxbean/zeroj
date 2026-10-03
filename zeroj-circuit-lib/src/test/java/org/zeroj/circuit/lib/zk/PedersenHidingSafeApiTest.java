package org.zeroj.circuit.lib.zk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.annotation.ZkBits;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitPedersen;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 D2 / milestone M1: the hiding-safe Pedersen API.
 *
 * <p>Every public entry point must refuse a blinding that cannot hide — narrower than 252 bits,
 * or wired directly to a public input or a constant — at circuit-definition time, before any
 * constraint is emitted. The complete user-facing cost is pinned alongside.
 */
class PedersenHidingSafeApiTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final int FULL = ZkPedersen.BLINDING_BITS;

    // ------------------------------------------------------------------
    //  ZkPedersen: width rule
    // ------------------------------------------------------------------

    @Test
    @DisplayName("ZkPedersen.commit rejects every blinding width other than 252")
    void zkCommit_rejectsNonFullWidthBlinding() {
        for (int width : new int[]{1, 16, 64, 128, 251, 253}) {
            assertThrows(IllegalArgumentException.class,
                    () -> defineZkCommit(width, false, false),
                    "blinding width " + width + " must be rejected");
        }
        assertDoesNotThrow(() -> defineZkCommit(FULL, false, false));
    }

    @Test
    @DisplayName("ZkPedersen.verifyOpening applies the same width rule")
    void zkVerifyOpening_rejectsNarrowBlinding() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("open-narrow")
                .publicVar("u").publicVar("v").secretVar("value").secretVar("blinding")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var commitment = ZkJubjubPoint.witnessAffine(
                            zk, ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"));
                    ZkPedersen.verifyOpening(zk, commitment,
                            ZkUInt.secret(c, "value", 16), ZkUInt.secret(c, "blinding", 64));
                }));
    }

    @Test
    @DisplayName("ZkPedersen.commitBits rejects a blinding vector that is not 252 bits")
    void zkCommitBits_rejectsNarrowBlinding() {
        assertThrows(IllegalArgumentException.class, () -> {
            var builder = CircuitBuilder.create("bits-narrow");
            for (int i = 0; i < 4; i++) builder.secretVar("vb_" + i);
            for (int i = 0; i < 251; i++) builder.secretVar("rb_" + i);
            builder.defineSignals(c -> ZkPedersen.commitBits(new ZkContext(c),
                    ZkBits.secret(c, "vb", 4), ZkBits.secret(c, "rb", 251)));
        });
    }

    // ------------------------------------------------------------------
    //  ZkPedersen: provenance rule
    // ------------------------------------------------------------------

    @Test
    @DisplayName("ZkPedersen.commit rejects a blinding that is a public input")
    void zkCommit_rejectsPublicBlinding() {
        assertThrows(IllegalArgumentException.class, () -> defineZkCommit(FULL, true, false));
    }

    @Test
    @DisplayName("ZkPedersen.commit rejects a blinding that is a circuit constant")
    void zkCommit_rejectsConstantBlinding() {
        assertThrows(IllegalArgumentException.class, () -> defineZkCommit(FULL, false, true));
    }

    @Test
    @DisplayName("ZkPedersen.commitBits rejects public blinding bits")
    void zkCommitBits_rejectsPublicBlindingBits() {
        assertThrows(IllegalArgumentException.class, () -> {
            var builder = CircuitBuilder.create("bits-public");
            for (int i = 0; i < 4; i++) builder.secretVar("vb_" + i);
            for (int i = 0; i < FULL; i++) builder.publicVar("rb_" + i);
            builder.defineSignals(c -> ZkPedersen.commitBits(new ZkContext(c),
                    ZkBits.secret(c, "vb", 4), ZkBits.publicInput(c, "rb", FULL)));
        });
    }

    // ------------------------------------------------------------------
    //  InCircuitPedersen (low level): same rules, every overload
    // ------------------------------------------------------------------

    @Test
    @DisplayName("InCircuitPedersen raw-bit overload rejects a narrow blinding")
    void lowLevelRawBits_rejectsNarrowBlinding() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("raw-narrow")
                .secretVar("v").secretVar("r")
                .define(api -> {
                    Variable[] valueBits = api.toBinary(api.var("v"), 16);
                    Variable[] blindBits = api.toBinary(api.var("r"), 64);
                    InCircuitPedersen.commit(api, valueBits, blindBits);
                }));
    }

    @Test
    @DisplayName("InCircuitPedersen raw-bit overload rejects a constant blinding bit")
    void lowLevelRawBits_rejectsConstantBlindingBit() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("raw-const")
                .secretVar("v").secretVar("r")
                .define(api -> {
                    Variable[] valueBits = api.toBinary(api.var("v"), 16);
                    Variable[] blindBits = api.toBinary(api.var("r"), FULL);
                    blindBits[200] = api.constant(0);
                    InCircuitPedersen.commit(api, valueBits, blindBits);
                }));
    }

    @Test
    @DisplayName("InCircuitPedersen decomposition overload rejects narrow and public blindings")
    void lowLevelDecomposition_rejectsNarrowAndPublicBlinding() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("dec-narrow")
                .secretVar("v").secretVar("r")
                .define(api -> InCircuitPedersen.commit(api,
                        api.decompose(api.var("v"), 16), api.decompose(api.var("r"), 251))));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("dec-public")
                .publicVar("r").secretVar("v")
                .define(api -> InCircuitPedersen.commit(api,
                        api.decompose(api.var("v"), 16), api.decompose(api.var("r"), FULL))));
    }

    @Test
    @DisplayName("InCircuitPedersen scalar overload rejects public and constant blindings")
    void lowLevelScalar_rejectsPublicAndConstantBlinding() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("scalar-public")
                .publicVar("r").secretVar("v")
                .define(api -> InCircuitPedersen.commit(api, api.var("v"), 16, api.var("r"))));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("scalar-const")
                .secretVar("v")
                .define(api -> InCircuitPedersen.commit(
                        api, api.var("v"), 16, api.constant(BigInteger.valueOf(12345)))));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("scalar-width")
                .secretVar("v").secretVar("r")
                .define(api -> InCircuitPedersen.commit(api, api.var("v"), 0, api.var("r"))));
    }

    // ------------------------------------------------------------------
    //  Witness boundaries at full width
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Blinding l − 1 is accepted; l and 2^252 − 1 are rejected as non-canonical")
    void blindingBoundaryWitnesses() {
        var circuit = zkCommitCircuit(64);
        BigInteger value = BigInteger.valueOf(1_000_000);

        BigInteger lMinusOne = L.subtract(BigInteger.ONE);
        JubjubPoint c = PedersenCommitment.commit(value, lMinusOne);
        assertDoesNotThrow(() -> circuit.calculateWitness(
                witness(value, lMinusOne, c), CurveId.BLS12_381));

        // l and 2^252 − 1 fit the 252-bit decomposition but are not canonical. The point they
        // produce is the one for their residue, so the circuit must reject on canonicality,
        // not on a mismatching commitment.
        for (BigInteger nonCanonical : List.of(L, BigInteger.ONE.shiftLeft(252).subtract(BigInteger.ONE))) {
            JubjubPoint residue = PedersenCommitment.commit(value, nonCanonical);
            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                    witness(value, nonCanonical, residue), CurveId.BLS12_381),
                    "non-canonical blinding " + nonCanonical.toString(16) + " must be rejected");
        }
    }

    @Test
    @DisplayName("A random full-width blinding round-trips through the circuit")
    void randomBlindingRoundTrips() {
        var circuit = zkCommitCircuit(64);
        BigInteger value = BigInteger.valueOf(42);
        BigInteger blinding = PedersenCommitment.randomBlinding(new SecureRandom());
        JubjubPoint c = PedersenCommitment.commit(value, blinding);
        assertDoesNotThrow(() -> circuit.calculateWitness(
                witness(value, blinding, c), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Why the rule exists
    // ------------------------------------------------------------------

    /**
     * A 16-bit blinding with an 8-bit value is opened from the public commitment alone, in
     * seconds, by tabulating {@code [r]·H} for every 16-bit {@code r} and subtracting each
     * candidate {@code [v]·G}. This is the attack D2 removes from the reachable API.
     */
    @Test
    @DisplayName("A 16-bit blinding is recovered by brute force from the public commitment")
    void narrowBlinding_isRecoveredByBruteForce() {
        BigInteger secretValue = BigInteger.valueOf(173);
        BigInteger secretBlinding = BigInteger.valueOf(51_234);
        JubjubPoint published = PedersenCommitment.commit(secretValue, secretBlinding);

        Map<BigInteger, Integer> blindingTable = new HashMap<>();
        JubjubPoint running = JubjubPoint.IDENTITY;
        for (int r = 0; r < (1 << 16); r++) {
            blindingTable.put(running.normalized().affineU(), r);
            running = running.add(PedersenCommitment.H);
        }

        BigInteger recoveredValue = null;
        Integer recoveredBlinding = null;
        JubjubPoint negG = JubjubPoint.SUBGROUP_GENERATOR.negate();
        JubjubPoint candidate = published;   // published − [v]·G, starting at v = 0
        for (int v = 0; v < (1 << 8) && recoveredValue == null; v++) {
            Integer r = blindingTable.get(candidate.normalized().affineU());
            if (r != null && PedersenCommitment.verify(published, BigInteger.valueOf(v), BigInteger.valueOf(r))) {
                recoveredValue = BigInteger.valueOf(v);
                recoveredBlinding = r;
            }
            candidate = candidate.add(negG);
        }

        assertEquals(secretValue, recoveredValue);
        assertEquals(secretBlinding.intValueExact(), recoveredBlinding);
    }

    // ------------------------------------------------------------------
    //  randomBlinding
    // ------------------------------------------------------------------

    @Test
    @DisplayName("randomBlinding reduces exactly 64 big-endian bytes mod l")
    void randomBlinding_reducesSixtyFourBigEndianBytes() {
        var requested = new AtomicInteger();
        byte[] pattern = new byte[64];
        for (int i = 0; i < 64; i++) pattern[i] = (byte) (0xFF - i);
        SecureRandom fixed = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                requested.addAndGet(bytes.length);
                System.arraycopy(pattern, 0, bytes, 0, bytes.length);
            }
        };

        BigInteger blinding = PedersenCommitment.randomBlinding(fixed);

        assertEquals(64, requested.get(), "exactly one 64-byte draw");
        assertEquals(new BigInteger(1, pattern).mod(L), blinding);
        assertTrue(blinding.signum() >= 0 && blinding.compareTo(L) < 0);
    }

    @Test
    @DisplayName("randomBlinding stays in [0, l) and does not repeat")
    void randomBlinding_rangeAndFreshness() {
        var random = new SecureRandom();
        BigInteger first = PedersenCommitment.randomBlinding(random);
        for (int i = 0; i < 64; i++) {
            BigInteger next = PedersenCommitment.randomBlinding(random);
            assertTrue(next.signum() >= 0 && next.compareTo(L) < 0);
            assertNotEquals(first, next);
        }
        assertThrows(NullPointerException.class, () -> PedersenCommitment.randomBlinding(null));
    }

    // ------------------------------------------------------------------
    //  Complete safe-API cost pins (ADR-0051 performance gates)
    // ------------------------------------------------------------------

    /**
     * The complete user-facing operation — both canonicality checks and both affine public
     * coordinates bound — not the 3,020-row gadget alone. The 64/252 and 252/252 figures equal
     * the measurements taken during review of ADR-0051 r1, before this milestone, so M1 left
     * the constraint system of every full-width circuit unchanged.
     */
    @Test
    @DisplayName("Complete ZkPedersen commit cost is pinned (rows and nonzeros)")
    void completeSafeApiCostPins() {
        R1CSConstraintSystem narrowValue = zkCommitCircuit(64).compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem fullValue = zkCommitCircuit(252).compileR1CS(CurveId.BLS12_381);

        assertEquals(2_918, narrowValue.constraints().size(), "64/252 rows");
        assertEquals(13_460, nnz(narrowValue), "64/252 nonzeros");
        assertEquals(4_042, fullValue.constraints().size(), "252/252 rows");
        assertEquals(19_338, nnz(fullValue), "252/252 nonzeros");
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static void defineZkCommit(int blindingWidth, boolean publicBlinding, boolean constantBlinding) {
        var builder = CircuitBuilder.create("zk-commit").secretVar("value");
        if (publicBlinding) builder.publicVar("blinding");
        else if (!constantBlinding) builder.secretVar("blinding");
        builder.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkUInt blinding;
            if (publicBlinding) {
                blinding = ZkUInt.publicInput(c, "blinding", blindingWidth);
            } else if (constantBlinding) {
                blinding = ZkUInt.wrap(zk, zk.constant(BigInteger.valueOf(12345)).signal(), blindingWidth);
            } else {
                blinding = ZkUInt.secret(c, "blinding", blindingWidth);
            }
            ZkPedersen.commit(zk, ZkUInt.secret(c, "value", 16), blinding);
        });
    }

    private static CircuitBuilder zkCommitCircuit(int valueBits) {
        return CircuitBuilder.create("zk-commit-" + valueBits)
                .publicVar("outU").publicVar("outV")
                .secretVar("value").secretVar("blinding")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.commit(zk,
                                    ZkUInt.secret(c, "value", valueBits),
                                    ZkUInt.secret(c, "blinding", FULL))
                            .assertAffineEquals(zk,
                                    ZkField.publicInput(c, "outU"),
                                    ZkField.publicInput(c, "outV"));
                });
    }

    private static Map<String, List<BigInteger>> witness(BigInteger value, BigInteger blinding, JubjubPoint c) {
        return Map.of(
                "outU", List.of(c.affineU()),
                "outV", List.of(c.affineV()),
                "value", List.of(value),
                "blinding", List.of(blinding));
    }

    private static long nnz(R1CSConstraintSystem system) {
        return system.constraints().stream()
                .mapToLong(c -> (long) c.a().size() + c.b().size() + c.c().size())
                .sum();
    }
}
