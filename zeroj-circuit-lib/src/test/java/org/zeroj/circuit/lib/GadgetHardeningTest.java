package org.zeroj.circuit.lib;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0068: Binary/SignalBinary.rotateLeft & shiftRight, RangeCheck / deprecated AliasCheck,
 * and PoseidonN validation.
 */
class GadgetHardeningTest {

    @Test
    void binaryAndSignalBinaryRotateLeftMatchIntegerLeftRotation() {
        int[][] cases = {
                {0x01, 1, 0x02},
                {0x80, 1, 0x01},
                {0xA5, 3, 0x2D},
                {0x01, -1, 0x80},
                {0x01, 0, 0x01},
                {0x01, 8, 0x01},
                {0xA5, -3, 0xB4},
                {0x01, Integer.MIN_VALUE, 0x01} // -2^31 mod 8 == 0
        };

        for (int[] tc : cases) {
            int input = tc[0];
            int shift = tc[1];
            int expected = tc[2];

            var varCircuit = CircuitBuilder.create("bin-rotl-" + shift)
                    .secretVar("x").publicVar("out")
                    .define(api -> {
                        var bits = Binary.num2Bits(api, api.var("x"), 8);
                        var rotated = Binary.rotateLeft(bits, shift);
                        api.assertEqual(Binary.bits2Num(api, rotated), api.var("out"));
                    });
            var varR1cs = varCircuit.compileR1CS(CurveId.BLS12_381);
            var varWitness = varCircuit.calculateWitness(Map.of(
                    "x", List.of(BigInteger.valueOf(input)),
                    "out", List.of(BigInteger.valueOf(expected))), CurveId.BLS12_381);
            assertDoesNotThrow(() -> varR1cs.verifyWitness(varWitness));

            var sigCircuit = CircuitBuilder.create("sig-rotl-" + shift)
                    .secretVar("x").publicVar("out")
                    .defineSignals(c -> {
                        var bits = SignalBinary.num2Bits(c, c.privateInput("x"), 8);
                        var rotated = SignalBinary.rotateLeft(bits, shift);
                        c.assertEqual(SignalBinary.bits2Num(c, rotated), c.publicInput("out"));
                    });
            var sigR1cs = sigCircuit.compileR1CS(CurveId.BLS12_381);
            var sigWitness = sigCircuit.calculateWitness(Map.of(
                    "x", List.of(BigInteger.valueOf(input)),
                    "out", List.of(BigInteger.valueOf(expected))), CurveId.BLS12_381);
            assertDoesNotThrow(() -> sigR1cs.verifyWitness(sigWitness));
        }

        assertThrows(NullPointerException.class, () -> Binary.rotateLeft(null, 1));
        assertThrows(IllegalArgumentException.class, () -> Binary.rotateLeft(new Variable[0], 1));
        assertThrows(NullPointerException.class, () -> SignalBinary.rotateLeft(null, 1));
        assertThrows(IllegalArgumentException.class,
                () -> SignalBinary.rotateLeft(new Signal[0], 1));
    }

    @Test
    void binaryShiftRightGuardsNegativeAndLargeShifts() {
        var circuit = CircuitBuilder.create("bin-shr")
                .secretVar("x").publicVar("s1").publicVar("s8").publicVar("sMax")
                .define(api -> {
                    var bits = Binary.num2Bits(api, api.var("x"), 8);
                    api.assertEqual(Binary.bits2Num(api, Binary.shiftRight(api, bits, 1)), api.var("s1"));
                    api.assertEqual(Binary.bits2Num(api, Binary.shiftRight(api, bits, 8)), api.var("s8"));
                    api.assertEqual(Binary.bits2Num(api, Binary.shiftRight(api, bits, Integer.MAX_VALUE)), api.var("sMax"));
                });
        var witness = circuit.calculateWitness(Map.of(
                "x", List.of(BigInteger.valueOf(0xA5)),
                "s1", List.of(BigInteger.valueOf(0x52)),
                "s8", List.of(BigInteger.ZERO),
                "sMax", List.of(BigInteger.ZERO)), CurveId.BLS12_381);
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381).verifyWitness(witness));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("bin-shr-neg")
                .secretVar("x")
                .define(api -> Binary.shiftRight(api, Binary.num2Bits(api, api.var("x"), 8), -1)));
    }

    @Test
    @SuppressWarnings("removal")
    void rangeCheckAndDeprecatedAliasCheckEnforceBitWidthBounds() {
        var circuit = CircuitBuilder.create("range-8")
                .secretVar("x")
                .define(api -> RangeCheck.check(api, api.var("x"), 8));
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertDoesNotThrow(() -> r1cs.verifyWitness(
                circuit.calculateWitness(Map.of("x", List.of(BigInteger.valueOf(255))), CurveId.BLS12_381)));
        assertThrows(ArithmeticException.class, () ->
                circuit.calculateWitness(Map.of("x", List.of(BigInteger.valueOf(256))), CurveId.BLS12_381));

        // 254 bits rejected at definition time (not a < p alias check)
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("range-254")
                .secretVar("x")
                .define(api -> RangeCheck.check(api, api.var("x"), 254)));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("alias-254")
                .secretVar("x")
                .define(api -> AliasCheck.check(api, api.var("x"), 254)));
    }

    @Test
    void poseidonNRejectsNullInputsAndMatchesFoldedHostHash() {
        assertThrows(NullPointerException.class, () -> CircuitBuilder.create("p-null")
                .define(api -> PoseidonN.hash(api, PoseidonParamsBLS12_381T3.INSTANCE, (Variable[]) null)));
        assertThrows(NullPointerException.class, () -> CircuitBuilder.create("p-null-elem")
                .secretVar("x")
                .define(api -> PoseidonN.hash(api, PoseidonParamsBLS12_381T3.INSTANCE, api.var("x"), null)));

        BigInteger a = BigInteger.valueOf(11);
        BigInteger b = BigInteger.valueOf(22);
        BigInteger c = BigInteger.valueOf(33);
        BigInteger expected = PoseidonHash.hash(
                PoseidonParamsBLS12_381T3.INSTANCE,
                PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b),
                c);

        var circuit = CircuitBuilder.create("poseidon-n-3")
                .secretVar("a").secretVar("b").secretVar("c").publicVar("h")
                .define(api -> api.assertEqual(
                        PoseidonN.hash(api, PoseidonParamsBLS12_381T3.INSTANCE,
                                api.var("a"), api.var("b"), api.var("c")),
                        api.var("h")));
        var witness = circuit.calculateWitness(Map.of(
                "a", List.of(a), "b", List.of(b), "c", List.of(c), "h", List.of(expected)),
                CurveId.BLS12_381);
        assertEquals(expected, witness[1]);
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381).verifyWitness(witness));

        // Same-builder positive control for Signal-API RangeCheck and PoseidonN
        var sigCircuit = CircuitBuilder.create("signal-range-poseidon")
                .secretVar("a").secretVar("b").publicVar("h")
                .defineSignals(s -> {
                    var sa = s.privateInput("a");
                    var sb = s.privateInput("b");
                    RangeCheck.check(s, sa, 8);
                    s.assertEqual(PoseidonN.hash(s, PoseidonParamsBLS12_381T3.INSTANCE, sa, sb),
                            s.publicInput("h"));
                });
        BigInteger h2 = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
        var sigWitness = sigCircuit.calculateWitness(
                Map.of("a", List.of(a), "b", List.of(b), "h", List.of(h2)), CurveId.BLS12_381);
        assertDoesNotThrow(() -> sigCircuit.compileR1CS(CurveId.BLS12_381).verifyWitness(sigWitness));
    }

    @Test
    @SuppressWarnings("removal")
    void signalRangeCheckAliasCheckAndPoseidonNRejectForeignBuilderSignalsWithOverlappingWireIds() {
        // Foreign builder allocates wire ID 1 for "x" — same wire ID as local builder's "x".
        final Signal[] foreignSignal = new Signal[1];
        CircuitBuilder.create("foreign-owner")
                .secretVar("x")
                .defineSignals(foreign -> foreignSignal[0] = foreign.privateInput("x"));

        // RangeCheck rejects foreign signal before emitting gates
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("local-range")
                .secretVar("x")
                .defineSignals(local -> {
                    local.privateInput("x");
                    RangeCheck.check(local, foreignSignal[0], 8);
                }));

        // Deprecated AliasCheck inherits ownership check via RangeCheck
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("local-alias")
                .secretVar("x")
                .defineSignals(local -> {
                    local.privateInput("x");
                    AliasCheck.check(local, foreignSignal[0], 8);
                }));

        // PoseidonN rejects foreign signal in first OR second position atomically
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("local-poseidon-0")
                .secretVar("x").secretVar("y")
                .defineSignals(local -> {
                    var ly = local.privateInput("y");
                    PoseidonN.hash(local, PoseidonParamsBLS12_381T3.INSTANCE, foreignSignal[0], ly);
                }));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("local-poseidon-1")
                .secretVar("x").secretVar("y")
                .defineSignals(local -> {
                    var lx = local.privateInput("x");
                    PoseidonN.hash(local, PoseidonParamsBLS12_381T3.INSTANCE, lx, foreignSignal[0]);
                }));
    }
}
