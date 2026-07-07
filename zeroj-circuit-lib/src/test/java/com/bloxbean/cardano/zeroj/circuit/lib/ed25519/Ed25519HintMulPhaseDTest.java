package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0028 Phase D: wire the (audit-gated) hint mul into the Ed25519 gadgets and measure the
 * compounded end-to-end win, re-validating correctness against the host/BouncyCastle oracle.
 *
 * <p>Flips the {@link Fe25519#USE_HINT_MUL} opt-in under try/finally; gated behind
 * {@code -Dzeroj.heavy} so it runs isolated (the toggle is process-global) via
 * {@code :zeroj-circuit-lib:heavyGadgetTest}.</p>
 */
@EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
class Ed25519HintMulPhaseDTest {

    @Test
    void hintMul_pointAddAndScalarMul_costAndCorrectness() {
        boolean prev = Fe25519.USE_HINT_MUL;
        try {
            // --- cost: point-add with deterministic vs hint mul ---
            Fe25519.USE_HINT_MUL = false;
            int addDet = pointAddConstraints();
            Fe25519.USE_HINT_MUL = true;
            int addHint = pointAddConstraints();
            // The loose-operand hint mul (Phase C.2) accepts lazy operands directly (no
            // canonicalization), so it composes with Phase B and reduces point-add.
            System.out.printf("[ADR-0028 D] Ed25519 point-add: deterministic=%d  hint=%d  (%.2fx)%n",
                    addDet, addHint, addDet / (double) addHint);
            assertTrue(addHint < addDet, "loose-operand hint mul must reduce point-add (composes with lazy reduction)");

            // --- correctness: a full 255-bit windowed scalar mult with hint mul still == host ---
            Fe25519.USE_HINT_MUL = true;
            BigInteger k = BigInteger.ONE.shiftLeft(254).or(new BigInteger("123456789012345678901234567"));
            byte[] expected = Ed25519Host.encode(Ed25519Host.scalarMulBase(k));
            var builder = CircuitBuilder.create("hint-smul");
            for (int i = 0; i < 255; i++) builder.secretVar("s" + i);
            for (int i = 0; i < 32; i++) builder.publicVar("e" + i);
            builder.define(api -> {
                Variable[] bits = new Variable[255];
                for (int i = 0; i < 255; i++) bits[i] = api.var("s" + i);
                Variable[] enc = Ed25519Point.scalarMulFixedBaseBWindowed(api, bits, 4).encode();
                for (int i = 0; i < 32; i++) api.assertEqual(enc[i], api.var("e" + i));
            });
            Map<String, List<BigInteger>> in = new HashMap<>();
            for (int i = 0; i < 255; i++) in.put("s" + i, List.of(k.testBit(i) ? BigInteger.ONE : BigInteger.ZERO));
            for (int i = 0; i < 32; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));
            assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254),
                    "hint-mul scalar mult must reproduce the host encoding");
            System.out.println("[ADR-0028 D] full 255-bit scalar mult with hint mul validated vs host");
        } finally {
            Fe25519.USE_HINT_MUL = prev;
        }
    }

    private static int pointAddConstraints() {
        var builder = CircuitBuilder.create("padd-cost");
        builder.define(api -> Ed25519Point.constant(api, Ed25519Host.B)
                .add(Ed25519Point.constant(api, Ed25519Host.B)));
        return builder.compileR1CS(CurveId.BN254).numConstraints();
    }
}
