package com.bloxbean.cardano.zeroj.prover.gnark;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the gnark full prove API (setup + prove in one call).
 *
 * <p>Uses a simple multiplier circuit (X * Y = Z) defined in the Java DSL
 * and proves it entirely in-process via gnark FFM.</p>
 *
 * <p>Build the native library first: {@code make -C zeroj-prover-gnark/gnark-wrapper build}</p>
 */
class GnarkFullProveTest {

    /**
     * Simple multiplier circuit: X * Y = Z.
     * Public output: Z. Private inputs: X, Y.
     */
    static class MultiplierCircuit implements CircuitSpec {
        @Override
        public void define(SignalBuilder c) {
            Signal x = c.privateInput("x");
            Signal y = c.privateInput("y");
            Signal z = c.publicOutput("z");
            c.assertEqual(x.mul(y), z);
        }

        static CircuitBuilder build() {
            return CircuitBuilder.create("multiplier")
                    .publicVar("z")
                    .secretVar("x")
                    .secretVar("y")
                    .defineSignals(new MultiplierCircuit());
        }
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void groth16FullProve_multiplierCircuit() {
        var circuit = MultiplierCircuit.build();
        R1CSConstraintSystem r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        // X=3, Y=11, Z=33
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11)),
                "z", List.of(BigInteger.valueOf(33))
        ), CurveId.BLS12_381);

        try (var prover = new GnarkProver()) {
            var result = prover.groth16FullProve(r1cs, witness, CurveId.BLS12_381);

            assertNotNull(result);
            assertNotNull(result.proveResponse());
            assertNotNull(result.vkJson());
            assertEquals("groth16", result.proveResponse().protocol());
            assertEquals("bls12381", result.proveResponse().curve());
            assertFalse(result.proveResponse().publicSignals().isEmpty(),
                    "Should have public signals");

            System.out.println("Groth16 full prove SUCCESS (3 * 11 = 33)");
            System.out.println("  Public signals: " + result.proveResponse().publicSignals());
            System.out.println("  Proving time: " + result.proveResponse().provingTimeMs() + "ms");
        }
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void plonkFullProve_multiplierCircuit() {
        var circuit = MultiplierCircuit.build();
        R1CSConstraintSystem r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11)),
                "z", List.of(BigInteger.valueOf(33))
        ), CurveId.BLS12_381);

        try (var prover = new GnarkProver()) {
            var result = prover.plonkFullProve(r1cs, witness, CurveId.BLS12_381);

            assertNotNull(result);
            assertNotNull(result.proveResponse());
            assertNotNull(result.vkJson());
            assertEquals("plonk", result.proveResponse().protocol());
            assertEquals("bls12381", result.proveResponse().curve());

            System.out.println("PlonK full prove SUCCESS (3 * 11 = 33)");
            System.out.println("  Public signals: " + result.proveResponse().publicSignals());
            System.out.println("  Proving time: " + result.proveResponse().provingTimeMs() + "ms");
        }
    }

    @Test
    void constraintsJsonSerialization() {
        var circuit = MultiplierCircuit.build();
        R1CSConstraintSystem r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        String json = GnarkProver.serializeConstraintsToJson(r1cs);
        assertTrue(json.contains("\"numPublic\":" + r1cs.numPublicInputs()));
        assertTrue(json.contains("\"numWires\":" + r1cs.numWires()));
        assertTrue(json.contains("\"constraints\":["));
        System.out.println("Constraints JSON length: " + json.length());
        System.out.println("  numPublic: " + r1cs.numPublicInputs());
        System.out.println("  numWires: " + r1cs.numWires());
        System.out.println("  numConstraints: " + r1cs.numConstraints());
    }

    @Test
    void witnessJsonSerialization() {
        BigInteger[] witness = {
                BigInteger.ONE,
                BigInteger.valueOf(33),
                BigInteger.valueOf(3),
                BigInteger.valueOf(11)
        };

        String json = GnarkProver.buildWitnessValuesJson(witness, 1);
        assertTrue(json.contains("\"numPublic\":1"));
        assertTrue(json.contains("\"33\""));
        assertTrue(json.contains("\"3\""));
        assertTrue(json.contains("\"11\""));
    }

    static boolean isNativeLibraryAvailable() {
        return GnarkNativeLoader.isAvailable();
    }
}
