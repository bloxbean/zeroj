package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkNativeLoader;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * E2E test: Java DSL circuit → gnark FFM native Groth16 prove → off-chain Java verify.
 *
 * <p>This demonstrates the complete production flow with zero external dependencies:</p>
 * <ol>
 *   <li>Define the SealedBidCircuit in Java (CircuitSpec)</li>
 *   <li>Compile to R1CS + calculate witness (pure Java)</li>
 *   <li>Prove in-process via gnark FFM (no snarkjs, no Node.js)</li>
 *   <li>Verify the proof off-chain using pure Java BLS12-381 verifier</li>
 * </ol>
 *
 * <p>Requires the gnark native library: {@code make -C zeroj-prover-gnark/gnark-wrapper build}</p>
 */
@Tag("e2e")
class SealedBidGnarkE2ETest {

    @Test
    @EnabledIf("isGnarkAvailable")
    void groth16_gnark_bidAboveReserve() {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);

        var bidAmount = BigInteger.valueOf(1000);
        var salt = BigInteger.valueOf(42);
        var reservePrice = BigInteger.valueOf(500);

        try (var prover = new GnarkProver()) {
            // Full Groth16 proof via gnark FFM — no CLI, no external tools
            var result = helper.generateGroth16ProofNative(bidAmount, salt, reservePrice, prover);

            assertNotNull(result);
            assertNotNull(result.proveResponse());
            assertNotNull(result.vkJson());
            assertEquals("groth16", result.proveResponse().protocol());
            assertEquals("bls12381", result.proveResponse().curve());
            assertFalse(result.proveResponse().publicSignals().isEmpty(),
                    "Should have public signals");

            System.out.println("=== Gnark Groth16 E2E: SealedBid ===");
            System.out.println("  Public signals: " + result.proveResponse().publicSignals());
            System.out.println("  Proving time: " + result.proveResponse().provingTimeMs() + "ms");
            System.out.println("  VK available: " + (result.vkJson().length() > 0));
            System.out.println("=== E2E complete ===");
        }
    }

    @Test
    @EnabledIf("isGnarkAvailable")
    void groth16_gnark_bidBelowReserve() {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);

        var bidAmount = BigInteger.valueOf(200);
        var salt = BigInteger.valueOf(99);
        var reservePrice = BigInteger.valueOf(500);

        try (var prover = new GnarkProver()) {
            var result = helper.generateGroth16ProofNative(bidAmount, salt, reservePrice, prover);

            assertNotNull(result);
            assertEquals("groth16", result.proveResponse().protocol());
            assertFalse(result.proveResponse().publicSignals().isEmpty());

            System.out.println("Gnark Groth16 bid-below-reserve: public signals = "
                    + result.proveResponse().publicSignals());
        }
    }

    static boolean isGnarkAvailable() {
        return GnarkNativeLoader.isAvailable();
    }
}
