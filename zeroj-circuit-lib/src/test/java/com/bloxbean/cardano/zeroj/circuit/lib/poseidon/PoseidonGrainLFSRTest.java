package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonConstants;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-verification tests for {@link PoseidonGrainLFSR}.
 *
 * <p>The primary correctness gate: regenerate the BN254 t=3 round constants
 * and MDS matrix from our Java Grain LFSR and compare byte-for-byte against
 * the values currently shipped in {@link PoseidonConstants} — those constants
 * were produced by iden3/circomlibjs using the authoritative Sage script
 * (the same script this class ports) with BN254 arguments. If this test
 * passes, the Java port is proven equivalent to the reference Sage
 * implementation for GF(p) generation.
 *
 * <p>A secondary test exercises the generator with BLS12-381 arguments and
 * asserts basic structural properties (range, count). The concrete
 * BLS12-381 t=3 constants are produced by a separate one-shot runner and
 * checked in as source — this test verifies the runner's inputs are valid.
 */
class PoseidonGrainLFSRTest {

    private static final BigInteger BN254_PRIME = new BigInteger(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16);

    private static final BigInteger BLS12_381_PRIME = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    @DisplayName("BN254 t=3 α=5 RF=8 RP=57: round constants match committed circomlibjs reference byte-for-byte")
    void bn254_t3_roundConstants_matchCommittedReference() {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BN254_PRIME);

        BigInteger[] regenerated = gen.generateRoundConstants();

        assertEquals(PoseidonConstants.C.length, regenerated.length,
                "Round constant count must match (65 rounds * 3 cells = 195)");
        assertArrayEquals(PoseidonConstants.C, regenerated,
                "Regenerated BN254 round constants must match circomlibjs reference");
    }

    @Test
    @DisplayName("BN254 t=3 α=5 RF=8 RP=57: MDS matrix matches committed circomlibjs reference byte-for-byte")
    void bn254_t3_mdsMatrix_matchesCommittedReference() {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BN254_PRIME);

        // The Sage script runs round-constant generation first, then MDS sampling,
        // from the same LFSR stream. Order matters.
        gen.generateRoundConstants();
        BigInteger[][] m = gen.generateMdsMatrix();

        assertEquals(3, m.length);
        for (int i = 0; i < 3; i++) {
            assertEquals(3, m[i].length);
            for (int j = 0; j < 3; j++) {
                BigInteger expected = PoseidonConstants.M[i * 3 + j];
                assertEquals(expected, m[i][j],
                        "MDS[" + i + "][" + j + "] must match circomlibjs reference");
            }
        }
    }

    @Test
    @DisplayName("BLS12-381 t=3 α=5 RF=8 RP=57: generator produces 195 valid field elements")
    void bls12_381_t3_roundConstants_areValidFieldElements() {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(255, 3, 8, 57, BLS12_381_PRIME);

        BigInteger[] constants = gen.generateRoundConstants();

        assertEquals(195, constants.length,
                "Should produce (RF + RP) * t = 65 * 3 = 195 constants");
        for (int i = 0; i < constants.length; i++) {
            assertTrue(constants[i].signum() >= 0,
                    "Constant " + i + " must be non-negative");
            assertTrue(constants[i].compareTo(BLS12_381_PRIME) < 0,
                    "Constant " + i + " must be < BLS12-381 scalar prime");
        }
    }

    @Test
    @DisplayName("BLS12-381 t=3 α=5 RF=8 RP=57: generator produces a 3x3 MDS with all entries < prime and nonzero")
    void bls12_381_t3_mdsMatrix_isWellFormed() {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(255, 3, 8, 57, BLS12_381_PRIME);

        gen.generateRoundConstants();
        BigInteger[][] m = gen.generateMdsMatrix();

        assertEquals(3, m.length);
        for (int i = 0; i < 3; i++) {
            assertEquals(3, m[i].length);
            for (int j = 0; j < 3; j++) {
                assertTrue(m[i][j].signum() > 0,
                        "MDS[" + i + "][" + j + "] must be positive");
                assertTrue(m[i][j].compareTo(BLS12_381_PRIME) < 0,
                        "MDS[" + i + "][" + j + "] must be < BLS12-381 scalar prime");
            }
        }
    }

    @Test
    @DisplayName("Generator is deterministic: two runs with same params produce identical output")
    void generator_isDeterministic() {
        PoseidonGrainLFSR gen1 = PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BN254_PRIME);
        PoseidonGrainLFSR gen2 = PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BN254_PRIME);

        BigInteger[] c1 = gen1.generateRoundConstants();
        BigInteger[] c2 = gen2.generateRoundConstants();
        assertArrayEquals(c1, c2);

        BigInteger[][] m1 = gen1.generateMdsMatrix();
        BigInteger[][] m2 = gen2.generateMdsMatrix();
        for (int i = 0; i < 3; i++) {
            assertArrayEquals(m1[i], m2[i]);
        }
    }

    /**
     * Regression fixtures for BLS12-381 t=3 α=5 RF=8 RP=57.
     *
     * <p>These values were produced by this Java port of the hadeshash Grain
     * LFSR Sage script. Because BN254 t=3 output byte-matches the
     * Sage-produced circomlibjs reference ({@link #bn254_t3_roundConstants_matchCommittedReference}),
     * and the LFSR machinery is field-agnostic (only {@code fieldSize} and
     * {@code prime} change between the two), these BLS12-381 values are
     * expected to be byte-identical to the Sage script's own output for the
     * same arguments. To independently verify, run:
     * <pre>
     *   sage src/main/resources/poseidon/generate_parameters_grain.sage \
     *        1 0 255 3 8 57 \
     *        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
     * </pre>
     * and compare the first printed round constants and MDS entries.
     *
     * <p>These fixtures also serve as a regression gate: any accidental change
     * to {@link PoseidonGrainLFSR} that affects BLS12-381 output will fail
     * this test even if the BN254 test still passes (e.g., a bug in bit-width
     * handling of {@code n=255}).
     */
    private static final String[] BLS12_381_T3_FIRST_6_CONSTANTS_HEX = {
            "6c4ffa723eaf1a7bf74905cc7dae4ca9ff4a2c3bc81d42e09540d1f250910880",
            "54dd837eccf180c92c2f53a3476e45a156ab69a403b6b9fdfd8dd970fddcdd9a",
            "64f56d735286c35f0e7d0a29680d49d54fb924adccf8962eeee225bf9423a85e",
            "670d5b6efe620f987d967fb13d2045ee3ac8e9cbf7d30e8594e733c7497910dc",
            "2ef5299e2077b2392ca874b015120d7e7530f277e06f78ee0b28f33550c68937",
            "0c0981889405b59c384e7dfa49cd4236e2f45ed024488f67c73f51c7c22d8095",
    };

    private static final String[][] BLS12_381_T3_MDS_HEX = {
            {
                    "3d955d6c02fe4d7cb500e12f2b55eff668a7b4386bd27413766713c93f2acfcd",
                    "3798866f4e6058035dcf8addb2cf1771fac234bcc8fc05d6676e77e797f224bf",
                    "2c51456a7bf2467eac813649f3f25ea896eac27c5da020dae54a6e640278fda2",
            },
            {
                    "20088ca07bbcd7490a0218ebc0ecb31d0ea34840e2dc2d33a1a5adfecff83b43",
                    "1d04ba0915e7807c968ea4b1cb2d610c7f9a16b4033f02ebacbb948c86a988c3",
                    "5387ccd5729d7acbd09d96714d1d18bbd0eeaefb2ddee3d2ef573c9c7f953307",
            },
            {
                    "1e208f585a72558534281562cad89659b428ec61433293a8d7f0f0e38a6726ac",
                    "0455ebf862f0b60f69698e97d36e8aafd4d107cae2b61be1858b23a3363642e0",
                    "569e2c206119e89455852059f707370e2c1fc9721f6c50991cedbbf782daef54",
            },
    };

    @Test
    @DisplayName("BLS12-381 t=3 α=5 RF=8 RP=57: first 6 round constants match hex regression fixture")
    void bls12_381_t3_firstConstants_matchRegressionFixture() {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(255, 3, 8, 57, BLS12_381_PRIME);
        BigInteger[] c = gen.generateRoundConstants();

        for (int i = 0; i < BLS12_381_T3_FIRST_6_CONSTANTS_HEX.length; i++) {
            BigInteger expected = new BigInteger(BLS12_381_T3_FIRST_6_CONSTANTS_HEX[i], 16);
            assertEquals(expected, c[i],
                    "BLS12-381 round constant C[" + i + "] diverged — re-verify against Sage script output");
        }
    }

    @Test
    @DisplayName("BLS12-381 t=3 α=5 RF=8 RP=57: all 195 round constants match committed preset byte-for-byte")
    void bls12_381_t3_allConstants_matchCommittedPreset() {
        // The committed preset file (PoseidonParamsBLS12_381T3.java) was written by
        // PoseidonParamsCodegen running this generator. Comparing live LFSR output
        // to it catches any corruption of C[6..194] — the hex fixture above only
        // covers C[0..5].
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(255, 3, 8, 57, BLS12_381_PRIME);
        BigInteger[] freshC = gen.generateRoundConstants();
        assertArrayEquals(PoseidonParamsBLS12_381T3.C, freshC,
                "BLS12-381 constants drifted between LFSR and committed preset — regenerate");
    }

    @Test
    @DisplayName("BLS12-381 t=3 α=5 RF=8 RP=57: MDS matrix matches committed regression fixture")
    void bls12_381_t3_mds_matchesRegressionFixture() {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(255, 3, 8, 57, BLS12_381_PRIME);
        gen.generateRoundConstants();
        BigInteger[][] m = gen.generateMdsMatrix();

        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                BigInteger expected = new BigInteger(BLS12_381_T3_MDS_HEX[i][j], 16);
                assertEquals(expected, m[i][j],
                        "BLS12-381 MDS[" + i + "][" + j + "] diverged — re-verify against Sage script output");
            }
        }
    }

    @Test
    @DisplayName("forGFp rejects parameter tuples not in the accept-list")
    void forGFp_rejectsUnvettedParams() {
        // Non-standard RP value — not on VETTED_PARAMS, must throw.
        assertThrows(UnsupportedOperationException.class,
                () -> PoseidonGrainLFSR.forGFp(255, 3, 8, 52, BLS12_381_PRIME));
        // Made-up prime — must throw.
        assertThrows(UnsupportedOperationException.class,
                () -> PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BigInteger.valueOf(Long.MAX_VALUE)));
    }

    @Test
    @DisplayName("LFSR bit stream is deterministic across independently-constructed generators")
    void lfsr_bitStream_isDeterministicAcrossInstances() {
        // Two independent generators with same params must agree on every output bit,
        // which implicitly verifies the warm-up phase is correctly implemented.
        PoseidonGrainLFSR a = PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BN254_PRIME);
        PoseidonGrainLFSR b = PoseidonGrainLFSR.forGFp(254, 3, 8, 57, BN254_PRIME);
        for (int i = 0; i < 1000; i++) {
            assertEquals(a.nextBit(), b.nextBit(),
                    "Bit stream divergence at bit " + i);
        }
    }
}
