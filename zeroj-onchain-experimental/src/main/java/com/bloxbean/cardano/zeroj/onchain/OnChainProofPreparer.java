package com.bloxbean.cardano.zeroj.onchain;

import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Converts a {@link ZkProofEnvelope} into a format suitable for Plutus redeemer construction.
 *
 * <p>On-chain verifiers (Julc-based) expect proof data as lists of integers and byte arrays
 * that map to Plutus Data types. This helper transforms the generic proof envelope into
 * the specific layout each on-chain verifier expects.</p>
 *
 * <p><b>Note:</b> Actual Plutus script construction stays in zeroj-examples (Julc).
 * This helper prepares the Java-side data only.</p>
 */
public final class OnChainProofPreparer {

    private OnChainProofPreparer() {}

    /**
     * Prepare Groth16 BLS12-381 proof data for on-chain redeemer.
     * Returns the proof elements as a list of byte arrays (G1/G2 points).
     *
     * @param envelope the proof envelope (must be Groth16/BLS12-381)
     * @return list of proof element byte arrays: [piA, piB, piC]
     */
    public static List<byte[]> prepareGroth16BLS12381Redeemer(ZkProofEnvelope envelope) {
        validateSystem(envelope, "groth16", "bls12381");

        // Parse proof.json and extract the three curve points
        var proof = com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec.parseProof(
                new String(envelope.proofBytes()));

        List<byte[]> result = new ArrayList<>();
        result.add(g1ToBytes(proof.piA()));
        result.add(g2ToBytes(proof.piB()));
        result.add(g1ToBytes(proof.piC()));
        return result;
    }

    /**
     * Prepare public inputs as a list of BigIntegers for Plutus integer fields.
     */
    public static List<BigInteger> preparePublicInputs(ZkProofEnvelope envelope) {
        return List.copyOf(envelope.publicInputs().values());
    }

    /**
     * Encode a G1 point [x, y, z] (projective, BLS12-381) to 96-byte uncompressed affine.
     */
    static byte[] g1ToBytes(List<BigInteger> coords) {
        var x = coords.get(0);
        var y = coords.get(1);
        // Assume z=1 (snarkjs outputs affine-in-projective-form)
        var result = new byte[96];
        writeBigEndian(result, 0, 48, x);
        writeBigEndian(result, 48, 48, y);
        return result;
    }

    /**
     * Encode a G2 point [[x_c0,x_c1],[y_c0,y_c1],[z_c0,z_c1]] to 192-byte uncompressed.
     */
    static byte[] g2ToBytes(List<List<BigInteger>> coords) {
        var result = new byte[192];
        // BLS12-381 G2: x_c1, x_c0, y_c1, y_c0 (48 bytes each)
        writeBigEndian(result, 0, 48, coords.get(0).get(1));    // x_c1
        writeBigEndian(result, 48, 48, coords.get(0).get(0));   // x_c0
        writeBigEndian(result, 96, 48, coords.get(1).get(1));   // y_c1
        writeBigEndian(result, 144, 48, coords.get(1).get(0));  // y_c0
        return result;
    }

    private static void validateSystem(ZkProofEnvelope envelope, String expectedSystem, String expectedCurve) {
        if (!envelope.proofSystem().value().equals(expectedSystem)) {
            throw new IllegalArgumentException("Expected " + expectedSystem + " proof, got " + envelope.proofSystem());
        }
        if (!envelope.curve().value().equals(expectedCurve)) {
            throw new IllegalArgumentException("Expected " + expectedCurve + " curve, got " + envelope.curve());
        }
    }

    private static void writeBigEndian(byte[] buf, int offset, int fieldSize, BigInteger value) {
        var bytes = value.toByteArray();
        int srcStart = (bytes.length > fieldSize) ? bytes.length - fieldSize : 0;
        int destStart = offset + fieldSize - Math.min(bytes.length, fieldSize);
        System.arraycopy(bytes, srcStart, buf, destStart, Math.min(bytes.length, fieldSize));
    }
}
