package org.zeroj.onchain.julc.groth16.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Converts snarkjs JSON decimal coordinate format to BLS12-381 compressed bytes
 * suitable for Cardano on-chain use (UPLC BLS12-381 builtins). Points are validated with the
 * pure-Java checked decoders (ADR-0062 D3); only affine {@code z = 1} encodings and the
 * {@code z = 0} identity are accepted (D5).
 * <p>
 * snarkjs format: {@code [x_decimal, y_decimal, "1"]} (projective affine)
 * Cardano format: compressed BLS point bytes (48 for G1, 96 for G2)
 */
public final class SnarkjsToCardano {

    private static final int FP_SIZE = 48;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SnarkjsToCardano() {}

    /**
     * Compress a G1 point from snarkjs projective coordinates to 48-byte compressed form.
     *
     * @param coords [x, y, z] as BigInteger (projective coordinates)
     * @return 48-byte compressed G1 point
     */
    public static byte[] g1Compress(List<BigInteger> coords) {
        if (coords.size() != 3) {
            throw new IllegalArgumentException("G1 point must have 3 coordinates");
        }
        if (coords.get(2).signum() == 0) {
            return Bls12381Codecs.g1ToCompressed(G1Point.INFINITY);
        }
        // Checked decode (coordinates < p, on curve, in subgroup), then the canonical compression.
        return Bls12381Codecs.g1ToCompressed(Bls12381Codecs.g1FromUncompressed(g1ToUncompressed(coords)));
    }

    /**
     * Compress a G2 point from snarkjs projective coordinates to 96-byte compressed form.
     *
     * @param coords [[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]] as BigInteger
     * @return 96-byte compressed G2 point
     */
    public static byte[] g2Compress(List<List<BigInteger>> coords) {
        if (coords.size() != 3 || coords.stream().anyMatch(c -> c.size() != 2)) {
            throw new IllegalArgumentException("G2 point must have 3 coordinates of 2 elements");
        }
        if (coords.get(2).get(0).signum() == 0 && coords.get(2).get(1).signum() == 0) {
            return Bls12381Codecs.g2ToCompressed(G2Point.INFINITY);
        }
        return Bls12381Codecs.g2ToCompressed(Bls12381Codecs.g2FromUncompressed(g2ToUncompressed(coords)));
    }

    /**
     * Parse a snarkjs verification_key.json and extract all VK points as compressed bytes.
     *
     * @return VK with compressed G1/G2 points
     */
    public static VkCompressed parseVk(String vkJson) throws Exception {
        JsonNode root = MAPPER.readTree(vkJson);
        byte[] alpha = g1Compress(parseG1(root.get("vk_alpha_1")));
        byte[] beta = g2Compress(parseG2(root.get("vk_beta_2")));
        byte[] gamma = g2Compress(parseG2(root.get("vk_gamma_2")));
        byte[] delta = g2Compress(parseG2(root.get("vk_delta_2")));

        JsonNode icNode = root.get("IC");
        List<byte[]> ic = new ArrayList<>();
        for (int i = 0; i < icNode.size(); i++) {
            ic.add(g1Compress(parseG1(icNode.get(i))));
        }
        return new VkCompressed(alpha, beta, gamma, delta, ic);
    }

    /**
     * Parse a snarkjs proof.json and extract proof points as compressed bytes.
     */
    public static ProofCompressed parseProof(String proofJson) throws Exception {
        JsonNode root = MAPPER.readTree(proofJson);
        byte[] piA = g1Compress(parseG1(root.get("pi_a")));
        byte[] piB = g2Compress(parseG2(root.get("pi_b")));
        byte[] piC = g1Compress(parseG1(root.get("pi_c")));
        return new ProofCompressed(piA, piB, piC);
    }

    /**
     * Parse a snarkjs public.json and return the public inputs as BigInteger list.
     */
    public static List<BigInteger> parsePublicInputs(String publicJson) throws Exception {
        JsonNode root = MAPPER.readTree(publicJson);
        List<BigInteger> inputs = new ArrayList<>();
        for (JsonNode node : root) {
            inputs.add(new BigInteger(node.asText()));
        }
        return inputs;
    }

    // --- Records for results ---

    public record VkCompressed(byte[] alpha, byte[] beta, byte[] gamma, byte[] delta, List<byte[]> ic) {}
    public record ProofCompressed(byte[] piA, byte[] piB, byte[] piC) {}

    // --- Internal conversion ---

    /**
     * Convert snarkjs projective G1 [x, y, z] to blst uncompressed format (96 bytes).
     */
    static byte[] g1ToUncompressed(List<BigInteger> coords) {
        BigInteger x = coords.get(0);
        BigInteger y = coords.get(1);
        BigInteger z = coords.get(2);

        byte[] result = new byte[FP_SIZE * 2]; // 96 bytes
        if (z.signum() == 0) return result;

        // ADR-0062 D5: snarkjs emits affine points (z = 1); a rescaled projective encoding is
        // rejected rather than normalised, as in the off-chain verifiers.
        if (!z.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("G1 point must be affine (z = 1)");
        }

        writeFp(result, 0, x);
        writeFp(result, FP_SIZE, y);
        return result;
    }

    /**
     * Convert snarkjs projective G2 [[x_c0,x_c1],[y_c0,y_c1],[z_c0,z_c1]] to
     * blst uncompressed format (192 bytes).
     * <p>
     * blst byte order: x_c1, x_c0, y_c1, y_c0 (imaginary first).
     */
    static byte[] g2ToUncompressed(List<List<BigInteger>> coords) {
        BigInteger xc0 = coords.get(0).get(0);
        BigInteger xc1 = coords.get(0).get(1);
        BigInteger yc0 = coords.get(1).get(0);
        BigInteger yc1 = coords.get(1).get(1);
        BigInteger zc0 = coords.get(2).get(0);
        BigInteger zc1 = coords.get(2).get(1);

        byte[] result = new byte[FP_SIZE * 4]; // 192 bytes
        if (zc0.signum() == 0 && zc1.signum() == 0) return result;

        if (!zc0.equals(BigInteger.ONE) || zc1.signum() != 0) {
            throw new IllegalArgumentException("G2 point must be affine (z = (1, 0))");
        }

        // blst ordering: imaginary (c1) first, then real (c0)
        writeFp(result, 0, xc1);
        writeFp(result, FP_SIZE, xc0);
        writeFp(result, FP_SIZE * 2, yc1);
        writeFp(result, FP_SIZE * 3, yc0);
        return result;
    }

    /**
     * Write a field element as 48-byte big-endian into buffer at offset.
     */
    static void writeFp(byte[] buf, int offset, BigInteger value) {
        // Reject rather than truncate: a value >= p (or wider than 48 bytes) is not a coordinate.
        if (value.signum() < 0 || value.compareTo(Fp.P) >= 0) {
            throw new IllegalArgumentException("Coordinate must be in [0, p)");
        }
        byte[] bytes = value.toByteArray();
        int srcStart = Math.max(0, bytes.length - FP_SIZE);
        int count = Math.min(bytes.length, FP_SIZE);
        int destStart = offset + FP_SIZE - count;
        System.arraycopy(bytes, srcStart, buf, destStart, count);
    }

    // --- JSON parsing helpers ---

    private static List<BigInteger> parseG1(JsonNode node) {
        List<BigInteger> coords = new ArrayList<>();
        for (JsonNode elem : node) {
            coords.add(new BigInteger(elem.asText()));
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG2(JsonNode node) {
        List<List<BigInteger>> coords = new ArrayList<>();
        for (JsonNode pair : node) {
            List<BigInteger> fp2 = new ArrayList<>();
            for (JsonNode elem : pair) {
                fp2.add(new BigInteger(elem.asText()));
            }
            coords.add(fp2);
        }
        return coords;
    }
}
