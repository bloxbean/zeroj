package com.bloxbean.cardano.zeroj.onchain;

import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Converts {@link VerificationMaterial} into compressed byte arrays suitable for
 * Julc on-chain verifier {@code @Param byte[]} parameters.
 *
 * <p>On-chain verifiers need VK data as compact byte arrays that can be baked into
 * Plutus scripts or passed as datums. This helper serializes the VK into the expected format.</p>
 */
public final class OnChainVkPreparer {

    private OnChainVkPreparer() {}

    /**
     * Prepare a Groth16 BLS12-381 VK for on-chain use.
     * Returns VK elements as a list of byte arrays: [alpha, beta, gamma, delta, IC...]
     */
    public static List<byte[]> prepareGroth16BLS12381Vk(VerificationMaterial material) {
        var vk = SnarkjsJsonCodec.parseVerificationKey(new String(material.vkBytes()));

        List<byte[]> elements = new ArrayList<>();
        elements.add(OnChainProofPreparer.g1ToBytes(vk.vkAlpha1()));
        elements.add(OnChainProofPreparer.g2ToBytes(vk.vkBeta2()));
        elements.add(OnChainProofPreparer.g2ToBytes(vk.vkGamma2()));
        elements.add(OnChainProofPreparer.g2ToBytes(vk.vkDelta2()));
        for (var ic : vk.ic()) {
            elements.add(OnChainProofPreparer.g1ToBytes(ic));
        }
        return elements;
    }

    /**
     * Compute a compact VK hash for on-chain VK commitment (hash-in-script pattern).
     * Uses SHA-256 of the canonical VK bytes.
     */
    public static byte[] computeVkHash(VerificationMaterial material) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(material.vkBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Estimate the on-chain size (in bytes) of the VK when serialized for a given proof system.
     */
    public static int estimateOnChainSize(VerificationMaterial material) {
        return switch (material.proofSystemId()) {
            case GROTH16 -> {
                var vk = SnarkjsJsonCodec.parseVerificationKey(new String(material.vkBytes()));
                // alpha (96) + beta (192) + gamma (192) + delta (192) + IC * 96
                yield 96 + 192 * 3 + vk.ic().size() * 96;
            }
            case PLONK -> {
                // 8 selector/permutation G1 commitments (96 each) + 1 G2 (192)
                yield 8 * 96 + 192;
            }
            default -> material.vkBytes().length;
        };
    }
}
