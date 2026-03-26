package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deterministic SHA-256 hashing for proof envelopes and verification keys.
 *
 * <p>The canonical hash is computed over a deterministic byte encoding of the envelope's
 * core fields (proof system, curve, circuit id, proof bytes, public inputs, VK reference).
 * This ensures the same proof always produces the same hash regardless of serialization format.</p>
 */
public final class CanonicalHash {

    private CanonicalHash() {}

    /**
     * Compute the canonical SHA-256 hash of a proof envelope.
     *
     * <p>The hash covers: version, proofSystem, curve, circuitId, proofBytes, publicInputs, vkRef.
     * Optional fields (metadata, timestamps, etc.) are NOT included in the canonical hash.</p>
     *
     * @return 32-byte SHA-256 hash
     */
    public static byte[] hash(ZkProofEnvelope envelope) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // version (4 bytes, big-endian)
            digest.update(ByteBuffer.allocate(4).putInt(envelope.version()).array());

            // proof system
            digest.update(lengthPrefixed(envelope.proofSystem().value()));

            // curve
            digest.update(lengthPrefixed(envelope.curve().value()));

            // circuit id
            digest.update(lengthPrefixed(envelope.circuitId().value()));

            // proof bytes (length-prefixed)
            byte[] proofBytes = envelope.proofBytes();
            digest.update(ByteBuffer.allocate(4).putInt(proofBytes.length).array());
            digest.update(proofBytes);

            // public inputs count + each input as length-prefixed big-endian bytes
            var inputs = envelope.publicInputs().values();
            digest.update(ByteBuffer.allocate(4).putInt(inputs.size()).array());
            for (var input : inputs) {
                byte[] inputBytes = input.toByteArray();
                digest.update(ByteBuffer.allocate(4).putInt(inputBytes.length).array());
                digest.update(inputBytes);
            }

            // vk ref (tag byte + content)
            switch (envelope.vkRef()) {
                case com.bloxbean.cardano.zeroj.api.VerificationKeyRef.ByHash h -> {
                    digest.update((byte) 0x01);
                    digest.update(h.hash());
                }
                case com.bloxbean.cardano.zeroj.api.VerificationKeyRef.ById id -> {
                    digest.update((byte) 0x02);
                    digest.update(lengthPrefixed(id.id()));
                }
            }

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Compute SHA-256 of raw bytes.
     */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] lengthPrefixed(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(4 + bytes.length);
        buf.putInt(bytes.length);
        buf.put(bytes);
        return buf.array();
    }
}
