package com.bloxbean.cardano.zeroj.yaci.protocol;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Computes the deterministic hash of an {@link AppProofSubmission} for Ed25519 signing.
 *
 * <p>The hash covers all semantically significant fields (everything except the signature itself).
 * This is the message that must be signed by the submitter.</p>
 *
 * <p>Hash is SHA-256 over a canonical byte encoding with length-prefixed fields.</p>
 */
public final class SubmissionHash {

    private SubmissionHash() {}

    /**
     * Compute the signable hash of a submission.
     *
     * @return 32-byte SHA-256 hash
     */
    public static byte[] compute(AppProofSubmission submission) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");

            // Domain separator to prevent cross-protocol signature reuse
            digest.update("zeroj-submission-v1".getBytes(StandardCharsets.UTF_8));

            digest.update(lengthPrefixed(submission.appId()));
            digest.update(lengthPrefixed(submission.proofSystem().value()));
            digest.update(lengthPrefixed(submission.curve().value()));
            digest.update(lengthPrefixed(submission.circuitId()));
            digest.update(lengthPrefixed(submission.circuitVersion()));
            digest.update(lengthPrefixedBytes(submission.prevStateRoot()));
            digest.update(lengthPrefixedBytes(submission.newStateRoot()));

            // Public inputs: count + each as length-prefixed BigInteger bytes
            var inputs = submission.publicInputs();
            digest.update(ByteBuffer.allocate(4).putInt(inputs.size()).array());
            for (var input : inputs) {
                byte[] inputBytes = input.toByteArray();
                digest.update(lengthPrefixedBytes(inputBytes));
            }

            digest.update(lengthPrefixedBytes(submission.proofBytes()));
            digest.update(submission.vkHash()); // always 32 bytes, no length prefix needed
            digest.update(lengthPrefixed(submission.submitterId()));
            digest.update(ByteBuffer.allocate(8).putLong(submission.sequence()).array());

            // Nullifier (optional — tag byte 0x00 for absent, 0x01 + data for present)
            var nullifier = submission.nullifier();
            if (nullifier == null) {
                digest.update((byte) 0x00);
            } else {
                digest.update((byte) 0x01);
                digest.update(lengthPrefixedBytes(nullifier));
            }

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] lengthPrefixed(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        var buf = ByteBuffer.allocate(4 + bytes.length);
        buf.putInt(bytes.length);
        buf.put(bytes);
        return buf.array();
    }

    private static byte[] lengthPrefixedBytes(byte[] data) {
        var buf = ByteBuffer.allocate(4 + data.length);
        buf.putInt(data.length);
        buf.put(data);
        return buf.array();
    }
}
