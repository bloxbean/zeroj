package com.bloxbean.cardano.zeroj.verifier.plonk;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fiat-Shamir transcript matching gnark's exact format.
 *
 * <p>gnark's transcript format (from gnark-crypto/fiat-shamir/transcript.go):
 * <pre>
 * challenge = SHA-256(
 *     challenge_name_bytes ||         // e.g., "gamma", "beta", "alpha", "zeta"
 *     previous_challenge_hash ||      // hash chain (not reset between rounds)
 *     binding_value_1 ||
 *     binding_value_2 ||
 *     ...
 * )
 * </pre>
 *
 * <p>Key differences from snarkjs transcript:
 * <ul>
 *   <li>Challenge names are prefixed to the hash input</li>
 *   <li>Challenges chain (each includes the previous challenge's hash)</li>
 *   <li>Challenge order: gamma(0) → beta(1) → alpha(2) → zeta(3)</li>
 *   <li>VK points use compressed bytes (Marshal = 48 bytes for G1)</li>
 *   <li>Proof G1 points use uncompressed bytes (RawBytes = 96 bytes)</li>
 * </ul>
 */
public class GnarkFiatShamirTranscript {

    private final BigInteger fieldModulus;
    private final Map<String, ChallengeState> challenges = new LinkedHashMap<>();
    private byte[] previousChallengeHash = null;
    private int previousPosition = -1;

    private static class ChallengeState {
        final int position;
        final List<byte[]> bindings = new ArrayList<>();
        byte[] value;
        boolean computed;

        ChallengeState(int position) {
            this.position = position;
        }
    }

    /**
     * Create a new gnark-compatible transcript.
     *
     * @param fieldModulus the scalar field modulus Fr
     * @param challengeNames ordered challenge names (e.g., "gamma", "beta", "alpha", "zeta")
     */
    public GnarkFiatShamirTranscript(BigInteger fieldModulus, String... challengeNames) {
        this.fieldModulus = fieldModulus;
        for (int i = 0; i < challengeNames.length; i++) {
            challenges.put(challengeNames[i], new ChallengeState(i));
        }
    }

    /**
     * Bind a value to a challenge (before computing it).
     */
    public void bind(String challengeName, byte[] value) {
        ChallengeState state = challenges.get(challengeName);
        if (state == null) throw new IllegalArgumentException("Unknown challenge: " + challengeName);
        if (state.computed) throw new IllegalStateException("Challenge already computed: " + challengeName);
        state.bindings.add(value.clone());
    }

    /**
     * Compute a challenge value.
     *
     * <p>Format: SHA-256(challenge_name || previous_challenge_hash || bindings...)</p>
     *
     * @return the challenge as a field element (hash bytes interpreted as big-endian integer mod Fr)
     */
    public BigInteger computeChallenge(String challengeName) {
        ChallengeState state = challenges.get(challengeName);
        if (state == null) throw new IllegalArgumentException("Unknown challenge: " + challengeName);
        if (state.computed) return new BigInteger(1, state.value).mod(fieldModulus);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            // 1. Write challenge name
            sha256.update(challengeName.getBytes());

            // 2. Write previous challenge hash (if not the first challenge)
            if (state.position != 0) {
                if (previousChallengeHash == null || previousPosition != state.position - 1) {
                    throw new IllegalStateException("Previous challenge not computed for: " + challengeName);
                }
                sha256.update(previousChallengeHash);
            }

            // 3. Write all bindings
            for (byte[] binding : state.bindings) {
                sha256.update(binding);
            }

            // 4. Compute hash
            byte[] hash = sha256.digest();

            state.value = hash;
            state.computed = true;
            previousChallengeHash = hash;
            previousPosition = state.position;

            // gnark uses SetBytes on the hash which interprets as big-endian
            return new BigInteger(1, hash).mod(fieldModulus);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Get the raw hash bytes of a computed challenge (for debugging/validation).
     */
    public byte[] getRawHash(String challengeName) {
        ChallengeState state = challenges.get(challengeName);
        if (state == null || !state.computed) return null;
        return state.value.clone();
    }
}
