package com.bloxbean.cardano.zeroj.api;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Canonical, domain-separated identity for a Cardano Groth16 artifact bundle.
 *
 * <p>The v2 identity commits to the canonical circuit manifest before it commits to the
 * verification key, proof, and ordered public inputs. Consequently a proof cannot be moved
 * between operation/profile manifests while retaining its bundle identity.</p>
 */
public final class Groth16ArtifactBundleIdentity {
    public static final String SCHEMA = "zeroj-cardano-groth16-bundle-v2";
    private static final byte[] DOMAIN = (SCHEMA + "\0").getBytes(StandardCharsets.US_ASCII);
    private static final BigInteger BLS12_381_SCALAR_MODULUS = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private Groth16ArtifactBundleIdentity() {}

    public static String sha256(
            AuthenticatedStateCircuitManifest manifest,
            byte[] verificationKey,
            byte[] proofA,
            byte[] proofB,
            byte[] proofC,
            List<byte[]> orderedPublicInputs) {
        Objects.requireNonNull(manifest, "manifest");
        requireLength("proofA", proofA, 48);
        requireLength("proofB", proofB, 96);
        requireLength("proofC", proofC, 48);
        Objects.requireNonNull(verificationKey, "verificationKey");
        if (!digest(verificationKey).equals(manifest.verificationKeySha256())) {
            throw new IllegalArgumentException(
                    "verification key digest does not match the circuit manifest");
        }
        orderedPublicInputs = List.copyOf(
                Objects.requireNonNull(orderedPublicInputs, "orderedPublicInputs"));
        if (orderedPublicInputs.size() != manifest.publicInputs().size()) {
            throw new IllegalArgumentException(
                    "ordered public input count does not match the circuit manifest");
        }
        for (int index = 0; index < orderedPublicInputs.size(); index++) {
            byte[] encoded = orderedPublicInputs.get(index);
            requireLength("orderedPublicInputs[" + index + "]", encoded, 32);
            if (new BigInteger(1, encoded).compareTo(BLS12_381_SCALAR_MODULUS) >= 0) {
                throw new IllegalArgumentException(
                        "orderedPublicInputs[" + index + "] is not a canonical BLS12-381 scalar");
            }
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DOMAIN);
            update(digest, manifest.canonicalJsonBytes());
            update(digest, verificationKey);
            update(digest, proofA);
            update(digest, proofB);
            update(digest, proofC);
            for (byte[] publicInput : orderedPublicInputs) update(digest, publicInput);
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void update(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    private static String digest(byte[] value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void requireLength(String name, byte[] value, int expected) {
        Objects.requireNonNull(value, name);
        if (value.length != expected) {
            throw new IllegalArgumentException(name + " must be " + expected + " bytes");
        }
    }
}
