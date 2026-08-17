package com.bloxbean.cardano.zeroj.api;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Groth16ArtifactBundleIdentityTest {

    @Test
    void identityCommitsToManifestKeyProofAndOrderedPublicInputs() throws Exception {
        byte[] verificationKey = filled(432, (byte) 1);
        var manifest = manifest(sha256(verificationKey));
        byte[] proofA = filled(48, (byte) 2);
        byte[] proofB = filled(96, (byte) 3);
        byte[] proofC = filled(48, (byte) 4);
        byte[] root = filled(32, (byte) 5);

        String expected = Groth16ArtifactBundleIdentity.sha256(
                manifest, verificationKey, proofA, proofB, proofC, List.of(root));

        byte[] changedProof = proofC.clone();
        changedProof[0] ^= 1;
        assertNotEquals(expected, Groth16ArtifactBundleIdentity.sha256(
                manifest, verificationKey, proofA, proofB, changedProof, List.of(root)));

        byte[] changedRoot = root.clone();
        changedRoot[0] ^= 1;
        assertNotEquals(expected, Groth16ArtifactBundleIdentity.sha256(
                manifest, verificationKey, proofA, proofB, proofC, List.of(changedRoot)));

        var differentManifest = new AuthenticatedStateCircuitManifest(
                manifest.schemaVersion(), manifest.templateId(), manifest.structureProfile(),
                manifest.operation(), manifest.maxSteps(), manifest.publicInputs(),
                manifest.poseidonParameterFingerprint(), manifest.r1csFormat(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                manifest.dimensionFingerprint(), manifest.provingSystem(), manifest.curve(),
                manifest.verificationKeyFormat(), manifest.verificationKeySha256(), null, null,
                manifest.setupProvenance());
        assertNotEquals(expected, Groth16ArtifactBundleIdentity.sha256(
                differentManifest, verificationKey, proofA, proofB, proofC, List.of(root)));
    }

    @Test
    void rejectsKeyDigestArityPointLengthAndNonCanonicalScalar() throws Exception {
        byte[] verificationKey = filled(432, (byte) 1);
        var manifest = manifest(sha256(verificationKey));
        byte[] proofA = filled(48, (byte) 2);
        byte[] proofB = filled(96, (byte) 3);
        byte[] proofC = filled(48, (byte) 4);
        byte[] root = filled(32, (byte) 5);

        assertThrows(IllegalArgumentException.class, () ->
                Groth16ArtifactBundleIdentity.sha256(
                        manifest, filled(432, (byte) 9), proofA, proofB, proofC, List.of(root)));
        assertThrows(IllegalArgumentException.class, () ->
                Groth16ArtifactBundleIdentity.sha256(
                        manifest, verificationKey, proofA, proofB, proofC, List.of()));
        assertThrows(IllegalArgumentException.class, () ->
                Groth16ArtifactBundleIdentity.sha256(
                        manifest, verificationKey, new byte[47], proofB, proofC, List.of(root)));
        assertThrows(IllegalArgumentException.class, () ->
                Groth16ArtifactBundleIdentity.sha256(
                        manifest, verificationKey, proofA, proofB, proofC,
                        List.of(filled(32, (byte) 0xff))));
    }

    private static AuthenticatedStateCircuitManifest manifest(String verificationKeySha256) {
        return new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                "zeroj-mpf-v1-inclusion-s8-p1",
                "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.INCLUSION,
                8,
                List.of(new AuthenticatedStateCircuitManifest.PublicInput(
                        0, "root", "field", "canonical-unsigned-big-endian-32")),
                AuthenticatedStateCircuitManifest.POSEIDON_PARAMETER_FINGERPRINT,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "c1-w2-p1",
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                verificationKeySha256,
                null,
                null,
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "benchmark-single-party", "test", null, false));
    }

    private static String sha256(byte[] value) throws Exception {
        return java.util.HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static byte[] filled(int size, byte value) {
        byte[] result = new byte[size];
        Arrays.fill(result, value);
        return result;
    }
}
