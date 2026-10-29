package org.zeroj.docs.sha2;

import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.hash.Sha256;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Public teaching fixtures only. Not an issuer service, identity protocol or production setup. */
public final class ApprovedRecordDemo {
    private static final int RECORD_BYTES = 48;
    private static final CircuitId ID = new CircuitId("sha256-approved-record-v1");

    private ApprovedRecordDemo() {}

    public static void main(String[] args) throws Exception {
        byte[] issuedRecord = fixture("USER0042", 1);
        byte[] trustedDigest = MessageDigest.getInstance("SHA-256").digest(issuedRecord);
        List<BigInteger> expectedPublic = limbs(trustedDigest);
        // The application obtains this digest from its trusted issuer registry, not the prover.
        System.out.println("Trusted SHA-256: " + HexFormat.of().formatHex(trustedDigest));
        System.out.println("Public input order: [digest0, digest1]");
        var circuit = circuit();
        var compiled = circuit.compileR1CS(CurveId.BLS12_381);
        Path temporaryKeys = Files.createTempDirectory("zeroj-sha256-record-");
        try {
            // Development only. The setup API uses this sampled tau scalar, not a
            // four-power ceremony transcript for the much larger SHA circuit.
            var tau = PowersOfTauBLS381.generate(4).tauScalar();
            try (var keys = Groth16Keys.setupToStore(compiled.flat(), compiled.numWires(),
                    compiled.numPublicInputs(), tau, temporaryKeys.resolve("keys"), true)) {
                String vk = SnarkjsGroth16Json.verificationKeyJson(keys);
                var witness = circuit.calculateWitness(input(issuedRecord, expectedPublic), CurveId.BLS12_381);
                String proof = SnarkjsGroth16Json.proofJson(keys.prove(witness, compiled.constraints()));
                String pub = SnarkjsGroth16Json.publicJson(expectedPublic.toArray(BigInteger[]::new));
                require(accept(vk, expectedPublic, pub, proof), "Registered approved record: accepted");

                byte[] editedRecord = issuedRecord.clone();
                editedRecord[15] ^= 1; // USER0042 -> USER0043, original registered digest.
                rejectWitness(circuit, editedRecord, expectedPublic, "Changed record: rejected");
                byte[] deniedRecord = fixture("USER0042", 0);
                rejectWitness(circuit, deniedRecord, digestLimbs(deniedRecord),
                        "Denied record with its own matching hash: rejected");
                byte[] wrongProgram = issuedRecord.clone();
                wrongProgram[7] = 8;
                rejectWitness(circuit, wrongProgram, digestLimbs(wrongProgram),
                        "Wrong program with its own matching hash: rejected");

                BigInteger[] changedPublic = expectedPublic.toArray(BigInteger[]::new);
                changedPublic[0] = changedPublic[0].xor(BigInteger.ONE);
                String changedJson = SnarkjsGroth16Json.publicJson(changedPublic);
                require(!verifyMath(vk, changedJson, proof), "Changed public digest: rejected");

                // This statement really is true, but the issuer never registered this record.
                byte[] unregistered = fixture("USER0099", 1);
                List<BigInteger> unregisteredPublic = digestLimbs(unregistered);
                var otherWitness = circuit.calculateWitness(input(unregistered, unregisteredPublic), CurveId.BLS12_381);
                String otherProof = SnarkjsGroth16Json.proofJson(keys.prove(otherWitness, compiled.constraints()));
                String otherPub = SnarkjsGroth16Json.publicJson(unregisteredPublic.toArray(BigInteger[]::new));
                require(verifyMath(vk, otherPub, otherProof), "Unregistered approved record: proof is mathematically valid");
                require(!accept(vk, expectedPublic, otherPub, otherProof), "Unregistered approved record: application rejects");
            }
        } finally {
            try (var paths = Files.walk(temporaryKeys)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    // This exact method is shown in the tutorial. Policy is part of the circuit and its keys.
    public static CircuitBuilder circuit() {
        var builder = CircuitBuilder.create("sha256-approved-record-v1");
        builder.publicVar("digest0").publicVar("digest1");
        for (int i = 0; i < RECORD_BYTES; i++) builder.secretVar("byte" + i);
        return builder.define(api -> {
            Variable[] record = new Variable[RECORD_BYTES];
            for (int i = 0; i < record.length; i++) record[i] = api.var("byte" + i);

            // "ZJAP", version 1, approved=1, program=7 (unsigned 16-bit big-endian).
            int[] requiredHeader = {0x5a, 0x4a, 0x41, 0x50, 1, 1, 0, 7};
            for (int i = 0; i < requiredHeader.length; i++)
                api.assertEqual(record[i], api.constant(requiredHeader[i]));

            Variable[] digest = Sha256.hashBytes(api, record); // All bytes range-constrained.
            for (int limb = 0; limb < 2; limb++) {
                Variable packed = api.constant(0);
                for (int j = 0; j < 16; j++)
                    packed = api.add(api.mul(packed, api.constant(256)), digest[16 * limb + j]);
                api.assertEqual(packed, api.var("digest" + limb));
            }
        });
    }

    private static byte[] fixture(String subject, int approved) {
        byte[] record = new byte[RECORD_BYTES];
        byte[] header = {0x5a, 0x4a, 0x41, 0x50, 1, (byte) approved, 0, 7};
        System.arraycopy(header, 0, record, 0, header.length);
        byte[] reference = subject.getBytes(StandardCharsets.US_ASCII);
        if (reference.length != 8) throw new IllegalArgumentException("Eight-byte subject reference required");
        System.arraycopy(reference, 0, record, 8, 8);
        // PUBLIC deterministic test bytes, not a hiding nonce for real records.
        // A new private-record format needs fresh 32-byte SecureRandom nonces at issuance.
        for (int i = 16; i < record.length; i++) record[i] = (byte) (i - 16);
        return record;
    }

    private static List<BigInteger> digestLimbs(byte[] message) throws Exception {
        return limbs(MessageDigest.getInstance("SHA-256").digest(message));
    }

    private static List<BigInteger> limbs(byte[] digest) {
        if (digest.length != 32) throw new IllegalArgumentException("Full SHA-256 digest required");
        return List.of(new BigInteger(1, Arrays.copyOfRange(digest, 0, 16)),
                new BigInteger(1, Arrays.copyOfRange(digest, 16, 32)));
    }

    private static Map<String, List<BigInteger>> input(byte[] record, List<BigInteger> digest) {
        if (record.length != RECORD_BYTES || digest.size() != 2) throw new IllegalArgumentException("Wrong shape");
        var inputs = new HashMap<String, List<BigInteger>>();
        for (int i = 0; i < 2; i++) inputs.put("digest" + i, List.of(digest.get(i)));
        for (int i = 0; i < record.length; i++) inputs.put("byte" + i, List.of(BigInteger.valueOf(record[i] & 255)));
        return inputs;
    }

    private static boolean accept(String trustedVk, List<BigInteger> expected, String pub, String proof) {
        if (!SnarkjsJsonCodec.parsePublicInputs(pub).values().equals(expected)) return false;
        return verifyMath(trustedVk, pub, proof);
    }

    private static boolean verifyMath(String trustedVk, String pub, String proof) {
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proof, trustedVk, pub, ID);
        var material = VerificationMaterial.of(trustedVk.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, ID);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }

    private static void rejectWitness(CircuitBuilder circuit, byte[] record, List<BigInteger> digest, String label) {
        try {
            circuit.calculateWitness(input(record, digest), CurveId.BLS12_381);
        } catch (ArithmeticException expected) {
            System.out.println(label);
            return;
        }
        throw new IllegalStateException("Invalid witness accepted: " + label);
    }

    private static void require(boolean condition, String label) {
        if (!condition) throw new IllegalStateException("Tutorial regression: " + label);
        System.out.println(label);
    }
}
