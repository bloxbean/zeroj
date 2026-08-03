package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.ledger.Address;
import com.bloxbean.cardano.julc.ledger.Credential;
import com.bloxbean.cardano.julc.ledger.OutputDatum;
import com.bloxbean.cardano.julc.ledger.PolicyId;
import com.bloxbean.cardano.julc.ledger.ScriptHash;
import com.bloxbean.cardano.julc.ledger.TokenName;
import com.bloxbean.cardano.julc.ledger.TxInInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.ledger.Value;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.vds.jmt.store.InMemoryJmtStore;
import com.bloxbean.cardano.zeroj.api.AuthenticatedStateCircuitManifest;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit.PoseidonJmtCircuitTemplates;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness.PoseidonJmtInclusionWitness;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.PoseidonMpfCircuitTemplates;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16AuthenticatedStateTransitionScriptFactory;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16VerificationKeyCodec;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Real host structure -> operation-specific circuit -> Groth16 -> applied state validator.
 * All setup material in this test is intentionally single-party and non-production.
 */
class PoseidonAuthenticatedStateTransitionE2ETest extends ContractTest {
    private static final BigInteger TEST_TAU = new BigInteger(
            "5a65726f4a2d7472616e736974696f6e2d6532652d746f7869632d7761737465", 16);
    private static final byte[] SIGNER = filled(28, (byte) 0x31);
    private static final byte[] MPF_POLICY = filled(28, (byte) 0x41);
    private static final byte[] JMT_POLICY = filled(28, (byte) 0x42);
    private static final byte[] MPF_TOKEN = bytes("poseidon-mpf-state");
    private static final byte[] JMT_TOKEN = bytes("poseidon-jmt-state");

    @TempDir
    Path temporaryDirectory;

    @BeforeAll
    static void allowTestSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    @Test
    void realMpfAndJmtValueUpdatesVerifyAndCrossStructureSubstitutionFails() throws Exception {
        TransitionProof mpf = buildMpfTransition(temporaryDirectory.resolve("mpf-keys"));
        System.gc();
        TransitionProof jmt = buildJmtTransition(temporaryDirectory.resolve("jmt-keys"));

        Program template = compileValidator(Groth16AuthenticatedStateTransitionValidator.class)
                .program();
        String templateSha256 = Groth16AuthenticatedStateTransitionScriptFactory
                .unappliedValidatorSha256(template);
        var mpfApplied = apply(
                template, templateSha256, mpf, MPF_POLICY, MPF_TOKEN,
                genesis(0, (byte) 0x51));
        var jmtApplied = apply(
                template, templateSha256, jmt, JMT_POLICY, JMT_TOKEN,
                genesis(1, (byte) 0x52));

        assertSuccess(evaluate(mpfApplied.program(), context(
                mpfApplied, mpf, MPF_POLICY, MPF_TOKEN)));
        assertSuccess(evaluate(jmtApplied.program(), context(
                jmtApplied, jmt, JMT_POLICY, JMT_TOKEN)));

        // The exact same proof bytes cannot be replayed under the other structure's VK/release,
        // even when the ledger state is otherwise internally consistent for that applied script.
        assertFailure(evaluate(jmtApplied.program(), context(
                jmtApplied, mpf, JMT_POLICY, JMT_TOKEN)));
        assertFailure(evaluate(mpfApplied.program(), context(
                mpfApplied, jmt, MPF_POLICY, MPF_TOKEN)));

        assertNotEquals(mpf.manifest().verificationKeySha256(),
                jmt.manifest().verificationKeySha256());
        assertNotEquals(mpfApplied.releaseIdHex(), jmtApplied.releaseIdHex());
        assertThrows(IllegalArgumentException.class, () ->
                Groth16AuthenticatedStateTransitionScriptFactory.apply(
                        template, templateSha256, jmt.manifest().canonicalSha256(),
                        jmt.manifest(), jmt.exactFingerprint(), mpf.verificationKey(),
                        JMT_POLICY, JMT_TOKEN, SIGNER, genesis(1, (byte) 0x52)));

        AuthenticatedStateCircuitManifest relabeled = relabelAsInsert(mpf.manifest());
        assertThrows(IllegalArgumentException.class, () ->
                Groth16AuthenticatedStateTransitionScriptFactory.apply(
                        template, templateSha256, mpf.manifest().canonicalSha256(),
                        relabeled, mpf.exactFingerprint(), mpf.verificationKey(),
                        MPF_POLICY, MPF_TOKEN, SIGNER, genesis(0, (byte) 0x51)));
    }

    private TransitionProof buildMpfTransition(Path keysDirectory) throws Exception {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("member-1"), bytes("active"));
        trie.put(bytes("member-2"), bytes("active"));
        trie.put(bytes("member-3"), bytes("suspended"));
        trie.put(bytes("member-4"), bytes("active"));
        byte[] key = bytes("member-2");
        byte[] oldValue = bytes("active");
        byte[] newValue = bytes("revoked");
        byte[] oldRootBytes = trie.getRootHash();
        byte[] proofWire = trie.getProofWire(key).orElseThrow();
        int bound = PoseidonMpfCodec.decode(proofWire).size() + 1;
        PoseidonMpfBranchWitness branch = PoseidonMpfBranchWitness.inclusion(
                oldRootBytes, key, oldValue, proofWire, bound);
        trie.put(key, newValue);
        byte[] newRootBytes = trie.getRootHash();

        CircuitBuilder circuit = PoseidonMpfCircuitTemplates.valueUpdate(bound);
        var inputs = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.OLD_ROOT, mpfField(oldRootBytes))
                .put(PoseidonMpfCircuitTemplates.NEW_ROOT, mpfField(newRootBytes))
                .put(PoseidonMpfCircuitTemplates.OLD_VALUE,
                        PoseidonMpfValueCommitment.field(oldValue))
                .put(PoseidonMpfCircuitTemplates.NEW_VALUE,
                        PoseidonMpfValueCommitment.field(newValue));
        branch.putInto(inputs);
        return prove(
                circuit, inputs.toWitnessMap(), bound, PoseidonMpfHash.PROFILE_ID,
                keysDirectory);
    }

    private TransitionProof buildJmtTransition(Path keysDirectory) throws Exception {
        PoseidonJmtTree tree = new PoseidonJmtTree(new InMemoryJmtStore());
        Map<byte[], byte[]> initial = new LinkedHashMap<>();
        for (int index = 0; index < 12; index++) {
            initial.put(bytes("jmt-key-" + index), bytes("jmt-value-" + index));
        }
        byte[] oldRootBytes = tree.put(0, initial).rootHash();
        byte[] key = bytes("jmt-key-3");
        byte[] oldValue = bytes("jmt-value-3");
        byte[] newValue = bytes("jmt-value-3-updated");
        var hostProof = tree.getProof(key, 0).orElseThrow();
        int bound = hostProof.steps().size() + 1;
        var path = PoseidonJmtInclusionWitness.create(
                oldRootBytes, key, oldValue, hostProof, bound);
        byte[] newRootBytes = tree.put(1, Map.of(key, newValue)).rootHash();

        CircuitBuilder circuit = PoseidonJmtCircuitTemplates.valueUpdate(bound);
        var inputs = new ZkInputMap()
                .put("oldRoot", PoseidonJmtHash.decode(oldRootBytes))
                .put("newRoot", PoseidonJmtHash.decode(newRootBytes))
                .put("jmt_old_value_hash", PoseidonJmtHash.decode(PoseidonJmtHash.digest(oldValue)))
                .put("jmt_new_value_hash", PoseidonJmtHash.decode(PoseidonJmtHash.digest(newValue)));
        path.path().putInto(inputs);
        return prove(
                circuit, inputs.toWitnessMap(), bound, PoseidonJmtProfile.PROFILE_ID,
                keysDirectory);
    }

    private TransitionProof prove(
            CircuitBuilder circuit,
            Map<String, List<BigInteger>> inputs,
            int bound,
            String profile,
            Path keysDirectory) throws Exception {
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        assertEquals(2, r1cs.numPublicInputs());
        assertEquals(witness[1], inputs.get("oldRoot").getFirst());
        assertEquals(witness[2], inputs.get("newRoot").getFirst());

        SnarkjsToCardano.VkCompressed verificationKey;
        SnarkjsToCardano.ProofCompressed proof;
        try (Groth16Keys keys = Groth16Keys.setupToStore(
                r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs(),
                TEST_TAU, keysDirectory, true)) {
            verificationKey = ProverToCardano.compressVk(keys);
            proof = ProverToCardano.compressProof(keys.prove(witness, r1cs.constraints()));
        }

        String r1csSha256 = R1CSFlatIO.canonicalSha256(
                r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs());
        String dimensions = "c" + r1cs.numConstraints()
                + "-w" + r1cs.numWires() + "-p" + r1cs.numPublicInputs();
        String exactFingerprint = dimensions + "-r" + r1csSha256;
        String verificationKeySha256 = sha256(
                Groth16VerificationKeyCodec.encode(verificationKey));
        var manifest = new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                circuit.constraintGraph().name(),
                profile,
                AuthenticatedStateCircuitManifest.Operation.VALUE_UPDATE,
                bound,
                List.of(
                        new AuthenticatedStateCircuitManifest.PublicInput(
                                0, "oldRoot", "field", "canonical-unsigned-big-endian-32"),
                        new AuthenticatedStateCircuitManifest.PublicInput(
                                1, "newRoot", "field", "canonical-unsigned-big-endian-32")),
                AuthenticatedStateCircuitManifest.POSEIDON_PARAMETER_FINGERPRINT,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                r1csSha256,
                dimensions,
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                verificationKeySha256,
                null,
                null,
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "benchmark-single-party", "transition-e2e/" + exactFingerprint,
                        null, false));
        return new TransitionProof(
                witness[1], witness[2], verificationKey, proof, manifest, exactFingerprint);
    }

    private Groth16AuthenticatedStateTransitionScriptFactory.AppliedScript apply(
            Program template,
            String templateSha256,
            TransitionProof transition,
            byte[] policy,
            byte[] token,
            Groth16AuthenticatedStateTransitionScriptFactory.StateTokenGenesisAttestation genesis) {
        return Groth16AuthenticatedStateTransitionScriptFactory.apply(
                template,
                templateSha256,
                transition.manifest().canonicalSha256(),
                transition.manifest(),
                transition.exactFingerprint(),
                transition.verificationKey(),
                policy,
                token,
                SIGNER,
                genesis);
    }

    private PlutusData context(
            Groth16AuthenticatedStateTransitionScriptFactory.AppliedScript applied,
            TransitionProof transition,
            byte[] policyBytes,
            byte[] tokenBytes) {
        PolicyId policy = PolicyId.of(policyBytes);
        TokenName token = TokenName.of(tokenBytes);
        Address address = new Address(
                new Credential.ScriptCredential(ScriptHash.of(applied.cardanoScriptHash())),
                Optional.empty());
        Value value = Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(policy, token, BigInteger.ONE));
        var ownRef = TestDataBuilder.randomTxOutRef_typed();
        var inputDatum = stateDatum(transition.oldRoot(), BigInteger.valueOf(11));
        var input = new TxOut(
                address, value, new OutputDatum.OutputDatumInline(inputDatum), Optional.empty());
        var output = new TxOut(
                address, value,
                new OutputDatum.OutputDatumInline(
                        stateDatum(transition.newRoot(), BigInteger.valueOf(12))),
                Optional.empty());
        var proof = transition.proof();
        var redeemer = PlutusData.constr(0,
                PlutusData.integer(transition.newRoot()),
                PlutusData.bytes(applied.releaseId()),
                PlutusData.bytes(proof.piA()),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));
        return spendingContext(ownRef, inputDatum)
                .input(new TxInInfo(ownRef, input))
                .output(output)
                .mint(Value.zero())
                .signer(SIGNER)
                .redeemer(redeemer)
                .buildPlutusData();
    }

    private static AuthenticatedStateCircuitManifest relabelAsInsert(
            AuthenticatedStateCircuitManifest original) {
        return new AuthenticatedStateCircuitManifest(
                original.schemaVersion(),
                "zeroj-mpf-v1-insert-empty-s" + original.maxSteps() + "-p2",
                original.structureProfile(),
                AuthenticatedStateCircuitManifest.Operation.INSERT_EMPTY,
                original.maxSteps(),
                original.publicInputs(),
                original.poseidonParameterFingerprint(),
                original.r1csFormat(),
                original.r1csSha256(),
                original.dimensionFingerprint(),
                original.provingSystem(),
                original.curve(),
                original.verificationKeyFormat(),
                original.verificationKeySha256(),
                original.provingKeyFormat(),
                original.provingKeySha256(),
                original.setupProvenance());
    }

    private static Groth16AuthenticatedStateTransitionScriptFactory.StateTokenGenesisAttestation
            genesis(int outputIndex, byte evidenceByte) {
        return new Groth16AuthenticatedStateTransitionScriptFactory.StateTokenGenesisAttestation(
                "71".repeat(32), outputIndex,
                String.format("%02x", evidenceByte & 0xff).repeat(32));
    }

    private static PlutusData stateDatum(BigInteger root, BigInteger version) {
        return PlutusData.constr(0, PlutusData.integer(root), PlutusData.integer(version));
    }

    private static BigInteger mpfField(byte[] digest) {
        return PoseidonMpfHash.fieldFromDigestBytes(digest);
    }

    private static String sha256(byte[] value) throws Exception {
        return java.util.HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private record TransitionProof(
            BigInteger oldRoot,
            BigInteger newRoot,
            SnarkjsToCardano.VkCompressed verificationKey,
            SnarkjsToCardano.ProofCompressed proof,
            AuthenticatedStateCircuitManifest manifest,
            String exactFingerprint) {}
}
