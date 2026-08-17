package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import co.nstant.in.cbor.model.ByteString;
import com.bloxbean.cardano.client.common.cbor.CborSerializationUtil;
import com.bloxbean.cardano.client.plutus.spec.PlutusV3Script;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.ledger.Address;
import com.bloxbean.cardano.julc.ledger.Credential;
import com.bloxbean.cardano.julc.ledger.DatumHash;
import com.bloxbean.cardano.julc.ledger.OutputDatum;
import com.bloxbean.cardano.julc.ledger.PolicyId;
import com.bloxbean.cardano.julc.ledger.ScriptHash;
import com.bloxbean.cardano.julc.ledger.TokenName;
import com.bloxbean.cardano.julc.ledger.TxInInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.ledger.Value;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.ScriptContextTestBuilder;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.api.AuthenticatedStateCircuitManifest;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16AuthenticatedStateTransitionScriptFactory;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16VerificationKeyCodec;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Groth16AuthenticatedStateTransitionValidatorTest extends ContractTest {

    private static final byte[] STATE_POLICY_BYTES = filled(28, (byte) 0x11);
    private static final byte[] STATE_TOKEN_BYTES = "poseidon-state".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AUTHORIZED_SIGNER = filled(28, (byte) 0x22);
    private static final byte[] RELEASE_ID = filled(32, (byte) 0x33);
    private static final byte[] SCRIPT_HASH = filled(28, (byte) 0x44);
    private static final String GENESIS_TX_ID = "55".repeat(32);
    private static final String GENESIS_EVIDENCE = "66".repeat(32);

    private static final PolicyId STATE_POLICY = PolicyId.of(STATE_POLICY_BYTES);
    private static final TokenName STATE_TOKEN = TokenName.of(STATE_TOKEN_BYTES);
    private static final Address STATE_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(SCRIPT_HASH)), Optional.empty());
    private static final Value STATE_VALUE = Value.lovelace(BigInteger.valueOf(2_000_000))
            .merge(Value.singleton(STATE_POLICY, STATE_TOKEN, BigInteger.ONE));

    private static SnarkjsToCardano.VkCompressed vk;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static BigInteger oldRoot;
    private static BigInteger newRoot;

    @BeforeAll
    static void loadProofFixture() throws Exception {
        vk = SnarkjsToCardano.parseVk(loadResource(
                "/test-circuits/sealed-bid-bls12381/verification_key.json"));
        proof = SnarkjsToCardano.parseProof(loadResource(
                "/test-circuits/sealed-bid-bls12381/proof.json"));
        List<BigInteger> publicInputs = SnarkjsToCardano.parsePublicInputs(loadResource(
                "/test-circuits/sealed-bid-bls12381/public.json"));
        oldRoot = publicInputs.get(0);
        newRoot = publicInputs.get(1);
    }

    @Test
    void authenticatesStateAndRejectsLedgerBindingMutations() {
        Program program = appliedProgram(RELEASE_ID, vk);

        assertSuccess(evaluate(program, context(Mutation.NONE)));

        for (Mutation mutation : Mutation.values()) {
            if (mutation != Mutation.NONE) {
                assertFailure(evaluate(program, context(mutation)));
            }
        }
    }

    @Test
    void appliedReleaseAndVerificationKeyArePartOfScriptIdentity() {
        Program expected = appliedProgram(RELEASE_ID, vk);

        byte[] anotherRelease = RELEASE_ID.clone();
        anotherRelease[0] ^= 1;
        Program differentRelease = appliedProgram(anotherRelease, vk);

        List<byte[]> changedIc = new ArrayList<>(vk.ic());
        byte[] changedPoint = changedIc.get(0).clone();
        changedPoint[changedPoint.length - 1] ^= 1;
        changedIc.set(0, changedPoint);
        var differentVk = new SnarkjsToCardano.VkCompressed(
                vk.alpha(), vk.beta(), vk.gamma(), vk.delta(), changedIc);
        Program differentKey = appliedProgram(RELEASE_ID, differentVk);

        assertNotEquals(expected, differentRelease, "release ID must alter the applied script");
        assertNotEquals(expected, differentKey, "verification key must alter the applied script");
    }

    @Test
    void releaseFactoryBindsManifestKeyPolicyAndAppliedScriptWithoutCircularIdentity()
            throws Exception {
        var manifest = transitionManifest(vk);
        String exactFingerprint = manifest.dimensionFingerprint() + "-r" + manifest.r1csSha256();
        Program template = compileValidator(Groth16AuthenticatedStateTransitionValidator.class)
                .program();
        String templateSha256 = Groth16AuthenticatedStateTransitionScriptFactory
                .unappliedValidatorSha256(template);
        var genesis = new Groth16AuthenticatedStateTransitionScriptFactory
                .StateTokenGenesisAttestation(GENESIS_TX_ID, 0, GENESIS_EVIDENCE);

        var applied = Groth16AuthenticatedStateTransitionScriptFactory.apply(
                template, templateSha256, manifest.canonicalSha256(), manifest, exactFingerprint, vk,
                STATE_POLICY_BYTES, STATE_TOKEN_BYTES, AUTHORIZED_SIGNER, genesis);

        assertEquals(32, applied.releaseId().length);
        assertTrue(applied.flatProgram().length > 0);
        assertSuccess(evaluate(applied.program(), context(Mutation.NONE, applied.releaseId())));
        assertFailure(evaluate(applied.program(), context(Mutation.NONE, RELEASE_ID)));

        var deployment = applied.deploymentManifest(
                Groth16AuthenticatedStateTransitionScriptFactory.CardanoNetwork.PREPROD);
        assertEquals(applied.releaseIdHex(), deployment.releaseId());
        assertEquals(manifest.canonicalSha256(), deployment.circuitManifestSha256());
        assertEquals(manifest.verificationKeySha256(), deployment.verificationKeySha256());
        assertEquals(templateSha256, deployment.unappliedValidatorSha256());
        assertEquals(applied.appliedValidatorSha256(), deployment.appliedValidatorSha256());
        assertEquals(applied.cardanoScriptHashHex(), deployment.cardanoScriptHash());
        assertEquals("preprod", deployment.network());
        assertEquals(0, deployment.networkId());
        assertEquals(1L, deployment.networkMagic());
        assertEquals(GENESIS_TX_ID + "#0", deployment.stateTokenGenesisReference());
        assertEquals(GENESIS_EVIDENCE, deployment.stateTokenGenesisEvidenceSha256());
        assertFalse(deployment.productionApproved());
        assertThrows(IllegalStateException.class,
                () -> applied.deploymentManifest(
                        Groth16AuthenticatedStateTransitionScriptFactory.CardanoNetwork.MAINNET));

        // Independently cross-check the factory's Cardano script identity through CCL's
        // PlutusV3Script implementation.
        byte[] cbor = CborSerializationUtil.serialize(new ByteString(applied.flatProgram()));
        var cclScript = PlutusV3Script.builder()
                .cborHex(HexUtil.encodeHexString(cbor))
                .build();
        assertArrayEquals(cclScript.getScriptHash(), applied.cardanoScriptHash());

        byte[] anotherSigner = AUTHORIZED_SIGNER.clone();
        anotherSigner[0] ^= 1;
        var anotherPolicy = Groth16AuthenticatedStateTransitionScriptFactory.apply(
                template, templateSha256, manifest.canonicalSha256(), manifest, exactFingerprint, vk,
                STATE_POLICY_BYTES, STATE_TOKEN_BYTES, anotherSigner, genesis);
        assertFalse(Arrays.equals(applied.releaseId(), anotherPolicy.releaseId()));
        assertNotEquals(applied.appliedValidatorSha256(), anotherPolicy.appliedValidatorSha256());

        Program substitutedTemplate = template.applyParams(PlutusData.integer(BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16AuthenticatedStateTransitionScriptFactory.apply(
                        substitutedTemplate, templateSha256, manifest.canonicalSha256(),
                        manifest, exactFingerprint, vk,
                        STATE_POLICY_BYTES, STATE_TOKEN_BYTES, AUTHORIZED_SIGNER, genesis));

        var differentGenesis = new Groth16AuthenticatedStateTransitionScriptFactory
                .StateTokenGenesisAttestation(GENESIS_TX_ID, 1, GENESIS_EVIDENCE);
        var anotherGenesisPolicy = Groth16AuthenticatedStateTransitionScriptFactory.apply(
                template, templateSha256, manifest.canonicalSha256(), manifest, exactFingerprint, vk,
                STATE_POLICY_BYTES, STATE_TOKEN_BYTES, AUTHORIZED_SIGNER, differentGenesis);
        assertFalse(Arrays.equals(applied.releaseId(), anotherGenesisPolicy.releaseId()));

        byte[] releaseCopy = applied.releaseId();
        releaseCopy[0] ^= 1;
        assertFalse(Arrays.equals(releaseCopy, applied.releaseId()),
                "release ID accessor must be defensive");
        byte[] flatCopy = applied.flatProgram();
        byte first = flatCopy[0];
        flatCopy[0] ^= 1;
        assertEquals(first, applied.flatProgram()[0], "flat program accessor must be defensive");

        byte[] expectedHash = applied.cardanoScriptHash();
        vk.alpha()[0] ^= 1;
        STATE_POLICY_BYTES[0] ^= 1;
        try {
            assertArrayEquals(expectedHash, applied.cardanoScriptHash(),
                    "caller-owned arrays must not alter an applied release");
        } finally {
            vk.alpha()[0] ^= 1;
            STATE_POLICY_BYTES[0] ^= 1;
        }
    }

    private Program appliedProgram(byte[] release, SnarkjsToCardano.VkCompressed key) {
        return compileValidator(Groth16AuthenticatedStateTransitionValidator.class)
                .program()
                .applyParams(
                        PlutusData.bytes(key.alpha()),
                        PlutusData.bytes(key.beta()),
                        PlutusData.bytes(key.gamma()),
                        PlutusData.bytes(key.delta()),
                        vkIcData(key.ic()),
                        PlutusData.bytes(STATE_POLICY_BYTES),
                        PlutusData.bytes(STATE_TOKEN_BYTES),
                        PlutusData.bytes(AUTHORIZED_SIGNER),
                        PlutusData.bytes(release));
    }

    private PlutusData context(Mutation mutation) {
        return context(mutation, RELEASE_ID);
    }

    private PlutusData context(Mutation mutation, byte[] acceptedRelease) {
        TxOutRef ownRef = TestDataBuilder.randomTxOutRef_typed();

        BigInteger argumentRoot = mutation == Mutation.ARGUMENT_OLD_ROOT
                ? oldRoot.add(BigInteger.ONE) : oldRoot;
        BigInteger argumentVersion = mutation == Mutation.NEGATIVE_VERSION
                ? BigInteger.ONE.negate() : BigInteger.valueOf(7);
        BigInteger redeemerRoot = mutation == Mutation.REDEEMER_NEW_ROOT
                ? newRoot.add(BigInteger.ONE) : newRoot;
        byte[] redeemerRelease = mutation == Mutation.REDEEMER_RELEASE
                ? flipped(acceptedRelease) : acceptedRelease;
        byte[] piA = mutation == Mutation.PROOF
                ? flipped(proof.piA()) : proof.piA();

        BigInteger inputRoot = mutation == Mutation.INPUT_INLINE_ROOT
                ? oldRoot.add(BigInteger.ONE) : oldRoot;
        OutputDatum inputDatum = switch (mutation) {
            case INPUT_DATUM_HASH -> new OutputDatum.OutputDatumHash(
                    DatumHash.of(filled(32, (byte) 0x55)));
            case INPUT_NO_DATUM -> new OutputDatum.NoOutputDatum();
            default -> inlineDatum(inputRoot, BigInteger.valueOf(7));
        };
        Value inputValue = mutation == Mutation.INPUT_TOKEN
                ? Value.lovelace(BigInteger.valueOf(2_000_000)) : STATE_VALUE;
        TxOut ownOutput = txOut(STATE_ADDRESS, inputValue, inputDatum);

        Address continuingAddress = mutation == Mutation.OUTPUT_ADDRESS
                ? TestDataBuilder.pubKeyAddress(TestDataBuilder.randomPubKeyHash_typed())
                : STATE_ADDRESS;
        BigInteger outputRoot = mutation == Mutation.OUTPUT_INLINE_ROOT
                ? newRoot.add(BigInteger.ONE) : newRoot;
        BigInteger outputVersion = mutation == Mutation.OUTPUT_VERSION
                ? BigInteger.valueOf(9) : BigInteger.valueOf(8);
        OutputDatum outputDatum = switch (mutation) {
            case OUTPUT_DATUM_HASH -> new OutputDatum.OutputDatumHash(
                    DatumHash.of(filled(32, (byte) 0x66)));
            case OUTPUT_NO_DATUM -> new OutputDatum.NoOutputDatum();
            default -> inlineDatum(outputRoot, outputVersion);
        };
        Value outputValue;
        if (mutation == Mutation.OUTPUT_TOKEN) {
            outputValue = Value.lovelace(BigInteger.valueOf(2_000_000));
        } else if (mutation == Mutation.OUTPUT_VALUE) {
            outputValue = Value.lovelace(BigInteger.valueOf(3_000_000))
                    .merge(Value.singleton(STATE_POLICY, STATE_TOKEN, BigInteger.ONE));
        } else {
            outputValue = STATE_VALUE;
        }
        TxOut continuingOutput = txOut(continuingAddress, outputValue, outputDatum);

        PlutusData argumentDatum = stateDatum(argumentRoot, argumentVersion);
        PlutusData redeemer = PlutusData.constr(0,
                PlutusData.integer(redeemerRoot),
                PlutusData.bytes(redeemerRelease),
                PlutusData.bytes(piA),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));

        ScriptContextTestBuilder builder = spendingContext(ownRef, argumentDatum)
                .input(new TxInInfo(ownRef, ownOutput))
                .redeemer(redeemer)
                .mint(mutation == Mutation.MINT
                        ? Value.singleton(STATE_POLICY, STATE_TOKEN, BigInteger.ONE)
                        : Value.zero());

        if (mutation != Mutation.MISSING_SIGNER) {
            builder.signer(AUTHORIZED_SIGNER);
        }
        if (mutation != Mutation.NO_CONTINUING_OUTPUT) {
            builder.output(continuingOutput);
        }
        if (mutation == Mutation.MULTIPLE_CONTINUING_OUTPUTS) {
            builder.output(continuingOutput);
        }
        if (mutation == Mutation.FOREIGN_INPUT_TOKEN) {
            builder.input(new TxInInfo(
                    TestDataBuilder.randomTxOutRef_typed(),
                    txOut(
                            TestDataBuilder.pubKeyAddress(TestDataBuilder.randomPubKeyHash_typed()),
                            Value.singleton(STATE_POLICY, STATE_TOKEN, BigInteger.ONE),
                            new OutputDatum.NoOutputDatum())));
        }
        if (mutation == Mutation.FOREIGN_OUTPUT_TOKEN) {
            builder.output(txOut(
                    TestDataBuilder.pubKeyAddress(TestDataBuilder.randomPubKeyHash_typed()),
                    Value.singleton(STATE_POLICY, STATE_TOKEN, BigInteger.ONE),
                    new OutputDatum.NoOutputDatum()));
        }
        return builder.buildPlutusData();
    }

    private static TxOut txOut(Address address, Value value, OutputDatum datum) {
        return new TxOut(address, value, datum, Optional.empty());
    }

    private static OutputDatum inlineDatum(BigInteger root, BigInteger version) {
        return new OutputDatum.OutputDatumInline(stateDatum(root, version));
    }

    private static PlutusData stateDatum(BigInteger root, BigInteger version) {
        return PlutusData.constr(0, PlutusData.integer(root), PlutusData.integer(version));
    }

    private static PlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] points = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            points[i] = PlutusData.bytes(ic.get(i));
        }
        return PlutusData.list(points);
    }

    private static byte[] flipped(byte[] source) {
        byte[] result = source.clone();
        result[result.length - 1] ^= 1;
        return result;
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static String loadResource(String path) throws IOException {
        try (var input = Groth16AuthenticatedStateTransitionValidatorTest.class
                .getResourceAsStream(path)) {
            if (input == null) throw new IOException("Resource not found: " + path);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static AuthenticatedStateCircuitManifest transitionManifest(
            SnarkjsToCardano.VkCompressed key) throws Exception {
        byte[] encodedKey = Groth16VerificationKeyCodec.encode(key);
        String keySha = java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(encodedKey));
        return new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                "zeroj-mpf-v1-value-update-s8-p2",
                "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.VALUE_UPDATE,
                8,
                List.of(
                        new AuthenticatedStateCircuitManifest.PublicInput(
                                0, "oldRoot", "field", "canonical-unsigned-big-endian-32"),
                        new AuthenticatedStateCircuitManifest.PublicInput(
                                1, "newRoot", "field", "canonical-unsigned-big-endian-32")),
                AuthenticatedStateCircuitManifest.POSEIDON_PARAMETER_FINGERPRINT,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "c1-w3-p2",
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                keySha,
                null,
                null,
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "benchmark-single-party", "test-fixture", null, false));
    }

    private enum Mutation {
        NONE,
        ARGUMENT_OLD_ROOT,
        NEGATIVE_VERSION,
        REDEEMER_NEW_ROOT,
        REDEEMER_RELEASE,
        PROOF,
        INPUT_INLINE_ROOT,
        INPUT_DATUM_HASH,
        INPUT_NO_DATUM,
        INPUT_TOKEN,
        OUTPUT_ADDRESS,
        OUTPUT_INLINE_ROOT,
        OUTPUT_VERSION,
        OUTPUT_DATUM_HASH,
        OUTPUT_NO_DATUM,
        OUTPUT_TOKEN,
        OUTPUT_VALUE,
        MINT,
        MISSING_SIGNER,
        NO_CONTINUING_OUTPUT,
        MULTIPLE_CONTINUING_OUTPUTS,
        FOREIGN_INPUT_TOKEN,
        FOREIGN_OUTPUT_TOKEN
    }
}
