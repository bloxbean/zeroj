package com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.core.flat.UplcFlatEncoder;
import com.bloxbean.cardano.zeroj.api.AuthenticatedStateCircuitManifest;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Applies an operation-specific Groth16 verification key and authenticated-state policy to the
 * representative two-root transition validator.
 *
 * <p>The release ID binds the canonical circuit manifest, exact R1CS, verification key, exact
 * unapplied validator program, compiler profile, state token, signer, and the external one-shot
 * token genesis attestation. It deliberately excludes the applied script hash because the release
 * ID is itself an applied script parameter. The deployment manifest records both identities after
 * parameter application without introducing that circularity.</p>
 */
public final class Groth16AuthenticatedStateTransitionScriptFactory {
    public static final String POLICY_SCHEMA =
            "zeroj-groth16-authenticated-state-transition-validator-v1";
    public static final String DEPLOYMENT_SCHEMA =
            "zeroj-groth16-authenticated-state-deployment-v2";
    public static final String VALIDATOR_TEMPLATE_ID =
            "zeroj-groth16-authenticated-state-transition-validator-v1";
    public static final String COMPILER_PROFILE = "julc-0.1.0-pre14/plutus-v3";
    public static final String STATE_TOKEN_SUPPLY_INVARIANT =
            "externally-attested-one-shot-policy-total-supply-one";

    private static final byte PLUTUS_V3_LANGUAGE_TAG = 3;
    private static final byte[] RELEASE_DOMAIN =
            (POLICY_SCHEMA + "\0").getBytes(StandardCharsets.US_ASCII);
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Set<AuthenticatedStateCircuitManifest.Operation> TWO_ROOT_OPERATIONS =
            Set.of(
                    AuthenticatedStateCircuitManifest.Operation.VALUE_UPDATE,
                    AuthenticatedStateCircuitManifest.Operation.INSERT_EMPTY,
                    AuthenticatedStateCircuitManifest.Operation.INSERT_DIFFERENT_LEAF,
                    AuthenticatedStateCircuitManifest.Operation.DELETE);

    private Groth16AuthenticatedStateTransitionScriptFactory() {}

    /**
     * Applies a reviewed template only when its encoded UPLC digest matches the release-time
     * expectation. The expected digest must come from the audited build/release configuration.
     */
    public static AppliedScript apply(
            Program validatorTemplate,
            String expectedUnappliedValidatorSha256,
            String expectedCircuitManifestSha256,
            AuthenticatedStateCircuitManifest circuitManifest,
            String exactCircuitFingerprint,
            SnarkjsToCardano.VkCompressed verificationKey,
            byte[] statePolicyId,
            byte[] stateTokenName,
            byte[] authorizedSigner,
            StateTokenGenesisAttestation stateTokenGenesis) {
        Objects.requireNonNull(validatorTemplate, "validatorTemplate");
        Objects.requireNonNull(circuitManifest, "circuitManifest");
        Objects.requireNonNull(exactCircuitFingerprint, "exactCircuitFingerprint");
        Objects.requireNonNull(stateTokenGenesis, "stateTokenGenesis");
        requireSha("expectedUnappliedValidatorSha256", expectedUnappliedValidatorSha256);
        requireSha("expectedCircuitManifestSha256", expectedCircuitManifestSha256);

        // Snapshot every caller-owned byte array before validating or applying it. All subsequent
        // identity and script operations use only these snapshots.
        SnarkjsToCardano.VkCompressed key = snapshot(verificationKey);
        byte[] policyId = snapshot("statePolicyId", statePolicyId);
        byte[] tokenName = snapshot("stateTokenName", stateTokenName);
        byte[] signer = snapshot("authorizedSigner", authorizedSigner);
        requireLength("statePolicyId", policyId, 28);
        requireRange("stateTokenName", tokenName, 0, 32);
        requireLength("authorizedSigner", signer, 28);

        byte[] unappliedValidator = UplcFlatEncoder.encodeProgram(validatorTemplate);
        String unappliedValidatorSha256 = sha256(unappliedValidator);
        if (!unappliedValidatorSha256.equals(expectedUnappliedValidatorSha256)) {
            throw new IllegalArgumentException(
                    "validator template does not match the audited unapplied validator digest");
        }
        if (!circuitManifest.canonicalSha256().equals(expectedCircuitManifestSha256)) {
            throw new IllegalArgumentException(
                    "circuit manifest does not match the audited release manifest digest");
        }
        if (!TWO_ROOT_OPERATIONS.contains(circuitManifest.operation())
                || circuitManifest.publicInputs().size() != 2
                || !"oldRoot".equals(circuitManifest.publicInputs().get(0).name())
                || !"newRoot".equals(circuitManifest.publicInputs().get(1).name())) {
            throw new IllegalArgumentException(
                    "representative transition validator requires an oldRoot/newRoot p2 operation");
        }
        String expectedFingerprint = circuitManifest.dimensionFingerprint()
                + "-r" + circuitManifest.r1csSha256();
        if (!expectedFingerprint.equals(exactCircuitFingerprint)) {
            throw new IllegalArgumentException(
                    "exact circuit fingerprint does not match the circuit manifest");
        }
        byte[] verificationKeyBytes = Groth16VerificationKeyCodec.encode(key);
        if (!sha256(verificationKeyBytes).equals(circuitManifest.verificationKeySha256())) {
            throw new IllegalArgumentException(
                    "verification key does not match the circuit manifest");
        }
        if (key.ic().size() != 3) {
            throw new IllegalArgumentException("two public inputs require exactly three VK IC points");
        }

        byte[] releaseId = releaseId(
                circuitManifest, exactCircuitFingerprint, unappliedValidatorSha256,
                policyId, tokenName, signer, stateTokenGenesis);
        List<PlutusData> ic = new ArrayList<>(key.ic().size());
        key.ic().forEach(point -> ic.add(PlutusData.bytes(point)));
        Program applied = validatorTemplate.applyParams(
                PlutusData.bytes(key.alpha()),
                PlutusData.bytes(key.beta()),
                PlutusData.bytes(key.gamma()),
                PlutusData.bytes(key.delta()),
                PlutusData.list(ic.toArray(PlutusData[]::new)),
                PlutusData.bytes(policyId),
                PlutusData.bytes(tokenName),
                PlutusData.bytes(signer),
                PlutusData.bytes(releaseId));
        byte[] flatProgram = UplcFlatEncoder.encodeProgram(applied);
        return new AppliedScript(
                applied,
                flatProgram,
                releaseId,
                circuitManifest,
                exactCircuitFingerprint,
                unappliedValidatorSha256,
                policyId,
                tokenName,
                signer,
                stateTokenGenesis);
    }

    /** SHA-256 of the exact encoded, unapplied UPLC template. */
    public static String unappliedValidatorSha256(Program validatorTemplate) {
        Objects.requireNonNull(validatorTemplate, "validatorTemplate");
        return sha256(UplcFlatEncoder.encodeProgram(validatorTemplate));
    }

    private static byte[] releaseId(
            AuthenticatedStateCircuitManifest circuitManifest,
            String exactCircuitFingerprint,
            String unappliedValidatorSha256,
            byte[] statePolicyId,
            byte[] stateTokenName,
            byte[] authorizedSigner,
            StateTokenGenesisAttestation stateTokenGenesis) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(RELEASE_DOMAIN);
            update(digest, circuitManifest.canonicalJsonBytes());
            update(digest, exactCircuitFingerprint.getBytes(StandardCharsets.US_ASCII));
            update(digest, VALIDATOR_TEMPLATE_ID.getBytes(StandardCharsets.US_ASCII));
            update(digest, COMPILER_PROFILE.getBytes(StandardCharsets.US_ASCII));
            update(digest, HexFormat.of().parseHex(unappliedValidatorSha256));
            update(digest, statePolicyId);
            update(digest, stateTokenName);
            update(digest, authorizedSigner);
            update(digest, stateTokenGenesis.canonicalBytes());
            return digest.digest();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static SnarkjsToCardano.VkCompressed snapshot(
            SnarkjsToCardano.VkCompressed source) {
        Objects.requireNonNull(source, "verificationKey");
        List<byte[]> ic = Objects.requireNonNull(source.ic(), "verificationKey.ic").stream()
                .map(point -> snapshot("verificationKey.ic point", point))
                .toList();
        return new SnarkjsToCardano.VkCompressed(
                snapshot("verificationKey.alpha", source.alpha()),
                snapshot("verificationKey.beta", source.beta()),
                snapshot("verificationKey.gamma", source.gamma()),
                snapshot("verificationKey.delta", source.delta()),
                ic);
    }

    private static byte[] snapshot(String name, byte[] value) {
        return Objects.requireNonNull(value, name).clone();
    }

    private static void update(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void requireSha(String name, String value) {
        if (value == null || !SHA256.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be lowercase SHA-256 hex");
        }
    }

    private static void requireLength(String name, byte[] value, int length) {
        requireRange(name, value, length, length);
    }

    private static void requireRange(String name, byte[] value, int minimum, int maximum) {
        Objects.requireNonNull(value, name);
        if (value.length < minimum || value.length > maximum) {
            throw new IllegalArgumentException(
                    name + " length must be in [" + minimum + ", " + maximum + "]");
        }
    }

    /** Canonical networks supported by the deployment gate. */
    public enum CardanoNetwork {
        PREVIEW("preview", 0, 2L),
        PREPROD("preprod", 0, 1L),
        MAINNET("mainnet", 1, null);

        private final String label;
        private final int networkId;
        private final Long networkMagic;

        CardanoNetwork(String label, int networkId, Long networkMagic) {
            this.label = label;
            this.networkId = networkId;
            this.networkMagic = networkMagic;
        }

        public String label() { return label; }
        public int networkId() { return networkId; }
        public Long networkMagic() { return networkMagic; }
    }

    /**
     * External evidence that the state token was created by a one-shot policy with total supply
     * one. The validator can enforce conservation only within the transaction; it cannot prove
     * global supply or that the minting policy can never mint again.
     */
    public record StateTokenGenesisAttestation(
            String genesisTransactionId,
            int genesisOutputIndex,
            String evidenceSha256) {
        public StateTokenGenesisAttestation {
            requireSha("genesisTransactionId", genesisTransactionId);
            if (genesisOutputIndex < 0) {
                throw new IllegalArgumentException("genesisOutputIndex must be non-negative");
            }
            requireSha("evidenceSha256", evidenceSha256);
        }

        private byte[] canonicalBytes() {
            ByteBuffer output = ByteBuffer.allocate(32 + Integer.BYTES + 32);
            output.put(HexFormat.of().parseHex(genesisTransactionId));
            output.putInt(genesisOutputIndex);
            output.put(HexFormat.of().parseHex(evidenceSha256));
            return output.array();
        }

        public String genesisReference() {
            return genesisTransactionId + "#" + genesisOutputIndex;
        }
    }

    public static final class AppliedScript {
        private final Program program;
        private final byte[] flatProgram;
        private final byte[] releaseId;
        private final AuthenticatedStateCircuitManifest circuitManifest;
        private final String exactCircuitFingerprint;
        private final String unappliedValidatorSha256;
        private final byte[] statePolicyId;
        private final byte[] stateTokenName;
        private final byte[] authorizedSigner;
        private final StateTokenGenesisAttestation stateTokenGenesis;

        private AppliedScript(
                Program program,
                byte[] flatProgram,
                byte[] releaseId,
                AuthenticatedStateCircuitManifest circuitManifest,
                String exactCircuitFingerprint,
                String unappliedValidatorSha256,
                byte[] statePolicyId,
                byte[] stateTokenName,
                byte[] authorizedSigner,
                StateTokenGenesisAttestation stateTokenGenesis) {
            this.program = program;
            this.flatProgram = flatProgram.clone();
            this.releaseId = releaseId.clone();
            this.circuitManifest = circuitManifest;
            this.exactCircuitFingerprint = exactCircuitFingerprint;
            this.unappliedValidatorSha256 = unappliedValidatorSha256;
            this.statePolicyId = statePolicyId.clone();
            this.stateTokenName = stateTokenName.clone();
            this.authorizedSigner = authorizedSigner.clone();
            this.stateTokenGenesis = stateTokenGenesis;
        }

        public Program program() { return program; }
        public byte[] flatProgram() { return flatProgram.clone(); }
        public String unappliedValidatorSha256() { return unappliedValidatorSha256; }
        public String appliedValidatorSha256() { return sha256(flatProgram); }
        public byte[] releaseId() { return releaseId.clone(); }
        public String releaseIdHex() { return HexFormat.of().formatHex(releaseId); }

        /**
         * Cardano Plutus V3 script hash: BLAKE2b-224 over language tag {@code 0x03} followed by
         * the raw flat-encoded program bytes. The value is derived internally from this script.
         */
        public byte[] cardanoScriptHash() {
            byte[] taggedProgram = new byte[flatProgram.length + 1];
            taggedProgram[0] = PLUTUS_V3_LANGUAGE_TAG;
            System.arraycopy(flatProgram, 0, taggedProgram, 1, flatProgram.length);
            return Blake2bUtil.blake2bHash224(taggedProgram);
        }

        public String cardanoScriptHashHex() {
            return HexFormat.of().formatHex(cardanoScriptHash());
        }

        /** Produces a deployment identity using only a canonical, typed Cardano network. */
        public DeploymentManifest deploymentManifest(CardanoNetwork network) {
            Objects.requireNonNull(network, "network");
            boolean productionApproved = circuitManifest.setupProvenance().productionApproved();
            if (network == CardanoNetwork.MAINNET && !productionApproved) {
                throw new IllegalStateException(
                        "benchmark/non-production circuit manifest cannot create a mainnet deployment");
            }
            return new DeploymentManifest(
                    DEPLOYMENT_SCHEMA,
                    releaseIdHex(),
                    circuitManifest.canonicalSha256(),
                    circuitManifest.templateId(),
                    circuitManifest.structureProfile(),
                    circuitManifest.operation().slug(),
                    exactCircuitFingerprint,
                    circuitManifest.verificationKeySha256(),
                    VALIDATOR_TEMPLATE_ID,
                    COMPILER_PROFILE,
                    unappliedValidatorSha256,
                    appliedValidatorSha256(),
                    cardanoScriptHashHex(),
                    HexFormat.of().formatHex(statePolicyId),
                    HexFormat.of().formatHex(stateTokenName),
                    HexFormat.of().formatHex(authorizedSigner),
                    STATE_TOKEN_SUPPLY_INVARIANT,
                    stateTokenGenesis.genesisReference(),
                    stateTokenGenesis.evidenceSha256(),
                    network.label(),
                    network.networkId(),
                    network.networkMagic(),
                    productionApproved);
        }
    }

    public record DeploymentManifest(
            String schema,
            String releaseId,
            String circuitManifestSha256,
            String templateId,
            String structureProfile,
            String operation,
            String exactCircuitFingerprint,
            String verificationKeySha256,
            String validatorTemplateId,
            String compilerProfile,
            String unappliedValidatorSha256,
            String appliedValidatorSha256,
            String cardanoScriptHash,
            String statePolicyId,
            String stateTokenName,
            String authorizedSigner,
            String stateTokenSupplyInvariant,
            String stateTokenGenesisReference,
            String stateTokenGenesisEvidenceSha256,
            String network,
            int networkId,
            Long networkMagic,
            boolean productionApproved) {

        public Map<String, Object> toJsonModel() {
            Map<String, Object> model = new LinkedHashMap<>();
            model.put("schema", schema);
            model.put("releaseId", releaseId);
            model.put("circuitManifestSha256", circuitManifestSha256);
            model.put("templateId", templateId);
            model.put("structureProfile", structureProfile);
            model.put("operation", operation);
            model.put("exactCircuitFingerprint", exactCircuitFingerprint);
            model.put("verificationKeySha256", verificationKeySha256);
            model.put("validatorTemplateId", validatorTemplateId);
            model.put("compilerProfile", compilerProfile);
            model.put("unappliedValidatorSha256", unappliedValidatorSha256);
            model.put("appliedValidatorSha256", appliedValidatorSha256);
            model.put("cardanoScriptHash", cardanoScriptHash);
            model.put("statePolicyId", statePolicyId);
            model.put("stateTokenName", stateTokenName);
            model.put("authorizedSigner", authorizedSigner);
            model.put("stateTokenSupplyInvariant", stateTokenSupplyInvariant);
            model.put("stateTokenGenesisReference", stateTokenGenesisReference);
            model.put("stateTokenGenesisEvidenceSha256", stateTokenGenesisEvidenceSha256);
            model.put("network", network);
            model.put("networkId", networkId);
            if (networkMagic != null) model.put("networkMagic", networkMagic);
            model.put("productionApproved", productionApproved);
            return java.util.Collections.unmodifiableMap(model);
        }
    }
}
