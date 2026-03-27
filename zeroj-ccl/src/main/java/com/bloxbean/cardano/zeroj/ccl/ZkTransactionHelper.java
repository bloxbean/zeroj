package com.bloxbean.cardano.zeroj.ccl;

import com.bloxbean.cardano.client.metadata.Metadata;
import com.bloxbean.cardano.client.metadata.cbor.CBORMetadata;
import com.bloxbean.cardano.client.metadata.cbor.CBORMetadataMap;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.cardano.AnchorMetadataEncoder;
import com.bloxbean.cardano.zeroj.cardano.AnchorPattern;
import com.bloxbean.cardano.zeroj.cardano.ProofAnchor;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Fluent helper for adding ZK proof anchors to Cardano transactions via CCL.
 *
 * <p>Creates CIP-10 compatible metadata that can be attached to any CCL transaction.
 * The metadata uses the ZeroJ label ({@value AnchorMetadataEncoder#DEFAULT_LABEL}).</p>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * Metadata metadata = ZkTransactionHelper.forAnchor(proofAnchor)
 *     .withLabel(7270)
 *     .buildMetadata();
 *
 * // Attach to CCL QuickTx or TransactionBuilder
 * }</pre>
 */
public final class ZkTransactionHelper {

    private final ProofAnchor anchor;
    private long label = AnchorMetadataEncoder.DEFAULT_LABEL;

    private ZkTransactionHelper(ProofAnchor anchor) {
        this.anchor = Objects.requireNonNull(anchor, "anchor required");
    }

    /**
     * Start building transaction metadata for a proof anchor.
     */
    public static ZkTransactionHelper forAnchor(ProofAnchor anchor) {
        return new ZkTransactionHelper(anchor);
    }

    /**
     * Create a PROOF_HASH_ONLY anchor from a proof hash.
     */
    public static ZkTransactionHelper anchorProofHash(byte[] proofHash) {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.PROOF_HASH_ONLY)
                .proofHash(proofHash)
                .build();
        return new ZkTransactionHelper(anchor);
    }

    /**
     * Create a STATE_ROOT_AND_PROOF_HASH anchor.
     */
    public static ZkTransactionHelper anchorStateRoot(byte[] stateRoot, byte[] proofHash) {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.STATE_ROOT_AND_PROOF_HASH)
                .proofHash(proofHash)
                .stateRoot(stateRoot)
                .build();
        return new ZkTransactionHelper(anchor);
    }

    /**
     * Create a FULL_VERIFICATION_REF anchor.
     */
    public static ZkTransactionHelper anchorFullRef(byte[] stateRoot, byte[] proofHash,
                                                     String circuitId, byte[] vkHash) {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.FULL_VERIFICATION_REF)
                .proofHash(proofHash)
                .stateRoot(stateRoot)
                .circuitId(circuitId)
                .vkHash(vkHash)
                .build();
        return new ZkTransactionHelper(anchor);
    }

    /**
     * Create a NULLIFIER_COMMITMENT anchor.
     */
    public static ZkTransactionHelper anchorNullifier(byte[] nullifier, byte[] proofHash) {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.NULLIFIER_COMMITMENT)
                .proofHash(proofHash)
                .nullifier(nullifier)
                .build();
        return new ZkTransactionHelper(anchor);
    }

    /**
     * Override the CIP-10 metadata label (default: {@value AnchorMetadataEncoder#DEFAULT_LABEL}).
     */
    public ZkTransactionHelper withLabel(long label) {
        this.label = label;
        return this;
    }

    /**
     * Build CCL {@link Metadata} for attaching to a transaction.
     *
     * <p>The metadata structure is: {label: {0: pattern, 1: proofHash, ...}}</p>
     */
    public Metadata buildMetadata() {
        var metadata = new CBORMetadata();
        var map = new CBORMetadataMap();

        // Pattern
        map.put(BigInteger.ZERO, BigInteger.valueOf(anchor.pattern().ordinal()));

        // Proof hash (always present)
        map.put(BigInteger.ONE, anchor.proofHash());

        // Optional fields
        anchor.stateRoot().ifPresent(root -> map.put(BigInteger.TWO, root));
        anchor.circuitId().ifPresent(id -> map.put(BigInteger.valueOf(3), id));
        anchor.vkHash().ifPresent(hash -> map.put(BigInteger.valueOf(4), hash));
        anchor.nullifier().ifPresent(n -> map.put(BigInteger.valueOf(5), n));
        anchor.appId().ifPresent(id -> map.put(BigInteger.valueOf(6), id));

        metadata.put(BigInteger.valueOf(label), map);
        return metadata;
    }

    /**
     * Validate the proof before building anchor metadata.
     * <p>
     * Verifies the ZK proof cryptographically, then builds the metadata only if valid.
     * Use this when you want the CCL layer to enforce proof validity before anchoring.
     *
     * @param envelope     the proof envelope to verify
     * @param material     the verification key material
     * @param orchestrator the verifier orchestrator
     * @return the metadata if proof is valid
     * @throws IllegalStateException if proof verification fails
     */
    public Metadata validateAndBuildMetadata(ZkProofEnvelope envelope, VerificationMaterial material,
                                              VerifierOrchestrator orchestrator) {
        VerificationResult result = orchestrator.verify(envelope, material);
        if (!result.proofValid()) {
            throw new IllegalStateException("Proof verification failed before anchoring: "
                    + result.message().orElse("invalid proof"));
        }
        return buildMetadata();
    }

    /**
     * Get the underlying proof anchor.
     */
    public ProofAnchor anchor() {
        return anchor;
    }
}
