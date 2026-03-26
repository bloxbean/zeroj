package com.bloxbean.cardano.zeroj.cardano;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * What gets written to Cardano L1 to anchor a verified ZK proof result.
 *
 * <p>Constructed via {@link ProofAnchor#builder()}. The fields populated depend on
 * the {@link AnchorPattern}.</p>
 */
public final class ProofAnchor {

    private final AnchorPattern pattern;
    private final byte[] proofHash;         // always present (SHA-256 of proof bytes)
    private final byte[] stateRoot;         // for STATE_ROOT_AND_PROOF_HASH, FULL_VERIFICATION_REF
    private final String circuitId;         // for FULL_VERIFICATION_REF
    private final byte[] vkHash;            // for FULL_VERIFICATION_REF
    private final byte[] nullifier;         // for NULLIFIER_COMMITMENT
    private final String appId;             // optional app context

    private ProofAnchor(Builder b) {
        this.pattern = Objects.requireNonNull(b.pattern, "pattern required");
        this.proofHash = Objects.requireNonNull(b.proofHash, "proofHash required").clone();
        if (this.proofHash.length != 32) {
            throw new IllegalArgumentException("proofHash must be 32 bytes");
        }
        this.stateRoot = b.stateRoot != null ? b.stateRoot.clone() : null;
        this.circuitId = b.circuitId;
        this.vkHash = b.vkHash != null ? b.vkHash.clone() : null;
        this.nullifier = b.nullifier != null ? b.nullifier.clone() : null;
        this.appId = b.appId;

        // Validate required fields per pattern
        switch (pattern) {
            case STATE_ROOT_AND_PROOF_HASH -> {
                if (stateRoot == null) throw new IllegalArgumentException("stateRoot required for " + pattern);
            }
            case FULL_VERIFICATION_REF -> {
                if (stateRoot == null) throw new IllegalArgumentException("stateRoot required for " + pattern);
                if (circuitId == null) throw new IllegalArgumentException("circuitId required for " + pattern);
                if (vkHash == null) throw new IllegalArgumentException("vkHash required for " + pattern);
            }
            case NULLIFIER_COMMITMENT -> {
                if (nullifier == null) throw new IllegalArgumentException("nullifier required for " + pattern);
            }
            case PROOF_HASH_ONLY -> { /* proofHash only, already validated */ }
        }
    }

    public AnchorPattern pattern() { return pattern; }
    public byte[] proofHash() { return proofHash.clone(); }
    public Optional<byte[]> stateRoot() { return Optional.ofNullable(stateRoot).map(byte[]::clone); }
    public Optional<String> circuitId() { return Optional.ofNullable(circuitId); }
    public Optional<byte[]> vkHash() { return Optional.ofNullable(vkHash).map(byte[]::clone); }
    public Optional<byte[]> nullifier() { return Optional.ofNullable(nullifier).map(byte[]::clone); }
    public Optional<String> appId() { return Optional.ofNullable(appId); }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private AnchorPattern pattern;
        private byte[] proofHash;
        private byte[] stateRoot;
        private String circuitId;
        private byte[] vkHash;
        private byte[] nullifier;
        private String appId;

        public Builder pattern(AnchorPattern v) { this.pattern = v; return this; }
        public Builder proofHash(byte[] v) { this.proofHash = v; return this; }
        public Builder stateRoot(byte[] v) { this.stateRoot = v; return this; }
        public Builder circuitId(String v) { this.circuitId = v; return this; }
        public Builder vkHash(byte[] v) { this.vkHash = v; return this; }
        public Builder nullifier(byte[] v) { this.nullifier = v; return this; }
        public Builder appId(String v) { this.appId = v; return this; }

        public ProofAnchor build() { return new ProofAnchor(this); }
    }
}
