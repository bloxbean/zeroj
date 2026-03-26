package com.bloxbean.cardano.zeroj.yaci.protocol;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A proof-backed state transition submission to the Yaci network.
 *
 * <p>This is the wire-level message that a submitter sends to Yaci nodes.
 * Nodes validate it through the 6-stage ingestion pipeline.</p>
 *
 * <p>All fields are immutable. Byte arrays are defensively copied.</p>
 */
public final class AppProofSubmission {

    private final String appId;
    private final ProofSystemId proofSystem;
    private final CurveId curve;
    private final String circuitId;
    private final String circuitVersion;
    private final byte[] prevStateRoot;
    private final byte[] newStateRoot;
    private final List<BigInteger> publicInputs;
    private final byte[] proofBytes;
    private final byte[] vkHash;
    private final String submitterId;
    private final byte[] submitterSignature;
    private final long sequence;
    private final byte[] nullifier; // nullable
    private final Map<String, String> metadata;

    private AppProofSubmission(Builder b) {
        this.appId = Objects.requireNonNull(b.appId, "appId required");
        this.proofSystem = Objects.requireNonNull(b.proofSystem, "proofSystem required");
        this.curve = Objects.requireNonNull(b.curve, "curve required");
        this.circuitId = Objects.requireNonNull(b.circuitId, "circuitId required");
        this.circuitVersion = Objects.requireNonNull(b.circuitVersion, "circuitVersion required");
        this.prevStateRoot = Objects.requireNonNull(b.prevStateRoot, "prevStateRoot required").clone();
        this.newStateRoot = Objects.requireNonNull(b.newStateRoot, "newStateRoot required").clone();
        this.publicInputs = List.copyOf(Objects.requireNonNull(b.publicInputs, "publicInputs required"));
        this.proofBytes = Objects.requireNonNull(b.proofBytes, "proofBytes required").clone();
        if (this.proofBytes.length == 0) throw new IllegalArgumentException("proofBytes must not be empty");
        this.vkHash = Objects.requireNonNull(b.vkHash, "vkHash required").clone();
        if (this.vkHash.length != 32) throw new IllegalArgumentException("vkHash must be 32 bytes");
        this.submitterId = Objects.requireNonNull(b.submitterId, "submitterId required");
        this.submitterSignature = Objects.requireNonNull(b.submitterSignature, "submitterSignature required").clone();
        this.sequence = b.sequence;
        if (this.sequence < 0) throw new IllegalArgumentException("sequence must be >= 0");
        this.nullifier = b.nullifier != null ? b.nullifier.clone() : null;
        this.metadata = b.metadata != null ? Map.copyOf(b.metadata) : Map.of();
    }

    // --- Getters (defensive copies for byte arrays) ---

    public String appId() { return appId; }
    public ProofSystemId proofSystem() { return proofSystem; }
    public CurveId curve() { return curve; }
    public String circuitId() { return circuitId; }
    public String circuitVersion() { return circuitVersion; }
    public byte[] prevStateRoot() { return prevStateRoot.clone(); }
    public byte[] newStateRoot() { return newStateRoot.clone(); }
    public List<BigInteger> publicInputs() { return publicInputs; }
    public byte[] proofBytes() { return proofBytes.clone(); }
    public byte[] vkHash() { return vkHash.clone(); }
    public String submitterId() { return submitterId; }
    public byte[] submitterSignature() { return submitterSignature.clone(); }
    public long sequence() { return sequence; }
    public byte[] nullifier() { return nullifier != null ? nullifier.clone() : null; }
    public Map<String, String> metadata() { return metadata; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String appId;
        private ProofSystemId proofSystem;
        private CurveId curve;
        private String circuitId;
        private String circuitVersion;
        private byte[] prevStateRoot;
        private byte[] newStateRoot;
        private List<BigInteger> publicInputs;
        private byte[] proofBytes;
        private byte[] vkHash;
        private String submitterId;
        private byte[] submitterSignature;
        private long sequence;
        private byte[] nullifier;
        private Map<String, String> metadata;

        public Builder appId(String v) { this.appId = v; return this; }
        public Builder proofSystem(ProofSystemId v) { this.proofSystem = v; return this; }
        public Builder curve(CurveId v) { this.curve = v; return this; }
        public Builder circuitId(String v) { this.circuitId = v; return this; }
        public Builder circuitVersion(String v) { this.circuitVersion = v; return this; }
        public Builder prevStateRoot(byte[] v) { this.prevStateRoot = v; return this; }
        public Builder newStateRoot(byte[] v) { this.newStateRoot = v; return this; }
        public Builder publicInputs(List<BigInteger> v) { this.publicInputs = v; return this; }
        public Builder proofBytes(byte[] v) { this.proofBytes = v; return this; }
        public Builder vkHash(byte[] v) { this.vkHash = v; return this; }
        public Builder submitterId(String v) { this.submitterId = v; return this; }
        public Builder submitterSignature(byte[] v) { this.submitterSignature = v; return this; }
        public Builder sequence(long v) { this.sequence = v; return this; }
        public Builder nullifier(byte[] v) { this.nullifier = v; return this; }
        public Builder metadata(Map<String, String> v) { this.metadata = v; return this; }

        public AppProofSubmission build() { return new AppProofSubmission(this); }
    }

    @Override
    public String toString() {
        return "AppProofSubmission[app=" + appId + ", circuit=" + circuitId + "/" + circuitVersion
                + ", submitter=" + submitterId + ", seq=" + sequence + "]";
    }
}
