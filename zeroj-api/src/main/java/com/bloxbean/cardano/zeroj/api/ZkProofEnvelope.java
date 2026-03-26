package com.bloxbean.cardano.zeroj.api;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The generic ZK proof container — the core data type of ZeroJ.
 *
 * <p>A proof envelope wraps a cryptographic proof together with all metadata needed
 * for verification: the proof system, curve, circuit identifier, public inputs,
 * and a reference to the verification key.</p>
 *
 * <p>All instances are immutable. Use {@link Builder} to construct.</p>
 */
public final class ZkProofEnvelope {

    private static final int CURRENT_VERSION = 1;

    private final ProofSystemId proofSystem;
    private final CurveId curve;
    private final CircuitId circuitId;
    private final byte[] proofBytes;
    private final PublicInputs publicInputs;
    private final VerificationKeyRef vkRef;
    private final int version;
    private final String domainTag;
    private final Map<String, String> metadata;

    // optional fields
    private final String proofFormat;
    private final String proofUri;
    private final byte[] proofHash;
    private final Long createdAt;
    private final String producerId;

    private ZkProofEnvelope(Builder b) {
        this.proofSystem = Objects.requireNonNull(b.proofSystem, "proofSystem is required");
        this.curve = Objects.requireNonNull(b.curve, "curve is required");
        this.circuitId = Objects.requireNonNull(b.circuitId, "circuitId is required");
        this.proofBytes = Objects.requireNonNull(b.proofBytes, "proofBytes is required").clone();
        if (this.proofBytes.length == 0) {
            throw new IllegalArgumentException("proofBytes must not be empty");
        }
        this.publicInputs = Objects.requireNonNull(b.publicInputs, "publicInputs is required");
        this.vkRef = Objects.requireNonNull(b.vkRef, "vkRef is required");
        this.version = b.version;
        this.domainTag = b.domainTag != null ? b.domainTag : "";
        this.metadata = b.metadata != null ? Map.copyOf(b.metadata) : Map.of();

        this.proofFormat = b.proofFormat;
        this.proofUri = b.proofUri;
        this.proofHash = b.proofHash != null ? b.proofHash.clone() : null;
        this.createdAt = b.createdAt;
        this.producerId = b.producerId;
    }

    // --- Getters ---

    public ProofSystemId proofSystem() { return proofSystem; }
    public CurveId curve() { return curve; }
    public CircuitId circuitId() { return circuitId; }
    public byte[] proofBytes() { return proofBytes.clone(); }
    public PublicInputs publicInputs() { return publicInputs; }
    public VerificationKeyRef vkRef() { return vkRef; }
    public int version() { return version; }
    public String domainTag() { return domainTag; }
    public Map<String, String> metadata() { return metadata; }

    public Optional<String> proofFormat() { return Optional.ofNullable(proofFormat); }
    public Optional<String> proofUri() { return Optional.ofNullable(proofUri); }
    public Optional<byte[]> proofHash() { return proofHash != null ? Optional.of(proofHash.clone()) : Optional.empty(); }
    public Optional<Long> createdAt() { return Optional.ofNullable(createdAt); }
    public Optional<String> producerId() { return Optional.ofNullable(producerId); }

    /**
     * The current envelope format version.
     */
    public static int currentVersion() {
        return CURRENT_VERSION;
    }

    // --- Builder ---

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private ProofSystemId proofSystem;
        private CurveId curve;
        private CircuitId circuitId;
        private byte[] proofBytes;
        private PublicInputs publicInputs;
        private VerificationKeyRef vkRef;
        private int version = CURRENT_VERSION;
        private String domainTag;
        private Map<String, String> metadata;
        private String proofFormat;
        private String proofUri;
        private byte[] proofHash;
        private Long createdAt;
        private String producerId;

        private Builder() {}

        public Builder proofSystem(ProofSystemId proofSystem) { this.proofSystem = proofSystem; return this; }
        public Builder curve(CurveId curve) { this.curve = curve; return this; }
        public Builder circuitId(CircuitId circuitId) { this.circuitId = circuitId; return this; }
        public Builder proofBytes(byte[] proofBytes) { this.proofBytes = proofBytes; return this; }
        public Builder publicInputs(PublicInputs publicInputs) { this.publicInputs = publicInputs; return this; }
        public Builder vkRef(VerificationKeyRef vkRef) { this.vkRef = vkRef; return this; }
        public Builder version(int version) { this.version = version; return this; }
        public Builder domainTag(String domainTag) { this.domainTag = domainTag; return this; }
        public Builder metadata(Map<String, String> metadata) { this.metadata = metadata; return this; }
        public Builder proofFormat(String proofFormat) { this.proofFormat = proofFormat; return this; }
        public Builder proofUri(String proofUri) { this.proofUri = proofUri; return this; }
        public Builder proofHash(byte[] proofHash) { this.proofHash = proofHash; return this; }
        public Builder createdAt(Long createdAt) { this.createdAt = createdAt; return this; }
        public Builder producerId(String producerId) { this.producerId = producerId; return this; }

        public ZkProofEnvelope build() {
            return new ZkProofEnvelope(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ZkProofEnvelope e)) return false;
        return version == e.version
                && proofSystem == e.proofSystem
                && curve == e.curve
                && circuitId.equals(e.circuitId)
                && Arrays.equals(proofBytes, e.proofBytes)
                && publicInputs.equals(e.publicInputs)
                && vkRef.equals(e.vkRef)
                && Objects.equals(domainTag, e.domainTag)
                && metadata.equals(e.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(proofSystem, curve, circuitId, Arrays.hashCode(proofBytes),
                publicInputs, vkRef, version, domainTag, metadata);
    }

    @Override
    public String toString() {
        return "ZkProofEnvelope[" +
                "proofSystem=" + proofSystem +
                ", curve=" + curve +
                ", circuitId=" + circuitId +
                ", proofBytes=" + proofBytes.length + " bytes" +
                ", publicInputs=" + publicInputs.size() + " elements" +
                ", version=" + version +
                "]";
    }
}
