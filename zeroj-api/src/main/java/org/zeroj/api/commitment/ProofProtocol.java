package org.zeroj.api.commitment;

/**
 * The descriptor of one proof protocol over commitments ({@code commitment-profiles-v1} §5, §2.4
 * item 5; ADR-0061 D7a).
 *
 * <p>It names the protocol, the one commitment profile it consumes, and the generator set it uses.
 * Like {@link CommitmentProfile}, it is configuration, not provenance: the protocol's cryptographic
 * definition lives in its specification.
 *
 * <p>Every proof protocol is built in. There is no public factory and no {@code define} for proof
 * protocols in v1. The descriptors are created while this class is initialised, and their
 * identifiers are seeded into the shared registry set by {@link CommitmentProfile}'s own
 * initialisation, so a {@link CommitmentProfile#define} of a protocol or generator-set identifier is
 * always rejected, even as the first call in a fresh class loader. <b>Descriptors compare by
 * identity</b>: every check uses {@code ==}, never {@code equals}.
 *
 * <p>A descriptor for a protocol the registry still lists as {@code reserved} is not admission
 * (spec §2.3).
 */
public final class ProofProtocol {

    static final ProofProtocol BULLETPROOF_RANGE_BLS12_381_G1_V1 = builtIn("bulletproof-range-bls12-381-g1-v1",
            CommitmentProfile.PEDERSEN_BLS12_381_G1_V1, "bulletproof-bls12-381-g1-gens-v1");

    private final CommitmentProfileId id;
    private final CommitmentProfile consumes;
    private final CommitmentProfileId generatorSetId;

    private ProofProtocol(CommitmentProfileId id, CommitmentProfile consumes, CommitmentProfileId generatorSetId) {
        this.id = id;
        this.consumes = consumes;
        this.generatorSetId = generatorSetId;
    }

    private static ProofProtocol builtIn(String id, CommitmentProfile consumes, String generatorSetId) {
        CommitmentProfileId protocolId = CommitmentProfileId.of(id);
        CommitmentProfileId gensId = CommitmentProfileId.of(generatorSetId);
        // Both identifiers must already be reserved by CommitmentProfile's initialisation, which
        // has run by now: reading consumes forced it.
        if (!CommitmentProfile.RESERVED.contains(protocolId) || !CommitmentProfile.RESERVED.contains(gensId)) {
            throw new IllegalStateException("built-in proof protocol " + id + " is not reserved in CommitmentProfile");
        }
        return new ProofProtocol(protocolId, consumes, gensId);
    }

    /** The protocol identifier. */
    public CommitmentProfileId id() {
        return id;
    }

    /** The one commitment profile whose commitments this protocol proves statements about. */
    public CommitmentProfile consumes() {
        return consumes;
    }

    /** The identifier of the generator set the protocol uses. */
    public CommitmentProfileId generatorSetId() {
        return generatorSetId;
    }

    @Override
    public String toString() {
        return "ProofProtocol[" + id + ", consumes " + consumes.id() + ", generators " + generatorSetId + "]";
    }
}
