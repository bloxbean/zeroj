package org.zeroj.bindings.circuit;

import org.zeroj.crypto.groth16.ZkeyImporterBLS381;

/** Immutable, Java-selected resource policy. Never selectable through untrusted RPC arguments. */
public enum CircuitKeyProfile {
    STANDARD("circuit-key-v1", 2 * 1024 * 1024, 4096, 4096, 16384),
    /** Opt-in desktop experiment, not a supported npm bundle or a hard heap bound. ADR-0064. */
    RESEARCH_MERKLE("circuit-key-research-merkle-v1", 32 * 1024 * 1024, 65536, 8192, 262144);

    private final String id;
    private final ZkeyImporterBLS381.Limits limits;
    CircuitKeyProfile(String id, int bytes, int wires, int domain, int coefficients) {
        this.id = id;
        this.limits = new ZkeyImporterBLS381.Limits(bytes, wires, domain, coefficients);
    }
    public String id() { return id; }
    public ZkeyImporterBLS381.Limits limits() { return limits; }
    boolean admits(int wires, int publicInputs, int constraints) {
        return wires <= limits.maxWires() && publicInputs <= 64
                && (long) constraints + publicInputs + 1 <= limits.maxDomainSize();
    }
}
