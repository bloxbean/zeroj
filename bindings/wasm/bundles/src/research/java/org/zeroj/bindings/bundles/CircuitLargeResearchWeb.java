package org.zeroj.bindings.bundles;

import java.util.Map;
import org.zeroj.bindings.circuit.CircuitAdapter;
import org.zeroj.bindings.circuit.CircuitKeyProfile;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;

/** Explicit resource experiment. No npm release; default image uses CircuitWeb. */
public final class CircuitLargeResearchWeb {
    public static void main(String[] args) {
        WebBridge.start(Map.of("circuit", new CircuitAdapter(CircuitKeyProfile.RESEARCH_MERKLE),
                "groth16-verifier", new Groth16VerifierAdapter()));
    }
}
