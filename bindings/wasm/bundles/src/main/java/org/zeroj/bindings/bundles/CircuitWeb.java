package org.zeroj.bindings.bundles;

import java.util.Map;
import org.zeroj.bindings.circuit.CircuitAdapter;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;

/** Selected compiler/gadgets and prover share one Java heap. */
public final class CircuitWeb {
    public static void main(String[] args) {
        WebBridge.start(Map.of("circuit", new CircuitAdapter(), "groth16-verifier", new Groth16VerifierAdapter()));
    }
}
