package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;
public final class VerifierWeb {
    public static void main(String[] args) { WebBridge.start(Map.of("groth16-verifier",new Groth16VerifierAdapter())); }
}
