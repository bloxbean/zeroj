package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.groth16.*;
public final class ProverWeb {
    public static void main(String[] args) {
        var cubic = new CubicCircuit();
        WebBridge.start(Map.of("groth16-prover",new Groth16ProverAdapter(Map.of(cubic.id(),cubic))));
    }
}
