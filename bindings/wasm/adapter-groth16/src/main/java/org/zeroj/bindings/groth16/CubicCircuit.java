package org.zeroj.bindings.groth16;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.bindings.common.Boundary;

/** Tutorial relation y = x^3 + x + 5 in BLS12-381 Fr. x is private; y is public. */
public final class CubicCircuit implements CompiledCircuit {
    public String id() { return "tutorial-cubic-bls12381-v1"; }
    public int numWires() { return 5; }
    public int numPublic() { return 1; }
    public List<R1CSConstraint> constraints() {
        var one = BigInteger.ONE;
        return List.of(new R1CSConstraint(Map.of(2,one),Map.of(2,one),Map.of(3,one)),
                new R1CSConstraint(Map.of(3,one),Map.of(2,one),Map.of(4,one)),
                new R1CSConstraint(Map.of(4,one,2,one,0,BigInteger.valueOf(5)),Map.of(0,one),Map.of(1,one)));
    }
    public BigInteger[] witness(JsonNode input) {
        Boundary.fields(input,"x");
        var x = Boundary.scalar(input,"x",Groth16VerifierAdapter.FR);
        var x2 = x.multiply(x).mod(Groth16VerifierAdapter.FR);
        var x3 = x2.multiply(x).mod(Groth16VerifierAdapter.FR);
        return new BigInteger[]{BigInteger.ONE,x3.add(x).add(BigInteger.valueOf(5)).mod(Groth16VerifierAdapter.FR),x,x2,x3};
    }
}
