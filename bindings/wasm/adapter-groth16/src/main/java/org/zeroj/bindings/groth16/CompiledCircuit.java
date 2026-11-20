package org.zeroj.bindings.groth16;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.List;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.R1CSFlat;
import org.zeroj.crypto.groth16.Groth16Pipeline;

/** Trusted Java code compiled into an image; not an arbitrary JavaScript witness program. */
public interface CompiledCircuit {
    String id();
    int numWires();
    int numPublic();
    List<R1CSConstraint> constraints();
    BigInteger[] witness(JsonNode input);
    default String fingerprint() {
        var flat = R1CSFlat.builder();
        for (var row : constraints()) flat.add(row.a(),row.b(),row.c());
        return new Groth16Pipeline.Compiled(flat.build(),constraints().size(),numWires(),numPublic()).fingerprint();
    }
}
