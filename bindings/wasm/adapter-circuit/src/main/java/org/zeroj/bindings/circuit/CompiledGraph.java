package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.groth16.CompiledCircuit;
import org.zeroj.circuit.ConstraintGraph;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.WitnessCalculator;
import org.zeroj.circuit.r1cs.R1CSCompiler;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.crypto.groth16.Groth16Pipeline;

public final class CompiledGraph implements CompiledCircuit {
    final ConstraintGraph graph;
    final R1CSConstraintSystem system;
    final String fingerprint;
    final double compileMs;
    CompiledGraph(ConstraintGraph graph) {
        this.graph=graph;
        long start=System.nanoTime();
        system=R1CSCompiler.compile(graph,FieldConfig.BLS12_381);
        compileMs=(System.nanoTime()-start)/1e6;
        fingerprint=new Groth16Pipeline.Compiled(system.flat(),system.numConstraints(),system.numWires(),system.numPublicInputs()).fingerprint();
    }
    public String id() { return graph.name(); }
    public int numWires() { return graph.numWires(); }
    public int numPublic() { return graph.publicInputs().size(); }
    public List<R1CSConstraint> constraints() { return system.constraints(); }
    @Override public String fingerprint() { return fingerprint; }
    public BigInteger[] witness(JsonNode input) {
        var vars=graph.namedVariables();
        Boundary.fields(input,vars.keySet().toArray(String[]::new));
        Map<String,List<BigInteger>> values=new LinkedHashMap<>();
        for (String name:vars.keySet()) values.put(name,List.of(GraphCodec.scalar(Boundary.text(input,name))));
        return WitnessCalculator.calculate(graph,values,FieldConfig.BLS12_381);
    }
    public void check(BigInteger[] witness) {
        if (witness.length!=numWires() || !BigInteger.ONE.equals(witness[0])) throw new IllegalArgumentException("INVALID_WITNESS");
        for (var v:witness) if(v==null || v.signum()<0 || v.compareTo(GraphCodec.FR)>=0) throw new IllegalArgumentException("INVALID_WITNESS");
        for (var c:constraints()) if (!dot(c.a(),witness).multiply(dot(c.b(),witness)).mod(GraphCodec.FR).equals(dot(c.c(),witness)))
            throw new IllegalArgumentException("INVALID_WITNESS");
    }
    private static BigInteger dot(Map<Integer,BigInteger> terms, BigInteger[] w) {
        var sum=BigInteger.ZERO;
        for(var entry:terms.entrySet()) sum=sum.add(w[entry.getKey()].multiply(entry.getValue()));
        return sum.mod(GraphCodec.FR);
    }
}
