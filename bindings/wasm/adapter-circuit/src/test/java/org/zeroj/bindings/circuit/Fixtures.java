package org.zeroj.bindings.circuit;

import java.math.BigInteger;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.WitnessCalculator;
import org.zeroj.crypto.groth16.R1csExporter;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/** JVM-only exporter and independent oracle fixture generator; never referenced from Wasm. */
public final class Fixtures {
    static CircuitBuilder circuit(String name) {
        return switch(name) {
            case "multiplier" -> MultiplierCircuit.build();
            case "cubic" -> CubicCircuit.build();
            case "age_check" -> AgeCheckCircuit.build();
            case "sha256_abc" -> Sha256PreimageCircuit.build();
            case "poseidon_opening" -> PoseidonOpeningCircuit.build();
            case "symbolic_select" -> TypedSelectionCircuit.build();
            default -> throw new IllegalArgumentException();
        };
    }
    static ObjectNode inputs(String name) throws Exception {
        var n=GraphCodec.JSON.createObjectNode();
        switch(name) {
            case "multiplier" -> n.put("product","33").put("x","3").put("y","11");
            case "cubic" -> n.put("y","35").put("x","3");
            case "age_check" -> n.put("threshold","18").put("age","21");
            case "symbolic_select" -> n.put("selected","42").put("chooseLeft","1").put("left","42").put("right","7");
            case "poseidon_opening" -> n.put("commitment",PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE,
                    BigInteger.valueOf(42),BigInteger.valueOf(99)).toString()).put("value","42").put("salt","99");
            case "sha256_abc" -> {
                byte[] message={97,98,99};
                byte[] digest=MessageDigest.getInstance("SHA-256").digest(message);
                for(int i=0;i<digest.length;i++) n.put("digest_"+i,Integer.toString(digest[i]&255));
                for(int i=0;i<message.length;i++) n.put("message_"+i,Integer.toString(message[i]&255));
            }
        }
        return n;
    }
    public static void main(String[] args) throws Exception {
        Path out=Path.of(args[0]); Files.createDirectories(out);
        var manifest=GraphCodec.JSON.createArrayNode();
        for(String name:List.of("multiplier","cubic","age_check","sha256_abc","poseidon_opening","symbolic_select")) {
            long t=System.nanoTime(); var original=circuit(name).constraintGraph();
            double buildMs=(System.nanoTime()-t)/1e6;
            t=System.nanoTime(); String encoded=GraphCodec.encode(original); double encodeMs=(System.nanoTime()-t)/1e6;
            t=System.nanoTime(); var decoded=GraphCodec.decode(encoded); double decodeMs=(System.nanoTime()-t)/1e6;
            var direct=new CompiledGraph(original); var portable=new CompiledGraph(decoded);
            if(!direct.fingerprint().equals(portable.fingerprint())) throw new AssertionError("R1CS drift");
            var input=inputs(name); var sourceValues=new LinkedHashMap<String,List<BigInteger>>();
            input.fields().forEachRemaining(e->sourceValues.put(e.getKey(),List.of(new BigInteger(e.getValue().textValue()))));
            var reference=WitnessCalculator.calculate(original,sourceValues,FieldConfig.BLS12_381);
            t=System.nanoTime(); var actual=portable.witness(input); double witnessMs=(System.nanoTime()-t)/1e6;
            if(!Arrays.equals(reference,actual)) throw new AssertionError("Witness drift");
            portable.check(actual);
            Path dir=out.resolve(name); Files.createDirectories(dir);
            Files.writeString(dir.resolve("graph.json"),encoded);
            Files.writeString(dir.resolve("inputs.json"),input.toString());
            var witness=GraphCodec.JSON.createArrayNode(); for(var v:actual) witness.add(v.toString());
            Files.writeString(dir.resolve("witness.json"),witness.toString());
            R1csExporter.export(portable.constraints(),portable.numWires(),portable.numPublic(),dir.resolve("circuit.r1cs"));
            var item=manifest.addObject().put("name",name).put("graphSha256",GraphCodec.hash(encoded))
                    .put("fingerprint",portable.fingerprint()).put("witnessSha256",TestWitness.digest(actual))
                    .put("graphBytes",encoded.length()).put("wires",portable.numWires()).put("gates",decoded.gates().size())
                    .put("constraints",portable.constraints().size()).put("publicInputs",portable.numPublic())
                    .put("buildMs",buildMs).put("encodeMs",encodeMs).put("decodeMs",decodeMs)
                    .put("compileMs",portable.compileMs).put("witnessMs",witnessMs).put("developmentOnly",true);
            var histogram=item.putObject("opcodes");
            for(var gate:decoded.gates()) { String k=gate.getClass().getSimpleName(); histogram.put(k,histogram.path(k).asInt()+1); }
            Arrays.fill(reference,BigInteger.ZERO); Arrays.fill(actual,BigInteger.ZERO);
            System.out.println(item);
        }
        Files.writeString(out.resolve("manifest.json"),manifest.toPrettyString());
    }
}
