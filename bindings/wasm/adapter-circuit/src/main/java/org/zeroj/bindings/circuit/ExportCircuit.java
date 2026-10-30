package org.zeroj.bindings.circuit;

import java.nio.file.Files;
import java.nio.file.Path;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.crypto.groth16.R1csExporter;

/** Build-time public artifact export. No witness or setup; excluded from consumer images. */
public final class ExportCircuit {
    private ExportCircuit() {}
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("Usage: ExportCircuit recipe.json output-directory");
        Path source = Path.of(args[0]), output = Path.of(args[1]);
        if (Files.size(source) > Boundary.MAX_BYTES) throw Boundary.invalid();
        String recipe = Files.readString(source);
        String encoded = GraphCodec.encode(SymbolicRecipe.expand(recipe));
        var compiled = new CompiledGraph(GraphCodec.decode(encoded));
        var manifest = Boundary.object().put("compiler", GraphCodec.COMPILER).put("field", "bls12-381-fr")
                .put("name", compiled.id()).put("recipeSha256", GraphCodec.hash(recipe))
                .put("graphSha256", GraphCodec.hash(encoded)).put("fingerprint", compiled.fingerprint())
                .put("wires", compiled.numWires()).put("constraints", compiled.constraints().size())
                .put("publicInputs", compiled.numPublic());
        manifest.set("inputs", Boundary.parse(recipe).get("inputs"));
        var pub = manifest.putArray("publicNames");
        compiled.graph.publicInputs().forEach(v -> pub.add(v.name()));
        var sec = manifest.putArray("secretNames");
        compiled.graph.secretInputs().forEach(v -> sec.add(v.name()));
        Files.createDirectories(output);
        Files.writeString(output.resolve("recipe.json"), recipe);
        Files.writeString(output.resolve("graph.json"), encoded);
        R1csExporter.export(compiled.constraints(), compiled.numWires(), compiled.numPublic(), output.resolve("circuit.r1cs"));
        Files.writeString(output.resolve("manifest.json"), manifest.toPrettyString() + "\n");
        System.out.println("Exported public circuit artifacts; ceremony keys must be supplied separately.");
    }
}
