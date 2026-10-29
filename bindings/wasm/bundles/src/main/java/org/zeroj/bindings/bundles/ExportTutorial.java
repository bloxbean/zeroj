package org.zeroj.bindings.bundles;
import java.nio.file.Files;
import java.nio.file.Path;
import org.zeroj.bindings.groth16.CubicCircuit;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.crypto.groth16.R1csExporter;
/** JVM-only fixture preparation; not referenced by consumer image entry points. */
public final class ExportTutorial {
    public static void main(String[] args) throws Exception {
        var dir=Path.of(args[0]); Files.createDirectories(dir);
        var c=new CubicCircuit();
        R1csExporter.export(c.constraints(),c.numWires(),c.numPublic(),dir.resolve("circuit.r1cs"));
        Files.writeString(dir.resolve("circuit.json"),Boundary.object().put("circuit",c.id()).put("fingerprint",c.fingerprint()).toPrettyString());
    }
}
