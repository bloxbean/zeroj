package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.R1csExporter;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;
import com.bloxbean.cardano.zeroj.tools.zkey.ZkeyContributor;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * ZeroJ Groth16 MPC-ceremony CLI (ADR-0031) — picocli-based; a GraalVM native binary is supported
 * (picocli-codegen emits the reflection configs at compile time).
 *
 * <p>Native-image note: {@code contribute} and {@code finalize} are fully native-friendly (pure
 * Java, no dynamic loading) — the commands ceremony <em>contributors</em> run. {@code export-r1cs}
 * loads circuit classes reflectively, so with a native binary the circuit must be compiled into
 * the image; coordinators typically run it on a JVM instead.</p>
 */
@Command(name = "zeroj-ceremony", mixinStandardHelpOptions = true,
        versionProvider = CeremonyCli.ManifestVersion.class,
        description = "Groth16 MPC trusted-setup ceremony tool for ZeroJ circuits. "
                + "Flow: export-r1cs -> snarkjs groth16 setup -> contribute (zeroj-ceremony or snarkjs, any mix) "
                + "-> snarkjs zkey beacon + verify -> finalize. Guide: docs/ceremony/USER-GUIDE.md",
        subcommands = {CeremonyCli.ExportR1cs.class, CeremonyCli.Contribute.class, CeremonyCli.Finalize.class})
public final class CeremonyCli {

    public static void main(String[] args) {
        System.exit(run(args));
    }

    /** Entry point separated from {@link #main} so tests can invoke it in-process. */
    public static int run(String[] args) {
        return new CommandLine(new CeremonyCli())
                .setExecutionExceptionHandler((e, cmd, parseResult) -> {
                    cmd.getErr().println(cmd.getColorScheme().errorText("Error: " + e.getMessage()));
                    return 1;
                })
                .execute(args);
    }

    // ---- export-r1cs ----

    @Command(name = "export-r1cs", mixinStandardHelpOptions = true,
            description = "Compile a ZeroJ circuit and export it to iden3 .r1cs (snarkjs ceremony input).")
    static class ExportR1cs implements Callable<Integer> {

        @Option(names = "--circuit", required = true,
                description = "FQCN of the @ZKCircuit class or its generated *Circuit companion "
                        + "(any class with a static build() returning CircuitBuilder)")
        String circuit;

        @Option(names = "--circuit-jar", description = "Jar containing the compiled circuit classes")
        Path circuitJar;

        @Option(names = "--out", required = true, description = "Output .r1cs file")
        Path out;

        @Override
        public Integer call() throws Exception {
            ClassLoader loader = CeremonyCli.class.getClassLoader();
            if (circuitJar != null) {
                if (!Files.isReadable(circuitJar)) { System.err.println("Cannot read jar: " + circuitJar); return 2; }
                loader = new URLClassLoader(new URL[]{circuitJar.toUri().toURL()}, loader);
            }
            CircuitBuilder builder = loadCircuit(circuit, loader);
            System.out.println("Compiling circuit " + circuit + " (BLS12-381) ...");
            long t0 = System.nanoTime();
            R1CSConstraintSystem r1cs = builder.compileR1CS(CurveId.BLS12_381);
            System.out.printf("  %,d constraints | %,d wires | %d public | %.1fs%n",
                    r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                    (System.nanoTime() - t0) / 1e9);
            R1csExporter.export(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), out);
            System.out.printf("Wrote %s (%,d bytes)%n", out, Files.size(out));
            System.out.println("Next: snarkjs groth16 setup " + out.getFileName() + " <prepared.ptau> key_0000.zkey");
            return 0;
        }
    }

    /** Load {@code fqcn} (or {@code fqcn + "Circuit"}) and call its static {@code build()}. */
    static CircuitBuilder loadCircuit(String fqcn, ClassLoader loader) throws Exception {
        Exception first = null;
        for (String name : new String[]{fqcn, fqcn + "Circuit"}) {
            try {
                Class<?> cls = Class.forName(name, true, loader);
                Method build = cls.getMethod("build");
                Object cb = build.invoke(null);
                if (cb instanceof CircuitBuilder b) return b;
                throw new IllegalArgumentException(name + ".build() does not return a CircuitBuilder");
            } catch (ClassNotFoundException | NoSuchMethodException e) {
                if (first == null) first = e;
            }
        }
        throw new IllegalArgumentException(
                "No class with a static build() -> CircuitBuilder found for '" + fqcn
                        + "' (tried " + fqcn + " and " + fqcn + "Circuit)", first);
    }

    // ---- contribute (Option B: the ZeroJ-native fast contributor) ----

    @Command(name = "contribute", mixinStandardHelpOptions = true,
            description = "Apply your phase-2 contribution to a ceremony .zkey (snarkjs-compatible; "
                    + "the transcript verifies with 'snarkjs zkey verify').")
    static class Contribute implements Callable<Integer> {

        @Option(names = "--in", required = true, description = "Input .zkey") Path in;
        @Option(names = "--out", required = true, description = "Output .zkey") Path out;
        @Option(names = "--name", defaultValue = "zeroj contributor", description = "Contributor name (in the transcript)")
        String name;

        @Override
        public Integer call() throws Exception {
            if (!Files.isReadable(in)) { System.err.println("Cannot read .zkey: " + in); return 2; }
            System.out.printf("Contributing to %s (%,d bytes) -> %s ...%n", in, Files.size(in), out);
            long t0 = System.nanoTime();
            byte[] hash = ZkeyContributor.contribute(in, out, name);
            System.out.printf("Done in %.1fs.%n", (System.nanoTime() - t0) / 1e9);
            StringBuilder hex = new StringBuilder("Contribution Hash:\n\t\t");
            for (int i = 0; i < hash.length; i++) {
                hex.append(String.format("%02x", hash[i]));
                if (i % 32 == 31 && i < hash.length - 1) hex.append("\n\t\t");
                else if (i % 4 == 3) hex.append(' ');
            }
            System.out.println(hex);
            System.out.println("Publish this hash in your attestation. Verify the transcript with:");
            System.out.println("  snarkjs zkey verify <circuit.r1cs> <pot.ptau> " + out.getFileName());
            return 0;
        }
    }

    /** Version from the jar manifest ({@code Implementation-Version}); "dev" when run from classes. */
    static class ManifestVersion implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() {
            String v = CeremonyCli.class.getPackage().getImplementationVersion();
            return new String[]{"zeroj-ceremony " + (v != null ? v : "dev")};
        }
    }

    // ---- finalize ----

    @Command(name = "finalize", mixinStandardHelpOptions = true,
            description = "Convert a completed ceremony .zkey into a ZeroJ proving-key store (streaming, multi-GB safe).")
    static class Finalize implements Callable<Integer> {

        @Option(names = "--zkey", required = true, description = "Final ceremony .zkey") Path zkey;
        @Option(names = "--pk-store", required = true, description = "Output proving-key store directory") Path pkStore;

        @Override
        public Integer call() throws Exception {
            if (!Files.isReadable(zkey)) { System.err.println("Cannot read .zkey: " + zkey); return 2; }
            System.out.printf("Importing %s (%,d bytes) -> %s ...%n", zkey, Files.size(zkey), pkStore);
            long t0 = System.nanoTime();
            var dims = ZkeyPkStoreImporter.importToPkStore(zkey, pkStore);
            System.out.printf("Done in %.1fs: %,d wires | %d public | domain %,d%n",
                    (System.nanoTime() - t0) / 1e9, dims.numWires(), dims.numPublic(), dims.domainSize());
            System.out.println("Prove with Groth16PkStore.load(\"" + pkStore + "\") and "
                    + "ZkeyPkStoreImporter.snarkjsConstraints(yourConstraints, " + dims.numPublic() + ").");
            return 0;
        }
    }
}
