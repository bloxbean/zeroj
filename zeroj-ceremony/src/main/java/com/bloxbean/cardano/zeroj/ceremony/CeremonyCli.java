package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.R1csExporter;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * ZeroJ Groth16 MPC-ceremony CLI (ADR-0031).
 *
 * <pre>
 *   export-r1cs --circuit &lt;FQCN&gt; [--circuit-jar &lt;jar&gt;] --out &lt;file.r1cs&gt;
 *       Compile a ZeroJ circuit and export it to the iden3 .r1cs format consumed by
 *       snarkjs Groth16 ceremonies. &lt;FQCN&gt; is the @ZKCircuit class or its generated
 *       *Circuit companion — any class with a static build() returning CircuitBuilder.
 *
 *   finalize --zkey &lt;final.zkey&gt; --pk-store &lt;dir&gt;
 *       Convert a completed ceremony .zkey into a ZeroJ proving-key store (streaming;
 *       handles multi-GB keys). Prove afterwards with Groth16PkStore.load(dir) and
 *       ZkeyPkStoreImporter.snarkjsConstraints(compiledConstraints, numPublic).
 * </pre>
 *
 * <p>Planned (ADR-0031 M5): {@code contribute}, {@code verify}, {@code beacon} (the ZeroJ-native
 * phase-2 contributor writing snarkjs-compatible .zkey), and {@code phase1 --source filecoin|file|new}.</p>
 */
public final class CeremonyCli {

    private CeremonyCli() {}

    public static void main(String[] args) throws Exception {
        System.exit(run(args));
    }

    /** Entry point separated from {@link #main} so tests can invoke it in-process. */
    public static int run(String[] args) throws Exception {
        if (args.length == 0) { usage(); return 2; }
        String cmd = args[0];
        Map<String, String> opts = parse(args);
        return switch (cmd) {
            case "export-r1cs" -> exportR1cs(opts);
            case "finalize" -> finalizeKey(opts);
            case "help", "--help", "-h" -> { usage(); yield 0; }
            default -> {
                System.err.println("Unknown command: " + cmd);
                usage();
                yield 2;
            }
        };
    }

    // ---- export-r1cs ----

    private static int exportR1cs(Map<String, String> o) throws Exception {
        String fqcn = require(o, "circuit");
        Path out = Path.of(require(o, "out"));
        ClassLoader loader = CeremonyCli.class.getClassLoader();
        if (o.containsKey("circuit-jar")) {
            Path jar = Path.of(o.get("circuit-jar"));
            if (!Files.isReadable(jar)) { System.err.println("Cannot read jar: " + jar); return 2; }
            loader = new URLClassLoader(new URL[]{jar.toUri().toURL()}, loader);
        }

        CircuitBuilder builder = loadCircuit(fqcn, loader);
        System.out.println("Compiling circuit " + fqcn + " (BLS12-381) ...");
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

    // ---- finalize ----

    private static int finalizeKey(Map<String, String> o) throws Exception {
        Path zkey = Path.of(require(o, "zkey"));
        Path store = Path.of(require(o, "pk-store"));
        if (!Files.isReadable(zkey)) { System.err.println("Cannot read .zkey: " + zkey); return 2; }

        System.out.printf("Importing %s (%,d bytes) -> %s ...%n", zkey, Files.size(zkey), store);
        long t0 = System.nanoTime();
        var dims = ZkeyPkStoreImporter.importToPkStore(zkey, store);
        System.out.printf("Done in %.1fs: %,d wires | %d public | domain %,d%n",
                (System.nanoTime() - t0) / 1e9, dims.numWires(), dims.numPublic(), dims.domainSize());
        System.out.println("Prove with Groth16PkStore.load(\"" + store + "\") and "
                + "ZkeyPkStoreImporter.snarkjsConstraints(yourConstraints, " + dims.numPublic() + ").");
        return 0;
    }

    // ---- plumbing ----

    private static Map<String, String> parse(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                String key = a.substring(2);
                int eq = key.indexOf('=');
                if (eq >= 0) m.put(key.substring(0, eq), key.substring(eq + 1));
                else if (i + 1 < args.length && !args[i + 1].startsWith("--")) m.put(key, args[++i]);
                else m.put(key, "true");
            }
        }
        return m;
    }

    private static String require(Map<String, String> o, String key) {
        String v = o.get(key);
        if (v == null) throw new IllegalArgumentException("Missing required option --" + key);
        return v;
    }

    private static void usage() {
        System.out.println("""
                zeroj-ceremony — Groth16 MPC trusted-setup tooling (ADR-0031)

                Commands:
                  export-r1cs --circuit <FQCN> [--circuit-jar <jar>] --out <file.r1cs>
                  finalize    --zkey <final.zkey> --pk-store <dir>
                  help

                Ceremony flow (Option A, snarkjs):
                  1. zeroj-ceremony export-r1cs --circuit com.example.MyProof --out my.r1cs
                  2. snarkjs groth16 setup my.r1cs <prepared.ptau> key_0000.zkey
                  3. contributors: snarkjs zkey contribute key_N.zkey key_N+1.zkey
                  4. snarkjs zkey beacon ... && snarkjs zkey verify my.r1cs <ptau> final.zkey
                  5. zeroj-ceremony finalize --zkey final.zkey --pk-store ./pk
                See docs/ceremony/OPTION-A-RUNBOOK.md.""");
    }
}
