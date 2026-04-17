package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Code generator that invokes {@link PoseidonGrainLFSR} to produce
 * {@code (C, M)} for each named Poseidon preset and writes the results as
 * Java source files containing hardcoded {@link PoseidonParams} instances.
 *
 * <p>Generated files are intended to be committed to source control.
 * Regenerate with:
 * <pre>
 *   ./gradlew :zeroj-circuit-lib:generatePoseidonParams
 * </pre>
 *
 * <p>The generated files are read-only at runtime; runtime generation is not
 * supported because it would bloat GraalVM native-image binaries. All
 * downstream code depends on the compiled-in constants.
 *
 * <p>Supported CLI forms:
 * <ul>
 *   <li>No args: writes into {@code src/main/java/...} of the current module
 *       (inferred from the working directory).</li>
 *   <li>One arg: target module root (e.g. absolute path to
 *       {@code zeroj-circuit-lib}).</li>
 * </ul>
 */
public final class PoseidonParamsCodegen {

    private static final String PACKAGE = "com.bloxbean.cardano.zeroj.circuit.lib.poseidon";

    private PoseidonParamsCodegen() {}

    private record Preset(String className, String displayName, FieldConfig field,
                          int fieldBitSize, int t, int alpha, int rf, int rp) {
        Preset {
            // Consistency guard: fieldBitSize must match the declared prime's bit length.
            // Catches a typo like "255 for BN254" that would otherwise silently change LFSR output.
            int expected = field.prime().bitLength();
            if (fieldBitSize != expected) {
                throw new IllegalStateException(
                        "Preset " + className + ": fieldBitSize=" + fieldBitSize
                                + " but " + field.name() + " prime bitLength=" + expected);
            }
        }
    }

    private static final List<Preset> PRESETS = List.of(
            new Preset("PoseidonParamsBN254T3",
                    "BN254 t=3 alpha=5 RF=8 RP=57",
                    FieldConfig.BN254, 254, 3, 5, 8, 57),
            new Preset("PoseidonParamsBLS12_381T3",
                    "BLS12-381 t=3 alpha=5 RF=8 RP=57",
                    FieldConfig.BLS12_381, 255, 3, 5, 8, 57)
    );

    public static void main(String[] args) throws IOException {
        Path moduleRoot = args.length > 0 ? Path.of(args[0]) : Path.of(".").toAbsolutePath().normalize();
        Path outDir = moduleRoot.resolve("src/main/java").resolve(PACKAGE.replace('.', '/'));
        Files.createDirectories(outDir);

        for (Preset preset : PRESETS) {
            String source = generate(preset);
            Path outFile = outDir.resolve(preset.className + ".java");
            Files.writeString(outFile, source, StandardCharsets.UTF_8);
            System.out.println("Generated " + outFile);
        }
    }

    static String generate(Preset p) {
        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(p.fieldBitSize, p.t, p.rf, p.rp, p.field.prime());
        BigInteger[] c = gen.generateRoundConstants();
        BigInteger[][] mMatrix = gen.generateMdsMatrix();

        BigInteger[] m = new BigInteger[p.t * p.t];
        for (int i = 0; i < p.t; i++) {
            for (int j = 0; j < p.t; j++) {
                m[i * p.t + j] = mMatrix[i][j];
            }
        }

        String fieldConstant = switch (p.field.curve()) {
            case BN254 -> "FieldConfig.BN254";
            case BLS12_381 -> "FieldConfig.BLS12_381";
            case PALLAS -> throw new UnsupportedOperationException(
                    "Pallas (α, RP) not yet audited against the Poseidon paper for ZeroJ use; "
                            + "adding a Pallas preset requires a new ADR entry. See ADR-0015.");
        };

        StringBuilder out = new StringBuilder();
        out.append("package ").append(PACKAGE).append(";\n\n");
        out.append("import com.bloxbean.cardano.zeroj.circuit.FieldConfig;\n\n");
        out.append("import java.math.BigInteger;\n\n");
        out.append("/**\n");
        out.append(" * Poseidon parameters for ").append(p.displayName).append(".\n");
        out.append(" *\n");
        out.append(" * <p><b>This file is generated</b> by {@link PoseidonParamsCodegen} from the\n");
        out.append(" * Grain LFSR in {@link PoseidonGrainLFSR}, which is a faithful port of the\n");
        out.append(" * Poseidon paper's reference Sage script (hadeshash commit\n");
        out.append(" * {@code 208b5a164c6a252b137997694d90931b2bb851c5}). Do not edit by hand;\n");
        out.append(" * regenerate with {@code ./gradlew :zeroj-circuit-lib:generatePoseidonParams}.\n");
        out.append(" */\n");
        out.append("public final class ").append(p.className).append(" {\n\n");
        out.append("    private ").append(p.className).append("() {}\n\n");

        out.append("    /** Round constants: ").append(c.length).append(" values (")
                .append(p.rf + p.rp).append(" rounds x ").append(p.t).append(" state width). */\n");
        out.append("    static final BigInteger[] C = new BigInteger[] {\n");
        for (int i = 0; i < c.length; i++) {
            out.append("            ").append(bigIntLiteral(c[i]));
            if (i < c.length - 1) out.append(",");
            out.append("\n");
        }
        out.append("    };\n\n");

        out.append("    /** MDS matrix (").append(p.t).append("x").append(p.t)
                .append(", row-major: M[i*").append(p.t).append("+j]). */\n");
        out.append("    static final BigInteger[] M = new BigInteger[] {\n");
        for (int i = 0; i < m.length; i++) {
            int row = i / p.t;
            int col = i % p.t;
            out.append("            ").append(bigIntLiteral(m[i]));
            if (i < m.length - 1) out.append(",");
            out.append(" // M[").append(row).append("][").append(col).append("]\n");
        }
        out.append("    };\n\n");

        out.append("    public static final PoseidonParams INSTANCE = new PoseidonParams(\n");
        out.append("            ").append(fieldConstant).append(",\n");
        out.append("            ").append(p.t).append(", ");
        out.append(p.alpha).append(", ");
        out.append(p.rf).append(", ");
        out.append(p.rp).append(",\n");
        out.append("            C,\n");
        out.append("            M\n");
        out.append("    );\n");
        out.append("}\n");

        return out.toString();
    }

    private static String bigIntLiteral(BigInteger v) {
        return "new BigInteger(\"" + v.toString(10) + "\")";
    }
}
