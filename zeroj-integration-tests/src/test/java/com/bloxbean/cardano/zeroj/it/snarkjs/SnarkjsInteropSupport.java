package com.bloxbean.cardano.zeroj.it.snarkjs;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.R1csExporter;
import com.bloxbean.cardano.zeroj.examples.dsl.common.SnarkjsProver;
import com.bloxbean.cardano.zeroj.examples.dsl.common.WitnessExporter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Shared plumbing for the ADR-0047 bidirectional snarkjs interop suites.
 *
 * <p>snarkjs is discovered by {@link SnarkjsProver#findSnarkjs()} ({@code SNARKJS_BIN}, then common
 * npm locations, then {@code PATH}). Locally, an absent snarkjs — or one other than the pinned
 * {@value #PINNED_VERSION} — <b>skips</b> the suites; in the assurance workflow the build passes
 * {@code -PrequireSnarkjs}, which sets {@code zeroj.assurance.requireSnarkjs=true} and turns both
 * into a failure, so the oracle can never silently vanish or drift. Verdicts come from
 * {@link #verify}, which distinguishes a rejection from a crash.</p>
 */
final class SnarkjsInteropSupport {

    private SnarkjsInteropSupport() {}

    /** The snarkjs release ADR-0047 pins as the normative reference for the JSON formats. */
    static final String PINNED_VERSION = "0.7.6";

    static final String REQUIRE_PROPERTY = "zeroj.assurance.requireSnarkjs";

    static final BigInteger FR = MontFr381.modulus();

    /** The snarkjs CLI name of the curve for {@code powersoftau new}. */
    static final String SNARKJS_CURVE = "bls12-381";

    /** How long a single snarkjs invocation may take before it is killed and reported as an error. */
    static final long SNARKJS_TIMEOUT_SECONDS = 300;

    /**
     * Returns a ready snarkjs driver. Absent snarkjs: skip locally, fail under {@link #REQUIRE_PROPERTY}.
     * A snarkjs other than {@value #PINNED_VERSION}: skip locally (the byte-for-byte assertions are
     * only meaningful against the pinned oracle), fail under {@link #REQUIRE_PROPERTY}.
     */
    static SnarkjsProver requireSnarkjs() {
        boolean required = Boolean.getBoolean(REQUIRE_PROPERTY);
        String bin = SnarkjsProver.findSnarkjs();
        String version = version(bin);
        if (version == null) {
            String msg = "snarkjs not found or not answering `--version` within 10 s (SNARKJS_BIN / PATH; see SnarkjsProver.findSnarkjs())";
            if (required) fail(msg + " — required by -PrequireSnarkjs");
            assumeTrue(false, msg + " — skipping");
        }
        if (!("snarkjs@" + PINNED_VERSION).equals(version)) {
            String msg = "ADR-0047 pins snarkjs " + PINNED_VERSION + " as the interop oracle, found " + version;
            if (required) fail(msg + " — required by -PrequireSnarkjs");
            assumeTrue(false, msg + " — skipping");
        }
        return new SnarkjsProver(bin, SNARKJS_TIMEOUT_SECONDS);
    }

    /**
     * First line of {@code snarkjs --version} (exactly {@code snarkjs@<version>}; snarkjs exits 99 by
     * design), or {@code null} if the binary cannot be started, hangs past 10 s, or prints nothing.
     */
    static String version(String bin) {
        try {
            var out = Files.createTempFile("snarkjs-version", ".txt");
            try {
                var p = new ProcessBuilder(bin, "--version").redirectErrorStream(true).redirectOutput(out.toFile()).start();
                if (!p.waitFor(10, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    return null;
                }
                var lines = Files.readAllLines(out, StandardCharsets.UTF_8);
                for (String l : lines) {
                    String t = l.trim();
                    if (t.startsWith("snarkjs@")) return t;
                }
                return null;
            } finally {
                Files.deleteIfExists(out);
            }
        } catch (Exception e) {
            return null;
        }
    }

    // ---------------------------------------------------------------- tri-state verify

    /** The oracle's verdict. Anything that is neither is an error, never a verdict. */
    enum Verdict { VALID, INVALID }

    /**
     * Run {@code snarkjs <protocol> verify verification_key.json public.json proof.json} in {@code dir}
     * and classify the outcome by exit status <b>and</b> output. snarkjs 0.7.6 exits 0 and logs
     * {@code OK!} for a valid proof; exits 1 and logs one of its rejection messages for an invalid
     * one; and also exits 1 for an internal error (unparseable JSON, a thrown exception), which must
     * not be mistaken for a rejection. A timeout or an unrecognised outcome throws, so a negative
     * test can only pass on a genuine {@code INVALID}.
     */
    static Verdict verify(String protocol, Path dir) throws IOException, InterruptedException {
        var out = dir.resolve("verify-" + protocol + "-" + System.nanoTime() + ".log");
        var pb = new ProcessBuilder(SnarkjsProver.findSnarkjs(), protocol, "verify",
                "verification_key.json", "public.json", "proof.json")
                .directory(dir.toFile()).redirectErrorStream(true).redirectOutput(out.toFile());
        var p = pb.start();
        if (!p.waitFor(SNARKJS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("snarkjs " + protocol + " verify timed out after " + SNARKJS_TIMEOUT_SECONDS + " s in " + dir);
        }
        String log = Files.readString(out, StandardCharsets.UTF_8);
        int exit = p.exitValue();
        if (exit == 0 && log.contains("OK!")) return Verdict.VALID;
        if (exit == 1 && REJECTIONS.stream().anyMatch(log::contains)) return Verdict.INVALID;
        throw new IOException("snarkjs " + protocol + " verify gave neither OK! nor a rejection (exit " + exit + "):\n" + log);
    }

    /** The rejection messages of snarkjs 0.7.6 {@code groth16_verify.js} / {@code plonk_verify.js}. */
    private static final List<String> REJECTIONS = List.of(
            "Invalid proof", "Invalid Proof",
            "Proof commitments are not valid", "Proof evaluations are not valid",
            "Public inputs are not valid", "Invalid number of public inputs",
            "Number of public signals does not match with vk");

    // ---------------------------------------------------------------- the interop circuit

    /** {@code c = a * b} with {@code c} public — the same relation the checked-in snarkjs vectors use. */
    static CircuitBuilder multiplier() {
        return CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
    }

    static BigInteger[] multiplierWitness(CircuitBuilder circuit, long a, long b) {
        return circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(a * b)),
                "a", List.of(BigInteger.valueOf(a)),
                "b", List.of(BigInteger.valueOf(b))), CurveId.BLS12_381);
    }

    static BigInteger[] publicInputs(BigInteger[] witness, int nPublic) {
        var pub = new BigInteger[nPublic];
        System.arraycopy(witness, 1, pub, 0, nPublic);
        return pub;
    }

    /** iden3 {@code .r1cs} bytes via the ZeroJ ceremony bridge ({@link R1csExporter}). */
    static byte[] r1csBytes(R1CSConstraintSystem r1cs) throws IOException {
        var out = new ByteArrayOutputStream();
        R1csExporter.export(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), out);
        return out.toByteArray();
    }

    /** iden3 {@code .wtns} bytes (BLS12-381 Fr, 8 × 32-bit limbs). */
    static byte[] wtnsBytes(BigInteger[] witness) {
        return WitnessExporter.toWtns(witness, FR, 8);
    }

    /** Drop the three snarkjs verifier inputs into {@code dir} as snarkjs names them. */
    static void writeVerifyInputs(Path dir, String vkJson, String publicJson, String proofJson) throws IOException {
        Files.writeString(dir.resolve("verification_key.json"), vkJson, StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("public.json"), publicJson, StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("proof.json"), proofJson, StandardCharsets.UTF_8);
    }
}
