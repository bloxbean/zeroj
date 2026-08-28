package com.bloxbean.cardano.zeroj.examples.dsl.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * Wraps the snarkjs CLI for trusted setup and proof generation.
 *
 * <p>This utility shells out to snarkjs to perform:</p>
 * <ul>
 *   <li>Powers of Tau ceremony (Phase 1 — universal, curve-wide)</li>
 *   <li>Groth16 setup + prove (Phase 2 — circuit-specific)</li>
 *   <li>PlonK setup + prove (no Phase 2 needed — truly universal)</li>
 * </ul>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * var prover = new SnarkjsProver("/path/to/snarkjs");
 * Path ptau = prover.powersOfTau("bls12-381", 13, workDir);
 * var setup = prover.groth16Setup(r1csBytes, ptau, workDir);
 * var proof = prover.groth16Prove(setup.zkeyFile(), wtnsBytes, workDir, setup.vkJson());
 * }</pre>
 */
public class SnarkjsProver {

    /** Result of trusted setup: zkey file path + verification key JSON. */
    public record SetupResult(Path zkeyFile, String vkJson) {}

    /** Result of proof generation: proof JSON + public inputs JSON + verification key JSON. */
    public record ProofResult(String proofJson, String publicJson, String vkJson) {}

    private final String snarkjsBin;
    private final long timeoutSeconds;

    public SnarkjsProver() {
        this(findSnarkjs());
    }

    /**
     * Find snarkjs binary by checking common locations.
     */
    public static String findSnarkjs() {
        // 1. Environment variable
        String envBin = System.getenv("SNARKJS_BIN");
        if (envBin != null && !envBin.isBlank()) return envBin;

        // 2. Common npm global install locations
        String home = System.getProperty("user.home");
        String[] candidates = {
                "snarkjs",
                home + "/.npm-global/bin/snarkjs",
                "/usr/local/bin/snarkjs",
                home + "/.nvm/versions/node/current/bin/snarkjs",
        };
        for (String candidate : candidates) {
            if (java.nio.file.Files.isExecutable(Path.of(candidate))) {
                return candidate;
            }
        }
        return "snarkjs"; // fallback to PATH
    }

    public SnarkjsProver(String snarkjsBin) {
        this(snarkjsBin, 300);
    }

    public SnarkjsProver(String snarkjsBin, long timeoutSeconds) {
        this.snarkjsBin = snarkjsBin;
        this.timeoutSeconds = timeoutSeconds;
    }

    /**
     * Check if snarkjs is available on the system.
     */
    public boolean isAvailable() {
        try {
            // snarkjs --version exits with code 99 but prints version info
            var pb = new ProcessBuilder(snarkjsBin, "--version")
                    .redirectErrorStream(true);
            var process = pb.start();
            String output = new String(process.getInputStream().readAllBytes());
            process.waitFor(10, TimeUnit.SECONDS);
            return output.contains("snarkjs");
        } catch (Exception e) {
            return false;
        }
    }

    // ========================================================================
    // Powers of Tau ceremony (Phase 1)
    // ========================================================================

    /**
     * Run a minimal Powers of Tau ceremony for testing.
     *
     * <p>In production, use community ceremony files (Hermez Perpetual PoT for BN254,
     * Filecoin PoT for BLS12-381). A single .ptau file works for ALL circuits on the
     * same curve — it only depends on curve + max circuit size.</p>
     *
     * @param curve    "bls12-381" or "bn128"
     * @param power    log2 of max constraints (e.g., 13 → up to 8192 constraints)
     * @param workDir  working directory for temp files
     * @return path to the finalized .ptau file
     */
    public Path powersOfTau(String curve, int power, Path workDir) throws IOException, InterruptedException {
        Path ptau0 = workDir.resolve("pot_0.ptau");
        Path ptau1 = workDir.resolve("pot_1.ptau");
        Path ptauFinal = workDir.resolve("pot_final.ptau");

        run(workDir, snarkjsBin, "powersoftau", "new", curve,
                String.valueOf(power), ptau0.toString(), "-v");
        run(workDir, snarkjsBin, "powersoftau", "contribute", ptau0.toString(),
                ptau1.toString(), "--name=test-contribution", "-v", "-e=test entropy for zeroj demo");
        run(workDir, snarkjsBin, "powersoftau", "prepare", "phase2",
                ptau1.toString(), ptauFinal.toString(), "-v");

        return ptauFinal;
    }

    // ========================================================================
    // Groth16 (requires Phase 2 circuit-specific setup)
    // ========================================================================

    /**
     * Groth16 trusted setup: generates circuit-specific zkey + verification key.
     *
     * @param r1csBytes serialized .r1cs binary
     * @param ptauFile  path to finalized .ptau file
     * @param workDir   working directory
     * @return setup result with zkey path and VK JSON
     */
    public SetupResult groth16Setup(byte[] r1csBytes, Path ptauFile, Path workDir)
            throws IOException, InterruptedException {
        Path r1csFile = workDir.resolve("circuit.r1cs");
        Files.write(r1csFile, r1csBytes);

        Path zkey0 = workDir.resolve("circuit_0.zkey");
        Path zkeyFinal = workDir.resolve("circuit_final.zkey");
        Path vkFile = workDir.resolve("verification_key.json");

        run(workDir, snarkjsBin, "groth16", "setup",
                r1csFile.toString(), ptauFile.toString(), zkey0.toString());
        run(workDir, snarkjsBin, "zkey", "contribute", zkey0.toString(), zkeyFinal.toString(),
                "--name=test-contribution", "-v", "-e=test entropy for zeroj demo");
        run(workDir, snarkjsBin, "zkey", "export", "verificationkey",
                zkeyFinal.toString(), vkFile.toString());

        return new SetupResult(zkeyFinal, Files.readString(vkFile));
    }

    /**
     * Groth16 proof generation.
     *
     * @param zkeyFile  path to circuit .zkey file
     * @param wtnsBytes serialized .wtns binary
     * @param workDir   working directory
     * @param vkJson    verification key JSON (passed through for convenience)
     * @return proof result with proof JSON, public inputs JSON, and VK JSON
     */
    public ProofResult groth16Prove(Path zkeyFile, byte[] wtnsBytes, Path workDir, String vkJson)
            throws IOException, InterruptedException {
        Path wtnsFile = workDir.resolve("witness.wtns");
        Files.write(wtnsFile, wtnsBytes);

        Path proofFile = workDir.resolve("proof.json");
        Path publicFile = workDir.resolve("public.json");

        run(workDir, snarkjsBin, "groth16", "prove", zkeyFile.toString(), wtnsFile.toString(),
                proofFile.toString(), publicFile.toString());

        return new ProofResult(Files.readString(proofFile), Files.readString(publicFile), vkJson);
    }

    // ========================================================================
    // PlonK (no Phase 2 — truly universal setup)
    // ========================================================================

    /**
     * PlonK trusted setup: generates zkey + verification key.
     * No circuit-specific Phase 2 ceremony needed — just Phase 1 (PoT).
     */
    public SetupResult plonkSetup(byte[] r1csBytes, Path ptauFile, Path workDir)
            throws IOException, InterruptedException {
        Path r1csFile = workDir.resolve("circuit.r1cs");
        Files.write(r1csFile, r1csBytes);

        Path zkeyFile = workDir.resolve("circuit_plonk.zkey");
        Path vkFile = workDir.resolve("verification_key.json");

        run(workDir, snarkjsBin, "plonk", "setup",
                r1csFile.toString(), ptauFile.toString(), zkeyFile.toString());
        run(workDir, snarkjsBin, "zkey", "export", "verificationkey",
                zkeyFile.toString(), vkFile.toString());

        return new SetupResult(zkeyFile, Files.readString(vkFile));
    }

    /**
     * PlonK proof generation.
     */
    public ProofResult plonkProve(Path zkeyFile, byte[] wtnsBytes, Path workDir, String vkJson)
            throws IOException, InterruptedException {
        Path wtnsFile = workDir.resolve("witness.wtns");
        Files.write(wtnsFile, wtnsBytes);

        Path proofFile = workDir.resolve("proof.json");
        Path publicFile = workDir.resolve("public.json");

        run(workDir, snarkjsBin, "plonk", "prove", zkeyFile.toString(), wtnsFile.toString(),
                proofFile.toString(), publicFile.toString());

        return new ProofResult(Files.readString(proofFile), Files.readString(publicFile), vkJson);
    }

    /**
     * Verify a PlonK proof using snarkjs CLI.
     * (For off-chain Java verification of snarkjs PlonK proofs, a snarkjs PlonK codec is needed.)
     */
    public boolean plonkVerify(Path workDir) throws IOException, InterruptedException {
        Path vkFile = workDir.resolve("verification_key.json");
        Path publicFile = workDir.resolve("public.json");
        Path proofFile = workDir.resolve("proof.json");

        try {
            run(workDir, snarkjsBin, "plonk", "verify",
                    vkFile.toString(), publicFile.toString(), proofFile.toString());
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Verify a Groth16 proof using snarkjs CLI.
     */
    public boolean groth16Verify(Path workDir) throws IOException, InterruptedException {
        Path vkFile = workDir.resolve("verification_key.json");
        Path publicFile = workDir.resolve("public.json");
        Path proofFile = workDir.resolve("proof.json");

        try {
            run(workDir, snarkjsBin, "groth16", "verify",
                    vkFile.toString(), publicFile.toString(), proofFile.toString());
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // ========================================================================
    // Shared helpers
    // ========================================================================

    /**
     * Export verification key from a zkey file.
     */
    public String exportVerificationKey(Path zkeyFile, Path workDir) throws IOException, InterruptedException {
        Path vkFile = workDir.resolve("verification_key.json");
        run(workDir, snarkjsBin, "zkey", "export", "verificationkey",
                zkeyFile.toString(), vkFile.toString());
        return Files.readString(vkFile);
    }

    private void run(Path workDir, String... command) throws IOException, InterruptedException {
        var pb = new ProcessBuilder(command)
                .directory(workDir.toFile())
                .redirectErrorStream(true);
        var process = pb.start();
        String output = new String(process.getInputStream().readAllBytes());
        boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("snarkjs timed out after " + timeoutSeconds + "s: "
                    + String.join(" ", command));
        }
        if (process.exitValue() != 0) {
            throw new IOException("snarkjs failed (exit " + process.exitValue() + "): "
                    + String.join(" ", command) + "\n" + output);
        }
    }
}
