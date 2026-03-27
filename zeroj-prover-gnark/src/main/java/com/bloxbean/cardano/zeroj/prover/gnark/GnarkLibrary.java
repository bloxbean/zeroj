package com.bloxbean.cardano.zeroj.prover.gnark;

import com.bloxbean.cardano.zeroj.prover.sidecar.ProverException;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Low-level FFM bindings to the gnark C shared library.
 *
 * <p>Wraps the {@code zeroj_groth16_prove}, {@code zeroj_groth16_setup},
 * {@code zeroj_gnark_version}, and {@code zeroj_free} functions from the
 * Go-compiled shared library.</p>
 */
public final class GnarkLibrary implements AutoCloseable {

    private static final int PROVER_OK = 0;

    private final Arena libraryArena;
    private final MethodHandle groth16Prove;
    private final MethodHandle groth16Setup;
    private final MethodHandle plonkSetup;
    private final MethodHandle plonkProve;
    private final MethodHandle plonkVerify;
    private final MethodHandle gnarkVersion;
    private final MethodHandle free;

    /**
     * Load the gnark shared library from the classpath (auto-detects platform).
     *
     * @throws IOException if library extraction fails
     */
    public GnarkLibrary() throws IOException {
        this(GnarkNativeLoader.extractLibrary());
    }

    /**
     * Load the gnark shared library from an explicit path.
     *
     * @param libraryPath path to {@code libzeroj_gnark.so} or {@code libzeroj_gnark.dylib}
     */
    public GnarkLibrary(Path libraryPath) {
        this.libraryArena = Arena.ofShared();

        SymbolLookup lookup = SymbolLookup.libraryLookup(libraryPath, libraryArena);
        Linker linker = Linker.nativeLinker();

        // zeroj_groth16_prove(curve, r1cs_path, pk_path, witness_json,
        //                     proof_out**, public_out**, error_out**) -> int
        this.groth16Prove = linker.downcallHandle(
                lookup.find("zeroj_groth16_prove").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_groth16_prove' not found")),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,    // return
                        ValueLayout.ADDRESS,     // curve
                        ValueLayout.ADDRESS,     // r1cs_path
                        ValueLayout.ADDRESS,     // pk_path
                        ValueLayout.ADDRESS,     // witness_json
                        ValueLayout.ADDRESS,     // proof_out
                        ValueLayout.ADDRESS,     // public_out
                        ValueLayout.ADDRESS      // error_out
                ));

        // zeroj_groth16_setup(curve, r1cs_path, pk_path_out**, vk_out**, error_out**) -> int
        this.groth16Setup = linker.downcallHandle(
                lookup.find("zeroj_groth16_setup").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_groth16_setup' not found")),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,     // curve
                        ValueLayout.ADDRESS,     // r1cs_path
                        ValueLayout.ADDRESS,     // pk_path_out
                        ValueLayout.ADDRESS,     // vk_out
                        ValueLayout.ADDRESS      // error_out
                ));

        // zeroj_plonk_setup(curve, r1cs_path, pk_path_out**, vk_out**, error_out**) -> int
        this.plonkSetup = linker.downcallHandle(
                lookup.find("zeroj_plonk_setup").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_plonk_setup' not found")),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,     // curve
                        ValueLayout.ADDRESS,     // r1cs_path
                        ValueLayout.ADDRESS,     // pk_path_out
                        ValueLayout.ADDRESS,     // vk_out
                        ValueLayout.ADDRESS      // error_out
                ));

        // zeroj_plonk_prove(curve, r1cs_path, pk_path, witness_path,
        //                   proof_out**, public_out**, error_out**) -> int
        this.plonkProve = linker.downcallHandle(
                lookup.find("zeroj_plonk_prove").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_plonk_prove' not found")),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,     // curve
                        ValueLayout.ADDRESS,     // r1cs_path
                        ValueLayout.ADDRESS,     // pk_path
                        ValueLayout.ADDRESS,     // witness_path
                        ValueLayout.ADDRESS,     // proof_out
                        ValueLayout.ADDRESS,     // public_out
                        ValueLayout.ADDRESS      // error_out
                ));

        // zeroj_plonk_verify(curve, vk_path, proof_base64, witness_path, error_out**) -> int
        this.plonkVerify = linker.downcallHandle(
                lookup.find("zeroj_plonk_verify").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_plonk_verify' not found")),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,     // curve
                        ValueLayout.ADDRESS,     // vk_path
                        ValueLayout.ADDRESS,     // proof_base64
                        ValueLayout.ADDRESS,     // witness_path
                        ValueLayout.ADDRESS      // error_out
                ));

        // zeroj_gnark_version() -> char*
        this.gnarkVersion = linker.downcallHandle(
                lookup.find("zeroj_gnark_version").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_gnark_version' not found")),
                FunctionDescriptor.of(ValueLayout.ADDRESS));

        // zeroj_free(char*) -> void
        this.free = linker.downcallHandle(
                lookup.find("zeroj_free").orElseThrow(
                        () -> new IllegalStateException("Symbol 'zeroj_free' not found")),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    /**
     * Result of a Groth16 proof generation.
     *
     * @param resultJson JSON containing proof, public witness, and timing
     * @param publicJson public witness JSON
     */
    public record ProveResult(String resultJson, String publicJson) {}

    /**
     * Result of a Groth16 trusted setup.
     *
     * @param pkPath  path to the generated proving key file
     * @param vkJson  verification key as JSON
     */
    public record SetupResult(String pkPath, String vkJson) {}

    /**
     * Generate a Groth16 proof using gnark.
     *
     * @param curve       curve identifier ("bls12381" or "bn254")
     * @param r1csPath    path to the R1CS constraint system file
     * @param pkPath      path to the proving key file
     * @param witnessPath path to the witness file (gnark binary format)
     * @return proof result
     * @throws ProverException if proving fails
     */
    public ProveResult groth16Prove(String curve, String r1csPath, String pkPath, String witnessPath) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment curveStr = arena.allocateFrom(curve, StandardCharsets.UTF_8);
            MemorySegment r1csStr = arena.allocateFrom(r1csPath, StandardCharsets.UTF_8);
            MemorySegment pkStr = arena.allocateFrom(pkPath, StandardCharsets.UTF_8);
            MemorySegment witnessStr = arena.allocateFrom(witnessPath, StandardCharsets.UTF_8);

            // Allocate pointer-to-pointer for output strings
            MemorySegment proofOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment publicOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment errorOutPtr = arena.allocate(ValueLayout.ADDRESS);

            int result = (int) groth16Prove.invokeExact(
                    curveStr, r1csStr, pkStr, witnessStr,
                    proofOutPtr, publicOutPtr, errorOutPtr);

            if (result != PROVER_OK) {
                MemorySegment errorPtr = errorOutPtr.get(ValueLayout.ADDRESS, 0);
                String errorMsg = errorPtr.equals(MemorySegment.NULL)
                        ? "Unknown gnark error"
                        : errorPtr.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
                freeIfNotNull(errorPtr);
                throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "gnark proving failed: " + errorMsg);
            }

            MemorySegment proofPtr = proofOutPtr.get(ValueLayout.ADDRESS, 0);
            MemorySegment publicPtr = publicOutPtr.get(ValueLayout.ADDRESS, 0);

            String resultJson = proofPtr.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);
            String publicJson = publicPtr.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);

            freeIfNotNull(proofPtr);
            freeIfNotNull(publicPtr);

            return new ProveResult(resultJson, publicJson);
        } catch (ProverException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                    "FFM call to zeroj_groth16_prove failed: " + e.getMessage(), e);
        }
    }

    /**
     * Run Groth16 trusted setup using gnark.
     *
     * @param curve    curve identifier
     * @param r1csPath path to the R1CS file
     * @return setup result with proving key path and verification key JSON
     * @throws ProverException if setup fails
     */
    public SetupResult groth16Setup(String curve, String r1csPath) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment curveStr = arena.allocateFrom(curve, StandardCharsets.UTF_8);
            MemorySegment r1csStr = arena.allocateFrom(r1csPath, StandardCharsets.UTF_8);

            MemorySegment pkPathOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment vkOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment errorOutPtr = arena.allocate(ValueLayout.ADDRESS);

            int result = (int) groth16Setup.invokeExact(
                    curveStr, r1csStr,
                    pkPathOutPtr, vkOutPtr, errorOutPtr);

            if (result != PROVER_OK) {
                MemorySegment errorPtr = errorOutPtr.get(ValueLayout.ADDRESS, 0);
                String errorMsg = errorPtr.equals(MemorySegment.NULL)
                        ? "Unknown gnark error"
                        : errorPtr.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
                freeIfNotNull(errorPtr);
                throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "gnark setup failed: " + errorMsg);
            }

            MemorySegment pkPathPtr = pkPathOutPtr.get(ValueLayout.ADDRESS, 0);
            MemorySegment vkPtr = vkOutPtr.get(ValueLayout.ADDRESS, 0);

            String pkPathResult = pkPathPtr.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
            String vkJson = vkPtr.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);

            freeIfNotNull(pkPathPtr);
            freeIfNotNull(vkPtr);

            return new SetupResult(pkPathResult, vkJson);
        } catch (ProverException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                    "FFM call to zeroj_groth16_setup failed: " + e.getMessage(), e);
        }
    }

    // --- PlonK operations ---

    /**
     * Run PlonK setup using gnark (generates SRS internally — for testing/dev only).
     *
     * @param curve    curve identifier ("bls12381" or "bn254")
     * @param r1csPath path to the SparseR1CS constraint system file
     * @return setup result with proving key path and verification key JSON
     * @throws ProverException if setup fails
     */
    public SetupResult plonkSetup(String curve, String r1csPath) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment curveStr = arena.allocateFrom(curve, StandardCharsets.UTF_8);
            MemorySegment r1csStr = arena.allocateFrom(r1csPath, StandardCharsets.UTF_8);
            MemorySegment pkPathOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment vkOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment errorOutPtr = arena.allocate(ValueLayout.ADDRESS);

            int result = (int) plonkSetup.invokeExact(
                    curveStr, r1csStr, pkPathOutPtr, vkOutPtr, errorOutPtr);

            if (result != PROVER_OK) {
                MemorySegment errorPtr = errorOutPtr.get(ValueLayout.ADDRESS, 0);
                String errorMsg = errorPtr.equals(MemorySegment.NULL)
                        ? "Unknown gnark error"
                        : errorPtr.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
                freeIfNotNull(errorPtr);
                throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "gnark plonk setup failed: " + errorMsg);
            }

            MemorySegment pkPathPtr = pkPathOutPtr.get(ValueLayout.ADDRESS, 0);
            MemorySegment vkPtr = vkOutPtr.get(ValueLayout.ADDRESS, 0);
            String pkPathResult = pkPathPtr.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
            String vkJson = vkPtr.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);
            freeIfNotNull(pkPathPtr);
            freeIfNotNull(vkPtr);

            return new SetupResult(pkPathResult, vkJson);
        } catch (ProverException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                    "FFM call to zeroj_plonk_setup failed: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a PlonK proof using gnark.
     *
     * @param curve       curve identifier ("bls12381" or "bn254")
     * @param r1csPath    path to the SparseR1CS file
     * @param pkPath      path to the proving key file
     * @param witnessPath path to the witness file (gnark binary format)
     * @return proof result
     * @throws ProverException if proving fails
     */
    public ProveResult plonkProve(String curve, String r1csPath, String pkPath, String witnessPath) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment curveStr = arena.allocateFrom(curve, StandardCharsets.UTF_8);
            MemorySegment r1csStr = arena.allocateFrom(r1csPath, StandardCharsets.UTF_8);
            MemorySegment pkStr = arena.allocateFrom(pkPath, StandardCharsets.UTF_8);
            MemorySegment witnessStr = arena.allocateFrom(witnessPath, StandardCharsets.UTF_8);
            MemorySegment proofOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment publicOutPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment errorOutPtr = arena.allocate(ValueLayout.ADDRESS);

            int result = (int) plonkProve.invokeExact(
                    curveStr, r1csStr, pkStr, witnessStr,
                    proofOutPtr, publicOutPtr, errorOutPtr);

            if (result != PROVER_OK) {
                MemorySegment errorPtr = errorOutPtr.get(ValueLayout.ADDRESS, 0);
                String errorMsg = errorPtr.equals(MemorySegment.NULL)
                        ? "Unknown gnark error"
                        : errorPtr.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
                freeIfNotNull(errorPtr);
                throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "gnark plonk proving failed: " + errorMsg);
            }

            MemorySegment proofPtr = proofOutPtr.get(ValueLayout.ADDRESS, 0);
            MemorySegment publicPtr = publicOutPtr.get(ValueLayout.ADDRESS, 0);
            String resultJson = proofPtr.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);
            String publicJson = publicPtr.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);
            freeIfNotNull(proofPtr);
            freeIfNotNull(publicPtr);

            return new ProveResult(resultJson, publicJson);
        } catch (ProverException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                    "FFM call to zeroj_plonk_prove failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verify a PlonK proof using gnark.
     *
     * @param curve       curve identifier
     * @param vkPath      path to the verification key file (gnark binary format)
     * @param proofBase64 base64-encoded proof bytes
     * @param witnessPath path to the public witness file
     * @return true if the proof is valid
     * @throws ProverException if verification encounters an error
     */
    public boolean plonkVerify(String curve, String vkPath, String proofBase64, String witnessPath) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment curveStr = arena.allocateFrom(curve, StandardCharsets.UTF_8);
            MemorySegment vkStr = arena.allocateFrom(vkPath, StandardCharsets.UTF_8);
            MemorySegment proofStr = arena.allocateFrom(proofBase64, StandardCharsets.UTF_8);
            MemorySegment witnessStr = arena.allocateFrom(witnessPath, StandardCharsets.UTF_8);
            MemorySegment errorOutPtr = arena.allocate(ValueLayout.ADDRESS);

            int result = (int) plonkVerify.invokeExact(
                    curveStr, vkStr, proofStr, witnessStr, errorOutPtr);

            if (result != PROVER_OK) {
                MemorySegment errorPtr = errorOutPtr.get(ValueLayout.ADDRESS, 0);
                if (!errorPtr.equals(MemorySegment.NULL)) {
                    freeIfNotNull(errorPtr);
                }
                return false;
            }
            return true;
        } catch (Throwable e) {
            throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                    "FFM call to zeroj_plonk_verify failed: " + e.getMessage(), e);
        }
    }

    /**
     * Get the gnark version string from the native library.
     *
     * @return version string (e.g., "v0.14.0")
     */
    public String gnarkVersion() {
        try {
            MemorySegment versionPtr = (MemorySegment) gnarkVersion.invokeExact();
            String version = versionPtr.reinterpret(64).getString(0, StandardCharsets.UTF_8);
            freeIfNotNull(versionPtr);
            return version;
        } catch (Throwable e) {
            return "unknown";
        }
    }

    private void freeIfNotNull(MemorySegment ptr) {
        try {
            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
                free.invokeExact(ptr);
            }
        } catch (Throwable e) {
            // best effort
        }
    }

    @Override
    public void close() {
        libraryArena.close();
    }
}
