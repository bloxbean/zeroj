package com.bloxbean.cardano.zeroj.prover.rapidsnark;

import com.bloxbean.cardano.zeroj.prover.sidecar.ProverException;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Low-level FFM (Foreign Function &amp; Memory) bindings to the rapidsnark C library.
 *
 * <p>Wraps the {@code groth16_prover} function from rapidsnark's {@code prover.h}.
 * All native memory is scoped to individual prove calls — no manual cleanup required.</p>
 *
 * <p>Error codes from rapidsnark:</p>
 * <ul>
 *   <li>{@code PROVER_OK (0x0)} — success</li>
 *   <li>{@code PROVER_ERROR (0x1)} — general error</li>
 *   <li>{@code PROVER_ERROR_SHORT_BUFFER (0x2)} — output buffer too small (retry with larger)</li>
 *   <li>{@code PROVER_INVALID_WITNESS_LENGTH (0x3)} — witness doesn't match circuit</li>
 * </ul>
 */
public final class RapidsnarkLibrary implements AutoCloseable {

    private static final int PROVER_OK = 0x0;
    private static final int PROVER_ERROR_SHORT_BUFFER = 0x2;
    private static final int PROVER_INVALID_WITNESS_LENGTH = 0x3;

    private static final long DEFAULT_ERROR_BUFFER_SIZE = 4096;

    private final Arena libraryArena;
    private final MethodHandle groth16Prover;
    private final MethodHandle groth16ProofSize;
    private final MethodHandle groth16PublicSizeForZkeyBuf;

    private final long proofBufferSize;

    /**
     * Load rapidsnark from the classpath (auto-detects platform).
     *
     * @throws IOException if library extraction fails
     * @throws UnsupportedOperationException if the platform is not supported
     */
    public RapidsnarkLibrary() throws IOException {
        this(NativeLibraryLoader.extractLibrary());
    }

    /**
     * Load rapidsnark from an explicit path.
     *
     * @param libraryPath path to {@code librapidsnark.so} or {@code librapidsnark.dylib}
     */
    public RapidsnarkLibrary(Path libraryPath) {
        this.libraryArena = Arena.ofShared();

        SymbolLookup lookup = SymbolLookup.libraryLookup(libraryPath, libraryArena);
        Linker linker = Linker.nativeLinker();

        // groth16_prover(zkey_buf, zkey_size, wtns_buf, wtns_size,
        //                proof_buf, proof_size, public_buf, public_size,
        //                error_msg, error_msg_maxsize) -> int
        this.groth16Prover = linker.downcallHandle(
                lookup.find("groth16_prover").orElseThrow(
                        () -> new IllegalStateException("Symbol 'groth16_prover' not found in " + libraryPath)),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,    // return
                        ValueLayout.ADDRESS,     // zkey_buffer
                        ValueLayout.JAVA_LONG,   // zkey_size
                        ValueLayout.ADDRESS,     // wtns_buffer
                        ValueLayout.JAVA_LONG,   // wtns_size
                        ValueLayout.ADDRESS,     // proof_buffer
                        ValueLayout.ADDRESS,     // proof_size
                        ValueLayout.ADDRESS,     // public_buffer
                        ValueLayout.ADDRESS,     // public_size
                        ValueLayout.ADDRESS,     // error_msg
                        ValueLayout.JAVA_LONG    // error_msg_maxsize
                ));

        // groth16_proof_size(proof_size*) -> void
        this.groth16ProofSize = linker.downcallHandle(
                lookup.find("groth16_proof_size").orElseThrow(
                        () -> new IllegalStateException("Symbol 'groth16_proof_size' not found")),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // groth16_public_size_for_zkey_buf(zkey_buf, zkey_size, public_size*, error_msg, error_msg_maxsize) -> int
        this.groth16PublicSizeForZkeyBuf = linker.downcallHandle(
                lookup.find("groth16_public_size_for_zkey_buf").orElseThrow(
                        () -> new IllegalStateException("Symbol 'groth16_public_size_for_zkey_buf' not found")),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ));

        // Query the fixed proof buffer size
        this.proofBufferSize = queryProofSize();
    }

    /**
     * Result of a Groth16 proof generation.
     *
     * @param proofJson        snarkjs-compatible proof JSON
     * @param publicSignalsJson snarkjs-compatible public signals JSON array
     */
    public record ProveResult(String proofJson, String publicSignalsJson) {}

    /**
     * Generate a Groth16 proof using the rapidsnark native library.
     *
     * @param zkey circuit proving key (.zkey file contents)
     * @param wtns witness data (.wtns file contents)
     * @return proof result containing proof JSON and public signals JSON
     * @throws ProverException if proving fails
     * @throws IllegalArgumentException if zkey or wtns is null or empty
     */
    public ProveResult groth16Prove(byte[] zkey, byte[] wtns) {
        if (zkey == null || zkey.length == 0) {
            throw new IllegalArgumentException("zkey must not be null or empty");
        }
        if (wtns == null || wtns.length == 0) {
            throw new IllegalArgumentException("wtns must not be null or empty");
        }

        long publicBufSize = queryPublicSize(zkey);

        // Attempt proving, retry once if buffer too small
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                return doProve(zkey, wtns, proofBufferSize, publicBufSize);
            } catch (ShortBufferException e) {
                publicBufSize = e.requiredPublicSize > 0 ? e.requiredPublicSize : publicBufSize * 2;
            }
        }

        throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                "Buffer too small after retry");
    }

    private ProveResult doProve(byte[] zkey, byte[] wtns, long proofBufSize, long publicBufSize) {
        try (var arena = Arena.ofConfined()) {
            // Copy zkey and wtns into native memory
            MemorySegment zkeySegment = arena.allocate(zkey.length);
            MemorySegment.copy(zkey, 0, zkeySegment, ValueLayout.JAVA_BYTE, 0, zkey.length);

            MemorySegment wtnsSegment = arena.allocate(wtns.length);
            MemorySegment.copy(wtns, 0, wtnsSegment, ValueLayout.JAVA_BYTE, 0, wtns.length);

            // Allocate output buffers
            MemorySegment proofBuffer = arena.allocate(proofBufSize);
            MemorySegment proofSizePtr = arena.allocate(ValueLayout.JAVA_LONG);
            proofSizePtr.set(ValueLayout.JAVA_LONG, 0, proofBufSize);

            MemorySegment publicBuffer = arena.allocate(publicBufSize);
            MemorySegment publicSizePtr = arena.allocate(ValueLayout.JAVA_LONG);
            publicSizePtr.set(ValueLayout.JAVA_LONG, 0, publicBufSize);

            MemorySegment errorBuffer = arena.allocate(DEFAULT_ERROR_BUFFER_SIZE);

            int result = (int) groth16Prover.invokeExact(
                    zkeySegment, (long) zkey.length,
                    wtnsSegment, (long) wtns.length,
                    proofBuffer, proofSizePtr,
                    publicBuffer, publicSizePtr,
                    errorBuffer, DEFAULT_ERROR_BUFFER_SIZE);

            if (result == PROVER_ERROR_SHORT_BUFFER) {
                long requiredProof = proofSizePtr.get(ValueLayout.JAVA_LONG, 0);
                long requiredPublic = publicSizePtr.get(ValueLayout.JAVA_LONG, 0);
                throw new ShortBufferException(requiredProof, requiredPublic);
            }

            if (result == PROVER_INVALID_WITNESS_LENGTH) {
                String errorMsg = errorBuffer.getString(0, StandardCharsets.UTF_8);
                throw new ProverException(ProverException.ErrorCode.INVALID_INPUT,
                        "Witness length doesn't match circuit: " + errorMsg);
            }

            if (result != PROVER_OK) {
                String errorMsg = errorBuffer.getString(0, StandardCharsets.UTF_8);
                throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "rapidsnark error (code " + result + "): " + errorMsg);
            }

            long proofSize = proofSizePtr.get(ValueLayout.JAVA_LONG, 0);
            long publicSize = publicSizePtr.get(ValueLayout.JAVA_LONG, 0);

            String proofJson = new String(
                    proofBuffer.asSlice(0, proofSize).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
            String publicJson = new String(
                    publicBuffer.asSlice(0, publicSize).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);

            return new ProveResult(proofJson, publicJson);
        } catch (ShortBufferException e) {
            throw e;
        } catch (ProverException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                    "FFM call to groth16_prover failed: " + e.getMessage(), e);
        }
    }

    /**
     * Query the fixed proof buffer size from rapidsnark.
     */
    private long queryProofSize() {
        try (var arena = Arena.ofConfined()) {
            MemorySegment sizePtr = arena.allocate(ValueLayout.JAVA_LONG);
            groth16ProofSize.invokeExact(sizePtr);
            return sizePtr.get(ValueLayout.JAVA_LONG, 0);
        } catch (Throwable e) {
            // Fallback to generous default
            return 16 * 1024;
        }
    }

    /**
     * Query the required public signals buffer size for a given zkey.
     */
    private long queryPublicSize(byte[] zkey) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment zkeySegment = arena.allocate(zkey.length);
            MemorySegment.copy(zkey, 0, zkeySegment, ValueLayout.JAVA_BYTE, 0, zkey.length);

            MemorySegment sizePtr = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment errorBuffer = arena.allocate(DEFAULT_ERROR_BUFFER_SIZE);

            int result = (int) groth16PublicSizeForZkeyBuf.invokeExact(
                    zkeySegment, (long) zkey.length,
                    sizePtr,
                    errorBuffer, DEFAULT_ERROR_BUFFER_SIZE);

            if (result == PROVER_OK) {
                return sizePtr.get(ValueLayout.JAVA_LONG, 0);
            }
        } catch (Throwable e) {
            // fall through to default
        }
        // Fallback to generous default
        return 64 * 1024;
    }

    @Override
    public void close() {
        libraryArena.close();
    }

    /**
     * Internal exception for short buffer retry logic.
     */
    private static final class ShortBufferException extends RuntimeException {
        final long requiredProofSize;
        final long requiredPublicSize;

        ShortBufferException(long requiredProofSize, long requiredPublicSize) {
            super("Buffer too small");
            this.requiredProofSize = requiredProofSize;
            this.requiredPublicSize = requiredPublicSize;
        }
    }
}
