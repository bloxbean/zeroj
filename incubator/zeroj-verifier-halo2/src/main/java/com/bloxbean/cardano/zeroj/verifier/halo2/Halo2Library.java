package com.bloxbean.cardano.zeroj.verifier.halo2;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Low-level FFM bindings to the Halo2 Rust shared library.
 * <p>
 * Wraps the {@code zeroj_halo2_setup_and_prove}, {@code zeroj_halo2_verify},
 * {@code zeroj_halo2_version}, and {@code zeroj_halo2_free} functions.
 */
public final class Halo2Library implements AutoCloseable {

    private static final int OK = 0;

    private final Arena libraryArena;
    private final MethodHandle setupAndProve;
    private final MethodHandle verify;
    private final MethodHandle version;
    private final MethodHandle free;

    public Halo2Library() throws IOException {
        this(Halo2NativeLoader.extractLibrary());
    }

    public Halo2Library(Path libraryPath) {
        this.libraryArena = Arena.ofShared();

        SymbolLookup lookup = SymbolLookup.libraryLookup(libraryPath, libraryArena);
        Linker linker = Linker.nativeLinker();

        // zeroj_halo2_setup_and_prove(k, a, b, result_out**, error_out**) -> int
        this.setupAndProve = linker.downcallHandle(
                lookup.find("zeroj_halo2_setup_and_prove").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,    // k
                        ValueLayout.JAVA_LONG,   // a
                        ValueLayout.JAVA_LONG,   // b
                        ValueLayout.ADDRESS,     // result_out
                        ValueLayout.ADDRESS));   // error_out

        // zeroj_halo2_verify(params, params_len, vk, vk_len, proof, proof_len, pi_json, error_out) -> int
        this.verify = linker.downcallHandle(
                lookup.find("zeroj_halo2_verify").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,  // params
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,  // vk
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,  // proof
                        ValueLayout.ADDRESS,                        // pi_json
                        ValueLayout.ADDRESS));                      // error_out

        this.version = linker.downcallHandle(
                lookup.find("zeroj_halo2_version").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS));

        this.free = linker.downcallHandle(
                lookup.find("zeroj_halo2_free").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    /**
     * Setup and prove the multiplier circuit (a * b = c).
     * Returns JSON with proof, params, and public inputs.
     */
    public String setupAndProve(int k, long a, long b) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment resultPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);

            int status = (int) setupAndProve.invokeExact(k, a, b, resultPtr, errorPtr);
            if (status != OK) {
                MemorySegment err = errorPtr.get(ValueLayout.ADDRESS, 0);
                String msg = err.equals(MemorySegment.NULL) ? "Unknown error"
                        : err.reinterpret(4096).getString(0, StandardCharsets.UTF_8);
                freeIfNotNull(err);
                throw new RuntimeException("Halo2 setup+prove failed: " + msg);
            }

            MemorySegment result = resultPtr.get(ValueLayout.ADDRESS, 0);
            String json = result.reinterpret(10 * 1024 * 1024).getString(0, StandardCharsets.UTF_8);
            freeIfNotNull(result);
            return json;
        } catch (RuntimeException e) { throw e; }
        catch (Throwable e) { throw new RuntimeException("FFM call failed: " + e.getMessage(), e); }
    }

    /**
     * Verify a Halo2 proof.
     */
    public boolean verify(byte[] params, byte[] vk, byte[] proof, String publicInputsJson) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment paramsSegment = arena.allocateFrom(ValueLayout.JAVA_BYTE, params);
            MemorySegment vkSegment = vk.length > 0 ? arena.allocateFrom(ValueLayout.JAVA_BYTE, vk)
                    : arena.allocate(ValueLayout.JAVA_BYTE);
            MemorySegment proofSegment = arena.allocateFrom(ValueLayout.JAVA_BYTE, proof);
            MemorySegment piJsonSegment = arena.allocateFrom(publicInputsJson, StandardCharsets.UTF_8);
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);

            int status = (int) verify.invokeExact(
                    paramsSegment, params.length,
                    vkSegment, vk.length,
                    proofSegment, proof.length,
                    piJsonSegment,
                    errorPtr);

            if (status != OK) {
                MemorySegment err = errorPtr.get(ValueLayout.ADDRESS, 0);
                if (!err.equals(MemorySegment.NULL)) freeIfNotNull(err);
                return false;
            }
            return true;
        } catch (Throwable e) {
            throw new RuntimeException("FFM call failed: " + e.getMessage(), e);
        }
    }

    public String version() {
        try {
            MemorySegment ptr = (MemorySegment) version.invokeExact();
            String v = ptr.reinterpret(64).getString(0, StandardCharsets.UTF_8);
            freeIfNotNull(ptr);
            return v;
        } catch (Throwable e) { return "unknown"; }
    }

    private void freeIfNotNull(MemorySegment ptr) {
        try {
            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
                free.invokeExact(ptr);
            }
        } catch (Throwable ignored) {}
    }

    @Override
    public void close() { libraryArena.close(); }
}
