package com.bloxbean.cardano.zeroj.blst.ffm;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Java-25 FFM (Panama) foundation for the ZeroJ blst binding (ADR-0029 M6 / Rung B).
 *
 * <p>Extracts the precompiled {@code libblst} for the current platform (bundled under
 * {@code /native/<os>/<arch>/}) to a temp file and maps it with a {@link SymbolLookup}, so the raw
 * {@code blst_*} C API (e.g. {@code blst_p1s_mult_pippenger}) can be called directly — no JNI, no
 * third-party wrapper. FFM is native-image-friendlier than JNI and already used elsewhere in ZeroJ
 * (mmap in the prover). Downcalls bind lazily via {@link #downcall}.</p>
 */
public final class BlstFfm {

    private BlstFfm() {}

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Arena LIB_ARENA = Arena.ofShared(); // lives for the JVM
    private static final SymbolLookup BLST = loadBlst();

    /** Bind a {@code blst_*} function to a {@link MethodHandle}. */
    public static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
        MemorySegment sym = BLST.find(name)
                .orElseThrow(() -> new IllegalStateException("libblst symbol not found: " + name));
        return LINKER.downcallHandle(sym, descriptor);
    }

    private static SymbolLookup loadBlst() {
        String os = osToken();
        String arch = archToken();
        String ext = os.equals("mac") ? "dylib" : os.equals("windows") ? "dll" : "so";
        String resource = "/native/" + os + "/" + arch + "/libblst." + ext;

        try (InputStream in = BlstFfm.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Bundled libblst not found for this platform: " + resource
                        + " (os=" + System.getProperty("os.name") + ", arch=" + System.getProperty("os.arch") + ")");
            }
            Path tmp = Files.createTempFile("libblst-zeroj-", "." + ext);
            tmp.toFile().deleteOnExit();
            Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
            return SymbolLookup.libraryLookup(tmp, LIB_ARENA);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to extract/load libblst", e);
        }
    }

    private static String osToken() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) return "mac";
        if (os.contains("win")) return "windows";
        return "linux";
    }

    private static String archToken() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("aarch64") || arch.equals("arm64")) return "aarch64";
        // x86-64: our resource layout uses "x86_64" on mac, "amd64" on linux/windows
        return osToken().equals("mac") ? "x86_64" : "amd64";
    }
}
