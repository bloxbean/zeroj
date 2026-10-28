package org.zeroj.blst.ffm;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Java-25 FFM (Panama) foundation for the ZeroJ blst binding (ADR-0029 M6 / Rung B, ADR-0062 D3).
 *
 * <p>Loads the source-built {@code libblst} bundled for the current platform under
 * {@value #RESOURCE_ROOT}{@code <os>/<arch>/} and maps it with a {@link SymbolLookup}, so the raw
 * {@code blst_*} C API can be called directly — no JNI, no third-party wrapper. Downcalls bind via
 * {@link #downcall}.</p>
 *
 * <p>Loading is fail-closed (ADR-0062 I4): only the bundled resource is used (no system property,
 * environment variable or {@code java.library.path} lookup); an unsupported OS or architecture is
 * rejected rather than mapped to a default; and the library's SHA-256 must match the bundled
 * manifest {@code libblst.sha256} before it is mapped. The library is written to a new file inside a
 * fresh owner-only temporary directory. The manifest guards against a stale or substituted binary
 * in the jar; it does not defend against an attacker who controls the class path.</p>
 */
public final class BlstFfm {

    private BlstFfm() {}

    static final String RESOURCE_ROOT = "/org/zeroj/blst/native/";

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Arena LIB_ARENA = Arena.ofShared(); // lives for the JVM
    private static final SymbolLookup BLST = loadBlst();

    /** Bind a {@code blst_*} function to a {@link MethodHandle}. */
    public static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
        MemorySegment sym = BLST.find(name)
                .orElseThrow(() -> new IllegalStateException("libblst symbol not found: " + name));
        return LINKER.downcallHandle(sym, descriptor);
    }

    /** {@code <os>/<arch>/libblst.<ext>} for this platform; throws if the platform is unsupported. */
    static String platformLibrary() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        String osToken;
        String ext;
        if (os.contains("mac") || os.contains("darwin")) {
            osToken = "mac";
            ext = "dylib";
        } else if (os.contains("linux")) {
            osToken = "linux";
            ext = "so";
        } else {
            throw new IllegalStateException("zeroj-blst has no libblst for OS '" + os + "'; use the pure-Java provider");
        }
        String archToken;
        if (arch.equals("aarch64") || arch.equals("arm64")) {
            archToken = "aarch64";
        } else if (arch.equals("amd64") || arch.equals("x86_64")) {
            archToken = osToken.equals("mac") ? "x86_64" : "amd64";
        } else {
            throw new IllegalStateException("zeroj-blst has no libblst for arch '" + arch + "'; use the pure-Java provider");
        }
        return osToken + "/" + archToken + "/libblst." + ext;
    }

    private static SymbolLookup loadBlst() {
        String library = platformLibrary();
        String expected = expectedSha256(library);
        try (InputStream in = BlstFfm.class.getResourceAsStream(RESOURCE_ROOT + library)) {
            if (in == null) {
                throw new IllegalStateException("Bundled libblst not found for this platform: " + RESOURCE_ROOT + library
                        + "; use the pure-Java provider");
            }
            byte[] bytes = in.readAllBytes();
            String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (!actual.equals(expected)) {
                throw new IllegalStateException("Bundled libblst " + library + " has SHA-256 " + actual
                        + ", but the manifest expects " + expected + "; refusing to load it");
            }
            Path dir = Files.createTempDirectory("zeroj-blst-"); // owner-only on POSIX
            dir.toFile().deleteOnExit();
            Path tmp = dir.resolve(library.substring(library.lastIndexOf('/') + 1));
            Files.write(tmp, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            tmp.toFile().deleteOnExit();
            return SymbolLookup.libraryLookup(tmp, LIB_ARENA);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to extract/load libblst", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** The manifest's SHA-256 for {@code library}, lower-case hex. */
    static String expectedSha256(String library) {
        try (InputStream in = BlstFfm.class.getResourceAsStream(RESOURCE_ROOT + "libblst.sha256")) {
            if (in == null) {
                throw new IllegalStateException("libblst SHA-256 manifest missing: " + RESOURCE_ROOT + "libblst.sha256");
            }
            for (String line : new String(in.readAllBytes(), StandardCharsets.US_ASCII).split("\n")) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length == 2 && parts[1].equals(library)) {
                    return parts[0].toLowerCase(Locale.ROOT);
                }
            }
            throw new IllegalStateException("libblst SHA-256 manifest has no entry for " + library);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read the libblst manifest", e);
        }
    }
}
