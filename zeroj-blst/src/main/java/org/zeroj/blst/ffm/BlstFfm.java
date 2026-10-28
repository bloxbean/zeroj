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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
 * fresh owner-only temporary directory under {@code java.io.tmpdir} and deleted as soon as it is
 * mapped. The manifest guards against a stale or substituted binary in the jar; it does not defend
 * against an attacker who controls the class path.</p>
 *
 * <p>Residual risk: between the write and the {@code dlopen} the file exists on disk. Inside the
 * owner-only directory only the same user can replace it, provided {@code java.io.tmpdir} itself
 * cannot be renamed by others — true for a per-user directory or a sticky {@code /tmp}. Pointing
 * {@code java.io.tmpdir} at a directory other users can write without the sticky bit weakens this,
 * and is the deployer's responsibility.</p>
 *
 * <p>{@link BlstPlatform} decides which bundled library serves the platform; every unbundled
 * platform, including Intel macOS and Windows, is rejected with a "use the pure-Java provider"
 * message.</p>
 */
public final class BlstFfm {

    private BlstFfm() {}

    static final String RESOURCE_ROOT = "/org/zeroj/blst/native/";

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Arena LIB_ARENA = Arena.ofShared(); // lives for the JVM
    private static final SymbolLookup BLST = loadBlst();

    /** Every descriptor bound so far; tests check it against the native-image foreign metadata. */
    static final Set<FunctionDescriptor> BOUND_DESCRIPTORS = ConcurrentHashMap.newKeySet();

    /** Bind a {@code blst_*} function to a {@link MethodHandle}. */
    public static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
        MemorySegment sym = BLST.find(name)
                .orElseThrow(() -> new IllegalStateException("libblst symbol not found: " + name));
        BOUND_DESCRIPTORS.add(descriptor);
        return LINKER.downcallHandle(sym, descriptor);
    }

    /** {@code <os>/<arch>/libblst.<ext>} for this platform; throws if the platform is unsupported. */
    static String platformLibrary() {
        return BlstPlatform.library(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    /** {@code <os>/<arch>/libblst.<ext>} for the given {@code os.name} / {@code os.arch} values. */
    static String platformLibrary(String osName, String osArch) {
        return BlstPlatform.library(osName, osArch);
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
            SymbolLookup lookup = SymbolLookup.libraryLookup(tmp, LIB_ARENA); // dlopen happens here
            // The mapping outlives the directory entry on every bundled (POSIX) platform, so remove
            // the file at once instead of leaving it on disk for the JVM's lifetime.
            try {
                Files.deleteIfExists(tmp);
                Files.deleteIfExists(dir);
            } catch (IOException ignored) {
                // deleteOnExit above still applies
            }
            return lookup;
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
