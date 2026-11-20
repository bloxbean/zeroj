package org.zeroj.crypto.testsupport;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Discovers and version-checks the pinned {@code snarkjs} CLI for ceremony and {@code .zkey}
 * interop tests (ADR-0031 / ADR-0047).
 *
 * <p>Discovery order:
 * <ol>
 *   <li>{@code -Dzeroj.snarkjs} system property</li>
 *   <li>{@code SNARKJS_BIN} environment variable</li>
 *   <li>{@code PATH} entries</li>
 *   <li>common global npm install directories ({@code ~/.npm-global/bin}, {@code /usr/local/bin},
 *       {@code /opt/homebrew/bin}, {@code ~/.nvm/versions/node/current/bin})</li>
 * </ol>
 *
 * <p>Locally, an absent binary or a version other than {@value #PINNED_VERSION} skips the suite;
 * under {@code -PrequireSnarkjs} ({@value #REQUIRE_PROPERTY}={@code true}), both fail closed.</p>
 */
public final class SnarkjsCliLocator {

    private SnarkjsCliLocator() {}

    /** Normative snarkjs version pinned by ADR-0047 and ADR-0031. */
    public static final String PINNED_VERSION = "0.7.6";

    /** System property set by Gradle {@code -PrequireSnarkjs}. */
    public static final String REQUIRE_PROPERTY = "zeroj.assurance.requireSnarkjs";

    /** Optional explicit binary override via system property. */
    public static final String BIN_PROPERTY = "zeroj.snarkjs";

    /** Optional explicit binary override via environment variable. */
    public static final String BIN_ENV = "SNARKJS_BIN";

    /** Resolution outcome: {@code binary != null} iff pinned snarkjs is ready to execute. */
    public record Resolution(String binary, String version, String reason) {
        public boolean isReady() {
            return binary != null;
        }
    }

    public static boolean isRequired() {
        return Boolean.getBoolean(REQUIRE_PROPERTY);
    }

    /**
     * Locate {@code snarkjs} and verify that {@code snarkjs --version} reports
     * {@code snarkjs@0.7.6}.
     */
    public static Resolution resolvePinned() {
        String expected = "snarkjs@" + PINNED_VERSION;
        String wrongVersionFound = null;
        String wrongVersionBin = null;

        for (String candidate : candidateBinaries()) {
            String detected = probeVersion(candidate);
            if (expected.equals(detected)) {
                return new Resolution(candidate, detected, null);
            }
            if (detected != null && wrongVersionFound == null) {
                wrongVersionFound = detected;
                wrongVersionBin = candidate;
            }
        }

        if (wrongVersionFound != null) {
            return new Resolution(null, wrongVersionFound,
                    "ADR-0047/ADR-0031 pin " + expected + " as the interop oracle, found "
                            + wrongVersionFound + " at " + wrongVersionBin);
        }
        return new Resolution(null, null,
                "snarkjs " + PINNED_VERSION + " not found or not answering `--version` within 10 s "
                        + "(checked -D" + BIN_PROPERTY + ", " + BIN_ENV + ", PATH, and common npm bin dirs)");
    }

    private static List<String> candidateBinaries() {
        Set<String> candidates = new LinkedHashSet<>();

        String prop = System.getProperty(BIN_PROPERTY);
        if (prop != null && !prop.isBlank()) {
            candidates.add(prop.trim());
        }
        String envBin = System.getenv(BIN_ENV);
        if (envBin != null && !envBin.isBlank()) {
            candidates.add(envBin.trim());
        }

        boolean isWindows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        String[] exeNames = isWindows ? new String[]{"snarkjs.cmd", "snarkjs.exe", "snarkjs"} : new String[]{"snarkjs"};

        String pathEnv = System.getenv("PATH");
        if (pathEnv != null && !pathEnv.isBlank()) {
            for (String dir : pathEnv.split(Pattern.quote(File.pathSeparator))) {
                if (dir.isBlank()) continue;
                for (String name : exeNames) {
                    Path p = Path.of(dir, name);
                    if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                        candidates.add(p.toAbsolutePath().normalize().toString());
                    }
                }
            }
        }

        String home = System.getProperty("user.home", "");
        String[] common = {
                home + "/.npm-global/bin/snarkjs",
                "/usr/local/bin/snarkjs",
                "/opt/homebrew/bin/snarkjs",
                home + "/.nvm/versions/node/current/bin/snarkjs"
        };
        for (String c : common) {
            Path p = Path.of(c);
            if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                candidates.add(p.toAbsolutePath().normalize().toString());
            }
        }

        // Final fallback letting OS PATH resolution run directly if PATH scan missed a wrapper
        candidates.add(isWindows ? "snarkjs.cmd" : "snarkjs");
        return new ArrayList<>(candidates);
    }

    /**
     * Runs {@code <bin> --version} (snarkjs exits 99 by design after printing its banner) and
     * extracts the {@code snarkjs@<ver>} line, or returns {@code null} on failure/timeout.
     */
    static String probeVersion(String bin) {
        try {
            Path out = Files.createTempFile("snarkjs-version", ".txt");
            try {
                Process p = new ProcessBuilder(bin, "--version")
                        .redirectErrorStream(true)
                        .redirectOutput(out.toFile())
                        .start();
                if (!p.waitFor(10, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    return null;
                }
                for (String line : Files.readAllLines(out, StandardCharsets.UTF_8)) {
                    String trimmed = line.trim();
                    if (trimmed.startsWith("snarkjs@")) {
                        return trimmed;
                    }
                }
                return null;
            } finally {
                Files.deleteIfExists(out);
            }
        } catch (Exception e) {
            return null;
        }
    }
}
