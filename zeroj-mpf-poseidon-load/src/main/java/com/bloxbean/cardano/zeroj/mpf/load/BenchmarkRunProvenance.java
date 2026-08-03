package com.bloxbean.cardano.zeroj.mpf.load;

import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Immutable per-section provenance; prevents mixed reports from hiding their source/configuration. */
record BenchmarkRunProvenance(
        String schema,
        String runId,
        String section,
        String recordedAt,
        String sourceRevision,
        boolean sourceTreeDirty,
        String sourceTreeSha256,
        int untrackedSourceFiles,
        String applicationCommand,
        List<String> jvmArguments,
        long processId,
        String workingDirectory,
        String cclVersion,
        String poseidonParameterFingerprint,
        Map<String, Object> configuration) {

    private static final byte[] DOMAIN =
            "zeroj-benchmark-source-tree-v1\0".getBytes(StandardCharsets.US_ASCII);

    static BenchmarkRunProvenance capture(
            String section, String cclVersion, String poseidonFingerprint,
            Map<String, Object> configuration) {
        SourceState source = sourceState();
        return new BenchmarkRunProvenance(
                "zeroj-benchmark-run-v1", UUID.randomUUID().toString(), section,
                Instant.now().toString(), source.revision(), source.dirty(), source.sha256(),
                source.untrackedFiles(),
                System.getProperty("sun.java.command", "unavailable"),
                List.copyOf(ManagementFactory.getRuntimeMXBean().getInputArguments()),
                ProcessHandle.current().pid(), Path.of("").toAbsolutePath().normalize().toString(),
                cclVersion, poseidonFingerprint, Map.copyOf(configuration));
    }

    private static SourceState sourceState() {
        try {
            String repository = new String(
                    command("git", "rev-parse", "--show-toplevel"), StandardCharsets.UTF_8).trim();
            byte[] revisionBytes = command("git", "-C", repository, "rev-parse", "HEAD");
            String revision = new String(revisionBytes, StandardCharsets.US_ASCII).trim();
            byte[] diff = command(
                    "git", "-C", repository, "diff", "--binary", "HEAD", "--", ".");
            byte[] untracked = command(
                    "git", "-C", repository, "ls-files", "--others", "--exclude-standard",
                    "-z", "--", ".");
            List<String> paths = nulSeparated(untracked);
            MessageDigest digest = sha256();
            digest.update(DOMAIN);
            updateLengthPrefixed(digest, revision.getBytes(StandardCharsets.US_ASCII));
            updateLengthPrefixed(digest, diff);
            int included = 0;
            for (String relative : paths) {
                Path path = Path.of(repository).resolve(relative).normalize();
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) continue;
                updateLengthPrefixed(digest, relative.getBytes(StandardCharsets.UTF_8));
                long size = Files.size(path);
                digest.update(ByteBuffer.allocate(Long.BYTES).putLong(size).array());
                try (InputStream input = Files.newInputStream(path)) {
                    input.transferTo(new DigestSink(digest));
                }
                included++;
            }
            return new SourceState(revision, diff.length != 0 || included != 0,
                    HexFormat.of().formatHex(digest.digest()), included);
        } catch (IOException | RuntimeException error) {
            return new SourceState("unavailable", true, "unavailable", 0);
        }
    }

    private static byte[] command(String... command) throws IOException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] output = process.getInputStream().readAllBytes();
        try {
            if (!process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException("Timed out running " + command[0]);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted running " + command[0], interrupted);
        }
        if (process.exitValue() != 0) {
            throw new IOException(command[0] + " failed with exit " + process.exitValue());
        }
        return output;
    }

    private static List<String> nulSeparated(byte[] value) {
        List<String> result = new ArrayList<>();
        int start = 0;
        for (int index = 0; index <= value.length; index++) {
            if (index == value.length || value[index] == 0) {
                if (index > start) {
                    result.add(new String(value, start, index - start, StandardCharsets.UTF_8));
                }
                start = index + 1;
            }
        }
        return result;
    }

    private static void updateLengthPrefixed(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(value.length).array());
        digest.update(value);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private record SourceState(String revision, boolean dirty, String sha256, int untrackedFiles) {}

    private static final class DigestSink extends java.io.OutputStream {
        private final MessageDigest digest;
        private DigestSink(MessageDigest digest) { this.digest = digest; }
        @Override public void write(int value) { digest.update((byte) value); }
        @Override public void write(byte[] value, int offset, int length) {
            digest.update(value, offset, length);
        }
    }
}
