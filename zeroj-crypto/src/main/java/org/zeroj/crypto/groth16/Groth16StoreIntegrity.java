package org.zeroj.crypto.groth16;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Properties;
import java.util.TreeSet;

/** Content identities for validated streaming imports; not a ceremony transcript verifier. */
final class Groth16StoreIntegrity {
    private static final String[] PAYLOADS = {"aux.bin", "pointsA.bin", "pointsB1.bin",
            "pointsB2.bin", "pointsH.bin", "pointsL.bin"};

    private Groth16StoreIntegrity() {}

    static void requireDigest(String digest) {
        if (digest == null || !digest.matches("[0-9a-fA-F]{64}"))
            throw new IllegalArgumentException("Expected SHA-256 must be 64 hexadecimal characters");
    }

    static String digest(Path file) throws IOException {
        MessageDigest hash;
        try { hash = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        try (var in = Files.newInputStream(file)) {
            byte[] buffer = new byte[1 << 20];
            int count;
            while ((count = in.read(buffer)) != -1) hash.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(hash.digest());
    }

    static String seal(Path dir, String sourceSha256) throws IOException {
        Path manifest = dir.resolve("manifest.properties");
        Properties values = new Properties();
        try (var in = Files.newInputStream(manifest)) { values.load(in); }
        values.setProperty("integrityProfile", "validated-zkey-v1");
        values.setProperty("sourceSha256", sourceSha256);
        for (String payload : PAYLOADS) values.setProperty("sha256." + payload, digest(dir.resolve(payload)));
        // Stable key order and no timestamp: identical imports have identical content identities.
        try (var out = Files.newBufferedWriter(manifest)) {
            for (String key : new TreeSet<>(values.stringPropertyNames())) {
                Properties entry = new Properties();
                entry.setProperty(key, values.getProperty(key));
                StringWriter encoded = new StringWriter();
                entry.store(encoded, null);
                for (String line : encoded.toString().split("\\R")) {
                    if (!line.startsWith("#")) { out.write(line); out.write('\n'); }
                }
            }
        }
        return digest(manifest);
    }

    static void verify(Path dir, String expectedManifestSha256) throws IOException {
        Path manifest = dir.resolve("manifest.properties");
        if (expectedManifestSha256 != null) {
            requireDigest(expectedManifestSha256);
            if (!digest(manifest).equalsIgnoreCase(expectedManifestSha256))
                throw new IOException("Groth16 manifest SHA-256 mismatch");
        }
        Properties values = new Properties();
        try (var in = Files.newInputStream(manifest)) { values.load(in); }
        String profile = values.getProperty("integrityProfile");
        if (profile == null && expectedManifestSha256 == null) return; // trusted legacy local store
        if (!"validated-zkey-v1".equals(profile)) throw new IOException("Missing/unsupported integrity profile");
        try { requireDigest(values.getProperty("sourceSha256")); }
        catch (IllegalArgumentException bad) { throw new IOException("Missing/invalid source identity", bad); }
        for (String payload : PAYLOADS) {
            String expected = values.getProperty("sha256." + payload);
            if (expected == null || !digest(dir.resolve(payload)).equals(expected))
                throw new IOException("Groth16 store SHA-256 mismatch: " + payload);
        }
    }
}
