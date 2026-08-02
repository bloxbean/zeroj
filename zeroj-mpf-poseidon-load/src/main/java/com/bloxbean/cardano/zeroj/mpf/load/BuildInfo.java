package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHash;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Properties;

final class BuildInfo {
    private static final String RESOURCE = "/zeroj-mpf-load.properties";

    private BuildInfo() {}

    static String cclVersion() {
        Properties properties = new Properties();
        try (InputStream in = BuildInfo.class.getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException("Missing build resource " + RESOURCE);
            properties.load(in);
            return properties.getProperty("cclVersion");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read " + RESOURCE, e);
        }
    }

    static String poseidonFingerprint() {
        try {
            var params = PoseidonParamsBLS12_381T3.INSTANCE;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(16)
                    .putInt(params.t())
                    .putInt(params.alpha())
                    .putInt(params.rf())
                    .putInt(params.rp())
                    .array());
            for (var value : params.c()) digest.update(PoseidonMpfHash.toDigestBytes(value));
            for (var value : params.m()) digest.update(PoseidonMpfHash.toDigestBytes(value));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
