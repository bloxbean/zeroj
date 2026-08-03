package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParameterFingerprint;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

final class BuildInfo {
    private static final String RESOURCE = "/zeroj-jmt-load.properties";

    private BuildInfo() {}

    static String cclVersion() {
        Properties properties = new Properties();
        try (InputStream input = BuildInfo.class.getResourceAsStream(RESOURCE)) {
            if (input == null) throw new IllegalStateException("Missing build resource " + RESOURCE);
            properties.load(input);
            return properties.getProperty("cclVersion");
        } catch (IOException error) {
            throw new IllegalStateException("Failed to read " + RESOURCE, error);
        }
    }

    static String poseidonFingerprint() {
        return PoseidonParameterFingerprint.sha256(PoseidonJmtProfile.PARAMS);
    }
}
