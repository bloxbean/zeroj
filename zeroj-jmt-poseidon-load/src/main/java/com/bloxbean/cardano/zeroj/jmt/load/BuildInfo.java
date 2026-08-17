package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParameterFingerprint;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

final class BuildInfo {
    private static final String RESOURCE = "/zeroj-jmt-load.properties";
    private static final String RELEASE_CCL = "0.8.0-pre5";
    private static final String QUALIFIED_PRE_RELEASE_CCL = "0.8.0-pre5-dev1";

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

    /**
     * The published pre5 tag contains no changes below CCL's verified-structures modules relative
     * to the qualified dev1 tag. Keep this exception exact and one-way so a later CCL upgrade
     * fails closed until separately qualified.
     */
    static boolean isVerifiedStructuresCompatibleCclVersion(String storedVersion) {
        String currentVersion = cclVersion();
        return currentVersion.equals(storedVersion)
                || (RELEASE_CCL.equals(currentVersion)
                    && QUALIFIED_PRE_RELEASE_CCL.equals(storedVersion));
    }
}
