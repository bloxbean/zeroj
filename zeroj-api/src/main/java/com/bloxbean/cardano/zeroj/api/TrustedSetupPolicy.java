package com.bloxbean.cardano.zeroj.api;

/**
 * Central policy for development-only trusted setup operations.
 */
public final class TrustedSetupPolicy {

    public static final String ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY = "zeroj.allowInsecureTrustedSetup";
    public static final String ALLOW_INSECURE_TRUSTED_SETUP_ENV = "ZEROJ_ALLOW_INSECURE_TRUSTED_SETUP";

    private TrustedSetupPolicy() {}

    public static boolean insecureTrustedSetupEnabled() {
        return Boolean.getBoolean(ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY)
                || "true".equalsIgnoreCase(System.getenv(ALLOW_INSECURE_TRUSTED_SETUP_ENV));
    }

    public static String insecureTrustedSetupDisabledMessage() {
        return "Single-party trusted setup is disabled by default because the generator "
                + "knows toxic waste and can forge proofs. Production deployments must use "
                + "imported MPC ceremony artifacts and pinned artifact hashes. For local "
                + "development or tests only, start the JVM with -D"
                + ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY + "=true.";
    }

    public static void requireInsecureTrustedSetupEnabled() {
        if (!insecureTrustedSetupEnabled()) {
            throw new IllegalStateException(insecureTrustedSetupDisabledMessage());
        }
    }
}
