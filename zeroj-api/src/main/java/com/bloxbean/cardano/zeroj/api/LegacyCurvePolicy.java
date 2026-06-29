package com.bloxbean.cardano.zeroj.api;

/**
 * Central policy for legacy curves that are not part of the Cardano production surface.
 */
public final class LegacyCurvePolicy {

    public static final String ALLOW_LEGACY_BN254_PROPERTY = "zeroj.allowLegacyBn254";
    public static final String ALLOW_LEGACY_BN254_ENV = "ZEROJ_ALLOW_LEGACY_BN254";

    private LegacyCurvePolicy() {}

    public static boolean legacyBn254Enabled() {
        return Boolean.getBoolean(ALLOW_LEGACY_BN254_PROPERTY)
                || "true".equalsIgnoreCase(System.getenv(ALLOW_LEGACY_BN254_ENV));
    }

    public static String legacyBn254DisabledMessage() {
        return "BN254 is disabled by default because ZeroJ targets Cardano "
                + "production flows and Cardano only supports BLS12-381 on-chain. "
                + "For legacy off-chain experiments, start the JVM with -D"
                + ALLOW_LEGACY_BN254_PROPERTY + "=true.";
    }

    public static void requireLegacyBn254Enabled() {
        if (!legacyBn254Enabled()) {
            throw new IllegalStateException(legacyBn254DisabledMessage());
        }
    }
}
