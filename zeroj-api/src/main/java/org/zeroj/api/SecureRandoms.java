package org.zeroj.api;

import java.security.ProviderException;
import java.security.SecureRandom;

/**
 * Default cryptographic randomness for ZeroJ (ADR-0057).
 *
 * <p>Oracle Web Image 25.3 reports os.name=Browser and substitutes the JCA default with
 * Math.random(). Refuse that runtime unless the selected provider explicitly implements the
 * reviewed host-entropy contract. Ordinary JVM/native behavior is unchanged.
 *
 * <p>This is a guard against accidental weak defaults, not against a malicious embedding host.
 * APIs accepting a caller-supplied SecureRandom retain their trusted-caller contract.
 */
public final class SecureRandoms {
    private SecureRandoms() {}

    /** Creates the platform default, rejecting unapproved Web Image providers before any draw. */
    public static SecureRandom create() {
        SecureRandom random = new SecureRandom();
        if ("Browser".equals(System.getProperty("os.name"))
                && !(random.getProvider() instanceof WebImageEntropyProvider)) {
            throw new ProviderException("Web Image requires a reviewed host entropy provider");
        }
        return random;
    }

    /**
     * Contract for a Web Image JCA provider: every draw uses the host CSPRNG, ignores seeds,
     * and fails closed when unavailable. Implementing this interface is a trust assertion,
     * not certification; embedders must audit and test the provider.
     */
    public interface WebImageEntropyProvider {}
}
