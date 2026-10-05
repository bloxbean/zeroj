package org.zeroj.circuit.lib.jubjub;

import java.util.Objects;

/**
 * A key-generation message as received from the broadcast mechanism, with the evidence that
 * its sender sent it (for example a signature, or a reference to a bulletin-board transaction).
 * The library hands both to {@link DkgAdmissionVerifier#authenticate} together with the
 * sender's roster key.
 *
 * @param message       the message bytes
 * @param authenticator the application's authenticity evidence for those bytes
 */
public record AuthenticatedDkgMessage(byte[] message, byte[] authenticator) {
    public AuthenticatedDkgMessage {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(authenticator, "authenticator");
        message = message.clone();
        authenticator = authenticator.clone();
    }

    @Override
    public byte[] message() {
        return message.clone();
    }

    @Override
    public byte[] authenticator() {
        return authenticator.clone();
    }
}
