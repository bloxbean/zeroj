package com.bloxbean.cardano.zeroj.bbs;

import java.util.Arrays;
import java.util.Objects;

/**
 * Revealed message and original message index for a BBS presentation.
 */
public final class BbsRevealedMessage {
    private final int index;
    private final byte[] message;

    public BbsRevealedMessage(int index, byte[] message) {
        if (index < 0) {
            throw new IllegalArgumentException("index must be non-negative");
        }
        Objects.requireNonNull(message, "message required");
        this.index = index;
        this.message = message.clone();
    }

    public int index() {
        return index;
    }

    public byte[] message() {
        return message.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof BbsRevealedMessage m
                && index == m.index
                && Arrays.equals(message, m.message);
    }

    @Override
    public int hashCode() {
        return 31 * index + Arrays.hashCode(message);
    }
}
