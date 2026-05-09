package com.bloxbean.cardano.zeroj.bbs;

import java.util.List;
import java.util.Objects;

/**
 * A CFRG BBS selective-disclosure presentation.
 */
public record BbsPresentation(
        BbsProof proof,
        byte[] header,
        byte[] presentationHeader,
        List<BbsRevealedMessage> revealedMessages
) {
    public BbsPresentation {
        Objects.requireNonNull(proof, "proof required");
        header = header != null ? header.clone() : new byte[0];
        presentationHeader = presentationHeader != null ? presentationHeader.clone() : new byte[0];
        revealedMessages = List.copyOf(Objects.requireNonNull(revealedMessages, "revealedMessages required"));
    }

    @Override
    public byte[] header() {
        return header.clone();
    }

    @Override
    public byte[] presentationHeader() {
        return presentationHeader.clone();
    }
}
