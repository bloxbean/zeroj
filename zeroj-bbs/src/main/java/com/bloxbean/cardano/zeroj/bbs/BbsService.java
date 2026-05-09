package com.bloxbean.cardano.zeroj.bbs;

import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProvider;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProviders;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;

import java.security.SecureRandom;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * High-level CFRG BBS draft-10 service.
 */
public final class BbsService {
    private final BbsProvider provider;
    private final SecureRandom random;

    public BbsService(BbsProvider provider) {
        this(provider, new SecureRandom());
    }

    public BbsService(BbsProvider provider, SecureRandom random) {
        this.provider = Objects.requireNonNull(provider, "provider required");
        this.random = Objects.requireNonNull(random, "secure random required");
    }

    public static BbsService pureJava() {
        return new BbsService(BbsProviders.pureJava());
    }

    public static BbsService pureJava(BbsCiphersuite ciphersuite) {
        return new BbsService(BbsProviders.pureJava(ciphersuite));
    }

    public static BbsService withBlsProvider(BbsCiphersuite ciphersuite, Bls12381Provider bls) {
        return new BbsService(BbsProviders.withBlsProvider(ciphersuite, bls));
    }

    public BbsProvider provider() {
        return provider;
    }

    public BbsKeyPair keyPair(byte[] keyMaterial, byte[] keyInfo) {
        return provider.keyPair(keyMaterial, keyInfo);
    }

    /**
     * Sign messages with the ZeroJ argument order: messages before header.
     *
     * <p>For the draft-10 order, use {@link #sign(BbsSecretKey, BbsPublicKey, byte[], List)}.</p>
     */
    public BbsSignature sign(BbsSecretKey secretKey, BbsPublicKey publicKey, List<byte[]> messages, byte[] header) {
        return provider.sign(secretKey, publicKey, messages, header);
    }

    /**
     * Sign messages with the draft-10 argument order: header before messages.
     */
    public BbsSignature sign(BbsSecretKey secretKey, BbsPublicKey publicKey, byte[] header, List<byte[]> messages) {
        return sign(secretKey, publicKey, messages, header);
    }

    /**
     * Verify a signature with the ZeroJ argument order: messages before header.
     *
     * <p>For the draft-10 order, use {@link #verify(BbsPublicKey, BbsSignature, byte[], List)}.</p>
     */
    public boolean verify(BbsPublicKey publicKey, BbsSignature signature, List<byte[]> messages, byte[] header) {
        return provider.verify(publicKey, signature, messages, header);
    }

    /**
     * Verify a signature with the draft-10 argument order: header before messages.
     */
    public boolean verify(BbsPublicKey publicKey, BbsSignature signature, byte[] header, List<byte[]> messages) {
        return verify(publicKey, signature, messages, header);
    }

    public BbsPresentation derivePresentation(
            BbsPublicKey publicKey,
            BbsSignature signature,
            List<byte[]> messages,
            byte[] header,
            byte[] presentationHeader,
            int[] disclosedIndexes) {
        Objects.requireNonNull(messages, "messages required");
        int[] indexes = validateDisclosedIndexes(disclosedIndexes, messages.size());
        BbsProof proof = provider.proofGen(
                publicKey, signature, messages, header, presentationHeader, indexes, random);
        List<BbsRevealedMessage> revealedMessages = revealedMessages(messages, indexes);
        return new BbsPresentation(proof, header, presentationHeader, revealedMessages);
    }

    public boolean verifyPresentation(BbsPublicKey publicKey, BbsPresentation presentation) {
        Objects.requireNonNull(presentation, "presentation required");
        List<BbsRevealedMessage> revealed = presentation.revealedMessages().stream()
                .sorted(Comparator.comparingInt(BbsRevealedMessage::index))
                .toList();
        int[] indexes = revealed.stream().mapToInt(BbsRevealedMessage::index).toArray();
        validateDisclosedIndexes(indexes, hiddenMessageCountFromProof(presentation.proof()) + revealed.size());
        List<byte[]> messages = revealed.stream().map(BbsRevealedMessage::message).toList();
        return provider.proofVerify(
                publicKey,
                presentation.proof(),
                presentation.header(),
                presentation.presentationHeader(),
                messages,
                indexes);
    }

    private static List<BbsRevealedMessage> revealedMessages(List<byte[]> messages, int[] indexes) {
        Objects.requireNonNull(messages, "messages required");
        return java.util.Arrays.stream(indexes)
                .mapToObj(index -> new BbsRevealedMessage(index, messages.get(index)))
                .toList();
    }

    private static int[] validateDisclosedIndexes(int[] indexes, int messageCount) {
        try {
            return CfrgBbsCore.validateDisclosedIndexes(indexes, messageCount);
        } catch (RuntimeException e) {
            throw new BbsException("Invalid BBS disclosed indexes", e);
        }
    }

    private static int hiddenMessageCountFromProof(BbsProof proof) {
        BbsCiphersuite ciphersuite = proof.ciphersuite();
        int scalarBytes = proof.bytes().length - 3 * ciphersuite.g1Bytes();
        int scalarCount = scalarBytes / ciphersuite.scalarBytes();
        return scalarCount - 4;
    }
}
