package org.zeroj.bbs.spi;

import org.zeroj.bbs.BbsCiphersuite;
import org.zeroj.bbs.BbsKeyPair;
import org.zeroj.bbs.BbsProof;
import org.zeroj.bbs.BbsPublicKey;
import org.zeroj.bbs.BbsSecretKey;
import org.zeroj.bbs.BbsSignature;

import java.security.SecureRandom;
import java.util.List;

/**
 * Provider boundary for CFRG BBS draft-10 implementations.
 */
public interface BbsProvider {
    String id();

    BbsCiphersuite ciphersuite();

    BbsSecretKey keyGen(byte[] keyMaterial, byte[] keyInfo);

    BbsPublicKey skToPk(BbsSecretKey secretKey);

    default BbsKeyPair keyPair(byte[] keyMaterial, byte[] keyInfo) {
        BbsSecretKey secretKey = keyGen(keyMaterial, keyInfo);
        return new BbsKeyPair(secretKey, skToPk(secretKey));
    }

    BbsSignature sign(BbsSecretKey secretKey, BbsPublicKey publicKey, List<byte[]> messages, byte[] header);

    default BbsSignature sign(BbsSecretKey secretKey, BbsPublicKey publicKey, byte[] header, List<byte[]> messages) {
        return sign(secretKey, publicKey, messages, header);
    }

    boolean verify(BbsPublicKey publicKey, BbsSignature signature, List<byte[]> messages, byte[] header);

    default boolean verify(BbsPublicKey publicKey, BbsSignature signature, byte[] header, List<byte[]> messages) {
        return verify(publicKey, signature, messages, header);
    }

    BbsProof proofGen(
            BbsPublicKey publicKey,
            BbsSignature signature,
            List<byte[]> messages,
            byte[] header,
            byte[] presentationHeader,
            int[] disclosedIndexes,
            SecureRandom random);

    boolean proofVerify(
            BbsPublicKey publicKey,
            BbsProof proof,
            byte[] header,
            byte[] presentationHeader,
            List<byte[]> disclosedMessages,
            int[] disclosedIndexes);
}
