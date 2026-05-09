package com.bloxbean.cardano.zeroj.bbs.wasm;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsProof;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSecretKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProvider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.wasm.WasmBls12381Provider;

import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

/**
 * CFRG BBS provider backed by the ZeroJ BLS12-381 Rust WASM provider.
 */
public final class WasmBbsProvider implements BbsProvider {
    private final BbsCiphersuite ciphersuite;
    private final Bls12381Provider bls;

    public WasmBbsProvider(BbsCiphersuite ciphersuite, Bls12381Provider bls) {
        this.ciphersuite = Objects.requireNonNull(ciphersuite, "ciphersuite required");
        this.bls = Objects.requireNonNull(bls, "BLS provider required");
    }

    public static WasmBbsProvider createDefault() {
        return new WasmBbsProvider(BbsCiphersuite.BLS12381_SHA256, WasmBls12381Provider.createDefault());
    }

    @Override
    public String id() {
        return "zeroj-bbs-wasm-bls12381-zkcrypto";
    }

    @Override
    public BbsCiphersuite ciphersuite() {
        return ciphersuite;
    }

    @Override
    public BbsSecretKey keyGen(byte[] keyMaterial, byte[] keyInfo) {
        return new BbsSecretKey(CfrgBbsCore.keyGen(ciphersuite, keyMaterial, keyInfo), ciphersuite);
    }

    @Override
    public BbsPublicKey skToPk(BbsSecretKey secretKey) {
        requireSuite(secretKey);
        return new BbsPublicKey(CfrgBbsCore.skToPk(secretKey.value(), bls), ciphersuite);
    }

    @Override
    public BbsSignature sign(BbsSecretKey secretKey, BbsPublicKey publicKey, List<byte[]> messages, byte[] header) {
        requireSuite(secretKey);
        requireSuite(publicKey);
        return new BbsSignature(CfrgBbsCore.sign(
                secretKey.value(), publicKey.bytes(), messages, header, ciphersuite, bls), ciphersuite);
    }

    @Override
    public boolean verify(BbsPublicKey publicKey, BbsSignature signature, List<byte[]> messages, byte[] header) {
        if (publicKey.ciphersuite() != ciphersuite || signature.ciphersuite() != ciphersuite) {
            return false;
        }
        return CfrgBbsCore.verify(publicKey.bytes(), signature.bytes(), messages, header, ciphersuite, bls);
    }

    @Override
    public BbsProof proofGen(
            BbsPublicKey publicKey,
            BbsSignature signature,
            List<byte[]> messages,
            byte[] header,
            byte[] presentationHeader,
            int[] disclosedIndexes,
            SecureRandom random) {
        requireSuite(publicKey);
        requireSuite(signature);
        return new BbsProof(CfrgBbsCore.proofGen(
                publicKey.bytes(),
                signature.bytes(),
                messages,
                header,
                presentationHeader,
                disclosedIndexes,
                ciphersuite,
                bls,
                random), ciphersuite);
    }

    @Override
    public boolean proofVerify(
            BbsPublicKey publicKey,
            BbsProof proof,
            byte[] header,
            byte[] presentationHeader,
            List<byte[]> disclosedMessages,
            int[] disclosedIndexes) {
        if (publicKey.ciphersuite() != ciphersuite || proof.ciphersuite() != ciphersuite) {
            return false;
        }
        return CfrgBbsCore.proofVerify(
                publicKey.bytes(),
                proof.bytes(),
                header,
                presentationHeader,
                disclosedMessages,
                disclosedIndexes,
                ciphersuite,
                bls);
    }

    private void requireSuite(BbsSecretKey secretKey) {
        if (Objects.requireNonNull(secretKey, "secret key required").ciphersuite() != ciphersuite) {
            throw new IllegalArgumentException("BBS secret key ciphersuite mismatch");
        }
    }

    private void requireSuite(BbsPublicKey publicKey) {
        if (Objects.requireNonNull(publicKey, "public key required").ciphersuite() != ciphersuite) {
            throw new IllegalArgumentException("BBS public key ciphersuite mismatch");
        }
    }

    private void requireSuite(BbsSignature signature) {
        if (Objects.requireNonNull(signature, "signature required").ciphersuite() != ciphersuite) {
            throw new IllegalArgumentException("BBS signature ciphersuite mismatch");
        }
    }
}
