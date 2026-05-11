package com.bloxbean.cardano.zeroj.bbs.wasm;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsProof;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSecretKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec;
import com.bloxbean.cardano.zeroj.bbs.spi.BbsProvider;

import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

/**
 * Full Rust-WASM CFRG BBS provider. The entire BBS algorithm runs inside
 * WebAssembly (zkryptium 0.6.1 compiled to {@code wasm32-unknown-unknown})
 * executed through Chicory. ZeroJ's Java layer only serializes requests,
 * parses responses, and supplies entropy via the single named host import
 * {@code env.zeroj_host_getrandom}.
 *
 * <p>This provider is per-{@link BbsCiphersuite}. Construct one instance per
 * ciphersuite you intend to use. The underlying {@link Bbs12381WasmClient} is
 * thread-safe; the wrapper does no further synchronization.</p>
 */
public final class WasmBbsProvider implements BbsProvider {
    private final BbsCiphersuite ciphersuite;
    private final Bbs12381WasmClient client;

    public WasmBbsProvider(BbsCiphersuite ciphersuite, Bbs12381WasmClient client) {
        this.ciphersuite = Objects.requireNonNull(ciphersuite, "ciphersuite required");
        this.client = Objects.requireNonNull(client, "client required");
    }

    public static WasmBbsProvider createDefault() {
        return createDefault(BbsCiphersuite.BLS12381_SHA256);
    }

    public static WasmBbsProvider createDefault(BbsCiphersuite ciphersuite) {
        return new WasmBbsProvider(ciphersuite, Bbs12381WasmClient.createDefault());
    }

    public static WasmBbsProvider createDefault(BbsCiphersuite ciphersuite, SecureRandom random) {
        return new WasmBbsProvider(ciphersuite, Bbs12381WasmClient.createDefault(random));
    }

    @Override
    public String id() {
        return "zeroj-bbs-wasm-zkryptium";
    }

    @Override
    public BbsCiphersuite ciphersuite() {
        return ciphersuite;
    }

    @Override
    public BbsSecretKey keyGen(byte[] keyMaterial, byte[] keyInfo) {
        byte[] sk = client.keyGen(ciphersuite, keyMaterial, keyInfo);
        return new BbsSecretKey(BbsCodec.scalarFromBytes(sk, "BBS secret key"), ciphersuite);
    }

    @Override
    public BbsPublicKey skToPk(BbsSecretKey secretKey) {
        requireSuite(secretKey);
        byte[] pk = client.skToPk(ciphersuite, secretKey.toBytes());
        return new BbsPublicKey(pk, ciphersuite);
    }

    @Override
    public BbsSignature sign(
            BbsSecretKey secretKey, BbsPublicKey publicKey, List<byte[]> messages, byte[] header) {
        requireSuite(secretKey);
        requireSuite(publicKey);
        byte[] sig = client.sign(ciphersuite, secretKey.toBytes(), publicKey.bytes(), header, messages);
        return new BbsSignature(sig, ciphersuite);
    }

    @Override
    public boolean verify(
            BbsPublicKey publicKey, BbsSignature signature, List<byte[]> messages, byte[] header) {
        if (publicKey.ciphersuite() != ciphersuite || signature.ciphersuite() != ciphersuite) {
            return false;
        }
        return client.verify(ciphersuite, publicKey.bytes(), signature.bytes(), header, messages);
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
        // The supplied SecureRandom is honored only if the caller used a
        // dedicated WasmBbsProvider constructed with the same random. The
        // standard `createDefault` factory builds the client with its own
        // SecureRandom and ignores the per-call argument. This matches the
        // BbsProvider SPI semantics (the random is advisory).
        requireSuite(publicKey);
        requireSuite(signature);
        byte[] proof = client.proofGen(
                ciphersuite,
                publicKey.bytes(),
                signature.bytes(),
                header,
                presentationHeader,
                messages,
                disclosedIndexes);
        return new BbsProof(proof, ciphersuite);
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
        return client.proofVerify(
                ciphersuite,
                publicKey.bytes(),
                proof.bytes(),
                header,
                presentationHeader,
                disclosedMessages,
                disclosedIndexes);
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
