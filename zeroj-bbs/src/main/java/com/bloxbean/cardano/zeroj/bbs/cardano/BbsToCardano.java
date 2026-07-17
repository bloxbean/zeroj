package com.bloxbean.cardano.zeroj.bbs.cardano;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsRevealedMessage;
import com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Off-chain bridge from BBS to a Cardano on-chain BBS verifier: derives the issuer verification
 * material an on-chain validator bakes in as parameters, and flattens a {@link BbsPresentation} into
 * the point/scalar values that validator consumes as its redeemer.
 *
 * <p>This is the BBS analog of the {@code SnarkjsToCardano} / {@code ProverToCardano} codecs in
 * {@code zeroj-onchain-julc}: plain off-chain Java (it runs in the application JVM before a tx is
 * built), producing {@code byte[]} / {@link BigInteger} values with no dependency on Julc, Plutus, or
 * cardano-client-lib. The matching on-chain gadget is
 * {@code com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib.BbsProofVerify}.</p>
 *
 * <p>All outputs are deterministic from the issuer's public key + the credential schema/header (for
 * the params) or from the presentation itself (for the proof), so {@link #verifierParams} can be
 * computed once and cached. Everything here targets the {@code BLS12381G1-SHA-256} ciphersuite — the
 * only BBS ciphersuite practical on Plutus.</p>
 */
public final class BbsToCardano {

    private BbsToCardano() {}

    /**
     * The issuer verification material an on-chain BBS validator bakes in as {@code @Param}s. All
     * fields are compressed points / a big-endian scalar / ASCII DSTs — directly usable as Plutus
     * {@code byte[]} parameters.
     *
     * @param publicKey       issuer BBS public key {@code W} (G2 compressed, 96 B)
     * @param g2Generator     the G2 generator {@code BP2} (compressed, 96 B)
     * @param p1              ciphersuite {@code P1} (G1 compressed, 48 B)
     * @param q1              BBS generator {@code Q1} (G1 compressed, 48 B)
     * @param h               BBS generators {@code H_1..H_L} (G1 compressed), one per message
     * @param domain          precomputed 32-byte big-endian {@code domain} scalar
     * @param dstHashToScalar the {@code H2S_} domain separation tag
     * @param dstMapToScalar  the {@code MAP_MSG_TO_SCALAR_AS_HASH_} domain separation tag
     */
    public record VerifierParams(byte[] publicKey, byte[] g2Generator, byte[] p1, byte[] q1,
                                 List<byte[]> h, byte[] domain,
                                 byte[] dstHashToScalar, byte[] dstMapToScalar) {}

    /**
     * A presentation flattened for an on-chain redeemer: the three proof points, the Schnorr responses
     * ({@code eHat, r1Hat, r3Hat} and one {@code mHat} per <b>undisclosed</b> message), the challenge,
     * the revealed messages (index + bytes), and the presentation header.
     */
    public record OnChainProof(byte[] aBar, byte[] bBar, byte[] d,
                               BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
                               List<BigInteger> mHats, BigInteger challenge,
                               List<Disclosed> disclosed, byte[] presentationHeader) {}

    /** One revealed message: its schema index and cleartext bytes. */
    public record Disclosed(int index, byte[] message) {}

    /** {@link #verifierParams(BbsPublicKey, byte[], int, BbsCiphersuite)} for the SHA-256 ciphersuite. */
    public static VerifierParams verifierParams(BbsPublicKey publicKey, byte[] header, int messageCount) {
        return verifierParams(publicKey, header, messageCount, BbsCiphersuite.BLS12381_SHA256);
    }

    /**
     * Derive the on-chain verifier parameters for {@code publicKey} signing {@code messageCount}
     * messages under {@code header}. The generators are ciphersuite-derived (count + 1), so the whole
     * result is deterministic and can be baked into the validator's script hash.
     */
    public static VerifierParams verifierParams(BbsPublicKey publicKey, byte[] header,
                                                int messageCount, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(publicKey, "publicKey required");
        Objects.requireNonNull(header, "header required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        if (messageCount <= 0) {
            throw new IllegalArgumentException("messageCount must be positive");
        }
        Bls12381Provider bls = Bls12381Providers.pureJava();
        byte[] apiId = ciphersuite.apiId();
        byte[] w = publicKey.bytes();
        CfrgBbsCore.Generators gens = CfrgBbsCore.createGenerators(messageCount + 1, ciphersuite, bls);
        List<byte[]> h = new ArrayList<>(messageCount);
        for (int i = 0; i < messageCount; i++) {
            h.add(g1c(gens.h().get(i)));
        }
        return new VerifierParams(
                w,
                Bls12381Codecs.g2ToCompressed(bls.g2Generator()),
                g1c(ciphersuite.p1()),
                g1c(gens.q1()),
                h,
                BbsCodec.scalarToBytesAllowZero(CfrgBbsCore.calculateDomain(w, gens, header, ciphersuite)),
                concat(apiId, "H2S_".getBytes(StandardCharsets.US_ASCII)),
                concat(apiId, "MAP_MSG_TO_SCALAR_AS_HASH_".getBytes(StandardCharsets.US_ASCII)));
    }

    /** {@link #onChainProof(BbsPresentation, BbsCiphersuite)} for the SHA-256 ciphersuite. */
    public static OnChainProof onChainProof(BbsPresentation presentation) {
        return onChainProof(presentation, BbsCiphersuite.BLS12381_SHA256);
    }

    /**
     * Flatten {@code presentation} into the redeemer values an on-chain BBS verifier consumes. The
     * revealed messages carry their schema index so a validator can enforce which attributes were
     * disclosed; the undisclosed messages appear only as blinded {@code mHat} responses.
     */
    public static OnChainProof onChainProof(BbsPresentation presentation, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(presentation, "presentation required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        BbsCodec.ProofParts pp = BbsCodec.octetsToProof(presentation.proof().bytes(), ciphersuite);
        List<Disclosed> disclosed = new ArrayList<>();
        for (BbsRevealedMessage rm : presentation.revealedMessages()) {
            disclosed.add(new Disclosed(rm.index(), rm.message()));
        }
        // BBS binds disclosed messages to the challenge in ascending-index order; presentations built
        // by BbsService are already ordered, but a hand-constructed one may not be.
        disclosed.sort(Comparator.comparingInt(Disclosed::index));
        return new OnChainProof(
                g1c(pp.aBar()), g1c(pp.bBar()), g1c(pp.d()),
                pp.eHat(), pp.r1Hat(), pp.r3Hat(), pp.mHats(), pp.challenge(),
                disclosed, presentation.presentationHeader());
    }

    private static byte[] g1c(G1Point p) {
        return Bls12381Codecs.g1ToCompressed(p);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
