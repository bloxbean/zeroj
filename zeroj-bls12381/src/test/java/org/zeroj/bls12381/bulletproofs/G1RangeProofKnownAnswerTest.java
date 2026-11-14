package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M1: the Java prover and verifier reproduce the known-answer trace pinned by the
 * independent Python implementation ({@code bulletproof-g1-reference/bulletproof_range_reference.py
 * --print-trace}, {@code PIN_TRACE}). None of these values was produced by the code under test; the
 * session identifier and every challenge were also reproduced by the CFRG drafts' own SHAKE128
 * sponge code during M0 review.
 */
class G1RangeProofKnownAnswerTest {

    private static final HexFormat HEX = HexFormat.of();

    static final int BITS = 16;
    static final BigInteger VALUE = BigInteger.valueOf(12345);
    static final BigInteger BLINDING = new BigInteger("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16);
    static final byte[] CTX = "hello".getBytes(StandardCharsets.US_ASCII);
    static final byte[] SEED = HEX.parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    static final String TAG = "ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
            + "/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0005:68656c6c6f";
    static final String SESSION_ID = "aefa01ae578defec57e942213978543a2e26bdf81ae69ac9e95dd3bda9ec7556";
    static final String COMMITMENT =
            "8c64f7f6919d77f06e79c9520d3af99c6064884d1bc3e1d8b97b63f0d2841cce045ba9fb77e7080fb5c3dae56624701e";
    static final String INSTANCE = "18000000706564657273656e2d626c7331322d3338312d67312d763180453f5474382da080469962"
            + "f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e92e04e91b89753df710400b28abb7d"
            + "8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab652000000062756c6c657470726f6f662d626c"
            + "7331322d3338312d67312d67656e732d763169abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef1910"
            + "0000008c64f7f6919d77f06e79c9520d3af99c6064884d1bc3e1d8b97b63f0d2841cce045ba9fb77e7080fb5c3dae56624701e";
    static final String Y = "36209000129655033253065255429180358080765337968981070404285725434891481435214";
    static final String Z = "46633051618233588676975911499950183005061894917303926296959925736837968283823";
    static final String X = "47228359020218805564661947561577753834407574540194626925198606108420299900437";
    static final String XU = "22143072433137489460645211340386941818930014091100376110692679921738536006978";
    static final List<String> XJ = List.of(
            "17735452590663590884174088837940452346824915976231644005372727082559053307244",
            "32939508233770058845369227004198000974479372739028121348871062643559301637578",
            "23879541988904653189122953040323391798477936798697311940928051176925699361449",
            "41826612228844513380365295144238554927794368972212012150612085629501841288776");
    static final String PROOF = "adad082dfddd9ed67f1ac22ccc4969c702769d58ba89787a2926cf8c47e5d272f602f9b2fbe8d934cc861b"
            + "9a4f537024a7f48ddec6a36c2841d0ca9705e00a7829d2fb4ab35489e38f78049d95b9a9ad26455a25459e89eb58209867c8fc27fa"
            + "ac3886e6dc0a05715afebce3f4539b49577cea41e76a8ff61eeb21b859c25cf41da4407c1bf3d4ed2da0c1f1e4b4df18912af42a08"
            + "f1601d89265c1aa4e349f615ed30d32b2a7d8863643ced634bb04e3236c966c3d5b39f7f0c9785e622b0046b3b50bcd8a594c77d87"
            + "8381f49008fe1142cafc9bc6e1c3c33df220f1f0fdf2419ccdb4dbaf404b0a61ba44304561bdf7fdc6fd325240b89fde47ad99a84b"
            + "320d90f8d7c62192725f2682f3bebf68f55e0b7662860dc9ace08538fe2af90f8887c36d60e42e7035d6a495baca385c9bb063eb63"
            + "31588a5964c52ff5b0bdf2c05146f2aea07094ac66628ad1860215a682c2261fb17700d6ccfd2013a25519d04a50fe394a95a6b805"
            + "b4e473625f0d1fd61ba4019f0ef3b56e1764a76ba735ca84cddf30c5ec832e06b53c724efc73144324b89cd08db9610a9dc7dccb99"
            + "070df9e3ada009cab374ef6da4220a4f0372936a35b480afdd212a13739342c19765c3e0beb723fa110839bf3185d75a17b25ceb98"
            + "143b11d1d9efae7d9773eb3d53b1fa434efd1be991dd8074d6b69ee86a7eba8732b72dd3802f6628588fbe5246aa8011e4963ce8ec"
            + "bfde7cd3454dcddb95af1dbc6a5f62cd951b91673fead403b214e52d10a48689df063f06ccb062ffe409a3bd61f046457372920d4b"
            + "57717aa48f892922c123bb2f0e85bbd0e970631e7091d664477011d78428d0475c8671bee756df4c160f5966d3a5b4652f1621994d"
            + "f89e6046c08781470de8e6a7a642ac8e4a72d3ca88c5e360c2020f2bb603540318bde0a587efac7952d1b11f634f3079f728fb44f7"
            + "5f9aa11a0a287794e5ac374163b9be164487311f236a4649c132c22f2a088521aa9c6305e07047ba0786d3e680d20c33ebf9e531bb"
            + "6588f086";

    @Test
    @DisplayName("Tag, session identifier and instance bytes equal the Python pins")
    void transcriptBytes() {
        assertEquals(TAG, new String(RangeTranscript.tag(BITS, CTX), StandardCharsets.US_ASCII));
        assertEquals(SESSION_ID, HEX.formatHex(DuplexSponge.deriveSessionId(RangeTranscript.tag(BITS, CTX))));
        G1PedersenCommitment v = G1Pedersen.pureJava().commitScalar(VALUE, BLINDING);
        assertEquals(COMMITMENT, HEX.formatHex(v.toPointBytes()));
        assertEquals(INSTANCE, HEX.formatHex(RangeTranscript.instance(BITS, PointCodec.point(v))));
    }

    @Test
    @DisplayName("The test-nonce prover reproduces the pinned proof byte for byte, and the verifier accepts it with the pinned challenges")
    void proofAndChallenges() {
        G1PedersenOpening opening = G1PedersenOpening.of(VALUE, BLINDING);
        G1RangeProof proof = TestNonceProver.prove(G1RangeProver.pureJava(), opening, BITS, CTX, SEED);
        assertEquals(PROOF, HEX.formatHex(proof.toBytes()));
        assertEquals(736, proof.toBytes().length);

        G1PedersenCommitment v = G1PedersenCommitment.decode(HEX.parseHex(COMMITMENT));
        G1RangeVerifier verifier = G1RangeVerifier.pureJava();
        assertTrue(verifier.verify(v, HEX.parseHex(PROOF), BITS, CTX));
        assertTrue(verifier.verify(HEX.parseHex(COMMITMENT), HEX.parseHex(PROOF), BITS, CTX));

        G1RangeVerifier.Outcome outcome = verifier.evaluate(PointCodec.point(v), G1RangeProof.decode(HEX.parseHex(PROOF), BITS), CTX);
        assertEquals(G1RangeVerifier.Layer.ACCEPT, outcome.layer());
        G1RangeVerifier.Challenges ch = outcome.challenges();
        assertArrayEquals(HEX.parseHex(SESSION_ID), ch.sessionId());
        assertArrayEquals(HEX.parseHex(INSTANCE), ch.instance());
        assertEquals(new BigInteger(Y), ch.y());
        assertEquals(new BigInteger(Z), ch.z());
        assertEquals(new BigInteger(X), ch.x());
        assertEquals(new BigInteger(XU), ch.xu());
        assertEquals(XJ.size(), ch.xj().length);
        for (int j = 0; j < XJ.size(); j++) {
            assertEquals(new BigInteger(XJ.get(j)), ch.xj()[j], "x_" + (j + 1));
        }
    }
}
