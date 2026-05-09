package com.bloxbean.cardano.zeroj.bbs;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;

import java.nio.charset.StandardCharsets;

/**
 * CFRG BBS ciphersuites supported by ZeroJ.
 */
public enum BbsCiphersuite {
    BLS12381_SHA256(
            "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
            "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"),
    BLS12381_SHAKE256(
            "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
            "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755");

    public static final String DEFAULT_PROOF_FORMAT = "bbs-cfrg-draft10-presentation-cbor-v1";

    private final String ciphersuiteId;
    private final byte[] ciphersuiteIdBytes;
    private final byte[] apiId;
    private final G1Point p1;

    BbsCiphersuite(String ciphersuiteId, String p1CompressedHex) {
        this.ciphersuiteId = ciphersuiteId;
        this.ciphersuiteIdBytes = ciphersuiteId.getBytes(StandardCharsets.US_ASCII);
        this.apiId = (ciphersuiteId + "H2G_HM2S_").getBytes(StandardCharsets.US_ASCII);
        this.p1 = Bls12381Codecs.g1FromCompressed(hexToBytes(p1CompressedHex));
    }

    public String ciphersuiteId() {
        return ciphersuiteId;
    }

    public byte[] ciphersuiteIdBytes() {
        return ciphersuiteIdBytes.clone();
    }

    public byte[] apiId() {
        return apiId.clone();
    }

    public G1Point p1() {
        return p1;
    }

    public int scalarBytes() {
        return Bls12381Codecs.SCALAR_BYTES;
    }

    public int g1Bytes() {
        return Bls12381Codecs.G1_COMPRESSED_BYTES;
    }

    public int g2Bytes() {
        return Bls12381Codecs.G2_COMPRESSED_BYTES;
    }

    public int expandLen() {
        return 48;
    }

    public static BbsCiphersuite fromCiphersuiteId(String ciphersuiteId) {
        for (BbsCiphersuite ciphersuite : values()) {
            if (ciphersuite.ciphersuiteId.equals(ciphersuiteId)) {
                return ciphersuite;
            }
        }
        throw new IllegalArgumentException("Unknown BBS ciphersuite: " + ciphersuiteId);
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
