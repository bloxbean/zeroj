package com.bloxbean.cardano.zeroj.bbs.wasm;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSecretKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bls12381.wasm.WasmBls12381Provider;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class WasmBbsProviderTest {
    private static final BbsCiphersuite SUITE = BbsCiphersuite.BLS12381_SHA256;
    private static final byte[] KEY_MATERIAL = hex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
    private static final byte[] KEY_INFO = hex("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
    private static final byte[] SK = hex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc");
    private static final byte[] PK = hex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    private static final byte[] HEADER = hex("11223344556677889900aabbccddeeff");
    private static final byte[] PRESENTATION_HEADER = hex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
    private static final byte[] MULTI_SIGNATURE = hex("8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8");
    private static final byte[] SOME_DISCLOSED_PROOF = hex("a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a");

    @Test
    void providerMatchesDraft10KeyAndSignatureVectors() {
        var provider = WasmBbsProvider.createDefault();
        BbsSecretKey secretKey = provider.keyGen(KEY_MATERIAL, KEY_INFO);
        BbsPublicKey publicKey = provider.skToPk(secretKey);

        assertArrayEquals(SK, secretKey.toBytes());
        assertArrayEquals(PK, publicKey.bytes());

        BbsSignature signature = provider.sign(secretKey, publicKey, messages(), HEADER);
        assertArrayEquals(MULTI_SIGNATURE, signature.bytes());
        assertTrue(provider.verify(publicKey, signature, messages(), HEADER));
    }

    @Test
    void wasmBlsProviderVerifiesOfficialSomeDisclosedProofVector() {
        var bls = WasmBls12381Provider.createDefault();
        int[] disclosedIndexes = {0, 2, 4, 6};
        List<byte[]> disclosedMessages = Arrays.stream(disclosedIndexes)
                .mapToObj(messages()::get)
                .toList();

        assertTrue(CfrgBbsCore.proofVerify(
                PK,
                SOME_DISCLOSED_PROOF,
                HEADER,
                PRESENTATION_HEADER,
                disclosedMessages,
                disclosedIndexes,
                SUITE,
                bls));
    }

    private static List<byte[]> messages() {
        return List.of(
                hex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
                hex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
                hex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
                hex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
                hex("496694774c5604ab1b2544eababcf0f53278ff50"),
                hex("515ae153e22aae04ad16f759e07237b4"),
                hex("d183ddc6e2665aa4e2f088af"),
                hex("ac55fb33a75909ed"),
                hex("96012096"),
                new byte[0]);
    }

    private static byte[] hex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
