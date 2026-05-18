package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.mpf.MpfTrie;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonMpfAdapterTest {

    @Test
    void cclTrieVerifiesInclusionWithPoseidonAdapters() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("product:1001");
        byte[] value = bytes("batch=A;status=ok");

        trie.put(key, value);
        byte[] root = trie.getRootHash();
        byte[] proof = trie.getProofWire(key).orElseThrow();

        assertArrayEquals(value, trie.get(key));
        assertTrue(PoseidonMpfReference.including(root, key, value, proof));
        assertTrue(trie.verifyProofWire(root, key, value, true, proof));
    }

    @Test
    void cclTrieVerifiesExclusionWithPoseidonAdapters() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("product:1001"), bytes("ok"));
        trie.put(bytes("product:1002"), bytes("ok"));
        trie.put(bytes("product:1003"), bytes("recalled"));

        byte[] missing = bytes("product:9999");
        byte[] root = trie.getRootHash();
        byte[] proof = trie.getProofWire(missing).orElseThrow();

        assertNull(trie.get(missing));
        assertTrue(PoseidonMpfReference.excluding(root, missing, proof));
        assertTrue(trie.verifyProofWire(root, missing, null, false, proof));
    }

    @Test
    void tamperedValueFailsReferenceVerification() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("product:1001");
        byte[] value = bytes("ok");
        trie.put(key, value);

        byte[] proof = trie.getProofWire(key).orElseThrow();
        assertFalse(PoseidonMpfReference.including(trie.getRootHash(), key, bytes("bad"), proof));
    }

    @Test
    void codecProducesStablePaddedWitnessArrays() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("product:1001");
        byte[] value = bytes("ok");
        trie.put(key, value);

        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(key, trie.getProofWire(key).orElseThrow(), 8, 2);

        assertEquals(PoseidonMpfHash.KEY_PATH_NIBBLES, witness.keyPath().size());
        assertEquals(8, witness.kind().size());
        assertEquals(8, witness.neighbors().size());
        assertEquals(4, witness.neighbors().getFirst().size());
        assertEquals(8, witness.forkPrefixChunks().size());
        assertEquals(2, witness.forkPrefixChunks().getFirst().size());
        assertTrue(witness.valid().stream().allMatch(v -> v.equals(BigInteger.ONE) || v.equals(BigInteger.ZERO)));
    }

    @Test
    void codecRejectsProofsLongerThanMaxSteps() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("product:1001"), bytes("ok"));
        trie.put(bytes("product:1002"), bytes("ok"));

        byte[] proof = trie.getProofWire(bytes("product:1001")).orElseThrow();
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.toWitness(bytes("product:1001"), proof, 0, 2));
    }

    @Test
    void valueCommitmentMatchesHashFunctionDigest() {
        byte[] value = bytes("some value");
        byte[] digest = PoseidonMpfValueCommitment.digest(value);
        assertEquals(PoseidonMpfHash.fieldFromDigestBytes(digest), PoseidonMpfValueCommitment.field(value));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
