package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

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

    @Test
    void v2DigestIsTotalForArbitraryByteArrays() {
        Random random = new Random(25L);
        for (int length = 0; length <= 512; length++) {
            byte[] input = new byte[length];
            random.nextBytes(input);

            byte[] digest = PoseidonMpfHash.digest(input);

            assertEquals(PoseidonMpfHash.DIGEST_LENGTH, digest.length, "length=" + length);
            assertDoesNotThrow(() -> PoseidonMpfHash.fieldFromDigestBytes(digest), "length=" + length);
        }
    }

    @Test
    void nonCanonicalScalarChunkUsesV2RawByteFallback() {
        byte[] input = new byte[32];
        Arrays.fill(input, (byte) 0xff);

        BigInteger expected = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                PoseidonMpfHash.DOMAIN_RAW_BYTES_V2,
                BigInteger.valueOf(input.length),
                PoseidonMpfHash.unsigned(Arrays.copyOfRange(input, 0, 31)),
                PoseidonMpfHash.unsigned(Arrays.copyOfRange(input, 31, 32)));

        assertEquals(expected, PoseidonMpfHash.digestField(PoseidonParamsBLS12_381T3.INSTANCE, input));
    }

    @Test
    void inputsBeyondInternalNinetySixByteBoundUseFallback() {
        byte[] input = new byte[257];
        Arrays.fill(input, (byte) 0xa5);

        byte[] first = PoseidonMpfHash.digest(input);
        byte[] second = PoseidonMpfHash.digest(input);

        assertArrayEquals(first, second);
        assertEquals("zeroj-poseidon-mpf-v2", PoseidonMpfHash.PROFILE_ID);
    }

    @Test
    void fastBlsPoseidonIsBitIdenticalToBigIntegerReference() {
        Random random = new Random(41L);
        BigInteger prime = com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime();
        for (int arity = 1; arity <= 9; arity++) {
            for (int vector = 0; vector < 20; vector++) {
                BigInteger[] inputs = new BigInteger[arity];
                for (int i = 0; i < inputs.length; i++) {
                    inputs[i] = new BigInteger(320, random).subtract(new BigInteger(64, random));
                }
                BigInteger expected = PoseidonHash.hashN(PoseidonParamsBLS12_381T3.INSTANCE, inputs);
                BigInteger actual = PoseidonMpfHash.hashFields(PoseidonParamsBLS12_381T3.INSTANCE, inputs);
                assertEquals(expected.mod(prime), actual, "arity=" + arity + ", vector=" + vector);
            }
        }
    }

    @Test
    void directPairHashIsBitIdenticalToFixedByteProfile() {
        Random random = new Random(52L);
        BigInteger prime = com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime();
        for (int vector = 0; vector < 100; vector++) {
            byte[] left = PoseidonMpfHash.toDigestBytes(new BigInteger(320, random).mod(prime));
            byte[] right = PoseidonMpfHash.toDigestBytes(new BigInteger(320, random).mod(prime));

            byte[] expected = PoseidonMpfHash.digest(PoseidonMpfCommitmentScheme.concat(left, right));
            byte[] actual = PoseidonMpfHash.digestPair(
                    PoseidonParamsBLS12_381T3.INSTANCE, left, right);

            assertArrayEquals(expected, actual, "vector=" + vector);
        }
    }

    @Test
    void boundedPairCachePreservesEveryRootAndGetsReuse() {
        var uncachedCommitments = new PoseidonMpfCommitmentScheme(
                PoseidonParamsBLS12_381T3.INSTANCE, 0);
        var cachedCommitments = new PoseidonMpfCommitmentScheme(
                PoseidonParamsBLS12_381T3.INSTANCE, 4_096);
        var uncached = new MpfTrie(
                new InMemoryNodeStore(), PoseidonMpfHashFunction.INSTANCE, null, uncachedCommitments);
        var cached = new MpfTrie(
                new InMemoryNodeStore(), PoseidonMpfHashFunction.INSTANCE, null, cachedCommitments);

        for (int i = 0; i < 128; i++) {
            byte[] key = bytes("cache-key-" + i);
            byte[] value = bytes("cache-value-" + i);
            uncached.put(key, value);
            cached.put(key, value);
            assertArrayEquals(uncached.getRootHash(), cached.getRootHash(), "entry=" + i);
        }

        var stats = cachedCommitments.pairCacheStats();
        assertTrue(stats.hits() > 0);
        assertTrue(stats.size() <= stats.capacity());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
