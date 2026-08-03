package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Tag;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.vds.mpf.proof.ProofVerifier;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBN254T3;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfWitness;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonMpfAdapterTest {

    @Test
    void cclTrieVerifiesInclusionWithPoseidonAdapters() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
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
    void strictVerifierRejectsTrailingNonCanonicalOversizedAndOverdeepProofs() throws Exception {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("only-key");
        byte[] value = bytes("only-value");
        trie.put(key, value);
        byte[] root = trie.getRootHash();
        byte[] proof = trie.getProofWire(key).orElseThrow();
        assertArrayEquals(new byte[]{(byte) 0x80}, proof, "one leaf has a canonical empty path");
        assertTrue(PoseidonMpfReference.including(root, key, value, proof));

        byte[] appended = Arrays.copyOf(proof, proof.length + 1);
        assertFalse(PoseidonMpfReference.including(root, key, value, appended));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(appended));

        byte[] indefiniteEmptyArray = {(byte) 0x9f, (byte) 0xff};
        assertFalse(PoseidonMpfReference.including(root, key, value, indefiniteEmptyArray));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.decode(indefiniteEmptyArray));

        byte[] oversized = new byte[PoseidonMpfCodec.MAX_PROOF_BYTES + 1];
        assertFalse(PoseidonMpfReference.including(root, key, value, oversized));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(oversized));

        Array overdeep = new Array();
        for (int index = 0; index <= PoseidonMpfCodec.MAX_PROOF_STEPS; index++) {
            Array branch = new Array();
            branch.setTag(121);
            branch.add(new UnsignedInteger(0));
            branch.add(new ByteString(new byte[4 * PoseidonMpfHash.DIGEST_LENGTH]));
            overdeep.add(branch);
        }
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        new CborEncoder(encoded).encode(overdeep);
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.decode(encoded.toByteArray()));

        byte[] declaredHugeByteString = {
                (byte) 0x81, (byte) 0xd8, 0x79, (byte) 0x82, 0x00,
                0x5a, 0x10, 0x00, 0x00, 0x00
        };
        byte[] declaredHugeArray = {
                (byte) 0x9a, 0x10, 0x00, 0x00, 0x00
        };
        for (byte[] hostile : new byte[][]{declaredHugeByteString, declaredHugeArray}) {
            assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(hostile));
            assertFalse(PoseidonMpfReference.including(root, key, value, hostile));
        }
    }

    @Test
    void strictCodecRejectsExtraneousSemanticTagsAtEveryGrammarLayer() throws Exception {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("tag-key-a"), bytes("one"));
        trie.put(bytes("tag-key-b"), bytes("two"));
        byte[] key = bytes("tag-key-a");
        byte[] value = bytes("one");
        byte[] root = trie.getRootHash();
        byte[] proof = trie.getProofWire(key).orElseThrow();
        assertTrue(PoseidonMpfReference.including(root, key, value, proof));

        assertTaggedMutationRejected(root, key, value, proof, item -> item.setTag(24));
        assertTaggedMutationRejected(root, key, value, proof, item -> {
            Array step = (Array) ((Array) item).getDataItems().getFirst();
            step.getTag().setTag(1000);
        });
        assertTaggedMutationRejected(root, key, value, proof, item -> {
            Array step = (Array) ((Array) item).getDataItems().getFirst();
            step.getDataItems().get(0).setTag(24);
        });
        assertTaggedMutationRejected(root, key, value, proof, item -> {
            Array step = (Array) ((Array) item).getDataItems().getFirst();
            step.getDataItems().get(1).setTag(24);
        });

        Array forkNeighbor = new Array();
        forkNeighbor.setTag(121);
        forkNeighbor.add(new UnsignedInteger(1));
        forkNeighbor.add(new ByteString(new byte[0]));
        forkNeighbor.add(new ByteString(new byte[PoseidonMpfHash.DIGEST_LENGTH]));
        Array fork = new Array();
        fork.setTag(122);
        fork.add(new UnsignedInteger(0));
        fork.add(forkNeighbor);
        Array forkRoot = new Array();
        forkRoot.add(fork);
        byte[] canonicalFork = encode(forkRoot);
        assertDoesNotThrow(() -> PoseidonMpfCodec.decode(canonicalFork));

        forkNeighbor.getTag().setTag(24);
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.decode(encode(forkRoot)));
    }

    @Test
    void cclTrieVerifiesExclusionWithPoseidonAdapters() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("product:1001"), bytes("ok"));
        trie.put(bytes("product:1002"), bytes("ok"));
        trie.put(bytes("product:1003"), bytes("recalled"));

        byte[] missing = bytes("product:9999");
        byte[] root = trie.getRootHash();
        byte[] proof = trie.getProofWire(missing).orElseThrow();

        assertNull(trie.get(missing));
        assertTrue(PoseidonMpfReference.excluding(root, missing, proof));
        assertTrue(trie.verifyProofWire(root, missing, null, false, proof));
        assertFalse(PoseidonMpfReference.verify(
                PoseidonParamsBLS12_381T3.INSTANCE,
                root, missing, bytes("ignored-value"), false, proof));
        assertFalse(trie.verifyProofWire(root, missing, bytes("ignored-value"), false, proof));
    }

    @Test
    void tamperedValueFailsReferenceVerification() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("product:1001");
        byte[] value = bytes("ok");
        trie.put(key, value);

        byte[] proof = trie.getProofWire(key).orElseThrow();
        assertFalse(PoseidonMpfReference.including(trie.getRootHash(), key, bytes("bad"), proof));
    }

    @Test
    void codecProducesStablePaddedWitnessArrays() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
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
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("product:1001"), bytes("ok"));
        trie.put(bytes("product:1002"), bytes("ok"));

        byte[] proof = trie.getProofWire(bytes("product:1001")).orElseThrow();
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.toWitness(bytes("product:1001"), proof, 0, 2));
    }

    @Test
    void fullSemanticsForkWidthIsExactAndAllocationBounded() {
        byte[] emptyProof = {(byte) 0x80};
        byte[] key = bytes("bounded-fork-width");
        assertDoesNotThrow(() -> PoseidonMpfCodec.toWitness(key, emptyProof, 0, 0));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.toWitness(key, emptyProof, 0, 2));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.toWitness(key, emptyProof, 1, 1));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.toWitness(key, emptyProof, 1, 3));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCodec.toWitness(key, emptyProof, 1, Integer.MAX_VALUE));
    }

    @Test
    void valueCommitmentMatchesHashFunctionDigest() {
        byte[] value = bytes("some value");
        byte[] digest = PoseidonMpfValueCommitment.digest(value);
        assertEquals(PoseidonMpfHash.fieldFromDigestBytes(digest), PoseidonMpfValueCommitment.field(value));
    }

    @Test
    void v1DigestIsTotalForArbitraryByteArrays() {
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
    void nonCanonicalScalarChunkUsesV1RawByteFallback() {
        byte[] input = new byte[32];
        Arrays.fill(input, (byte) 0xff);

        BigInteger expected = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                PoseidonMpfHash.DOMAIN_RAW_BYTES_V1,
                BigInteger.valueOf(input.length),
                PoseidonMpfHash.unsigned(Arrays.copyOfRange(input, 0, 31)),
                PoseidonMpfHash.unsigned(Arrays.copyOfRange(input, 31, 32)));

        assertEquals(expected, PoseidonMpfHash.digestField(PoseidonParamsBLS12_381T3.INSTANCE, input));
    }

    @Test
    void publicScalarEncoderRejectsFieldAliases() {
        BigInteger prime = com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime();
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfHash.toDigestBytes(BigInteger.valueOf(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfHash.toDigestBytes(prime));
        assertArrayEquals(new byte[32], PoseidonMpfHash.toDigestBytes(BigInteger.ZERO));
        assertEquals(prime.subtract(BigInteger.ONE), PoseidonMpfHash.fieldFromDigestBytes(
                PoseidonMpfHash.toDigestBytes(prime.subtract(BigInteger.ONE))));
    }

    @Test
    void publicProfileHelpersRejectForeignPoseidonParameters() {
        byte[] zero = new byte[PoseidonMpfHash.DIGEST_LENGTH];

        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfHash.hashFields(
                PoseidonParamsBN254T3.INSTANCE, BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfHash.digestPair(
                PoseidonParamsBN254T3.INSTANCE, zero, zero));
    }

    @Test
    void trieRejectsMalformedAndNonCanonicalRootBytesAtTheBoundary() {
        byte[] shortRoot = new byte[PoseidonMpfHash.DIGEST_LENGTH - 1];
        byte[] fieldAlias = com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381
                .prime().toByteArray();

        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfTrie.inMemory(shortRoot));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfTrie.inMemory(fieldAlias));

        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        assertThrows(IllegalArgumentException.class, () -> trie.setRootHash(shortRoot));
        assertThrows(IllegalArgumentException.class, () -> trie.setRootHash(fieldAlias));
        assertDoesNotThrow(() -> trie.setRootHash(new byte[PoseidonMpfHash.DIGEST_LENGTH]));
    }

    @Test
    void commitmentAdapterRejectsPathsOutsideTheV1KeyWidth() {
        int[] overlong = new int[PoseidonMpfHash.KEY_PATH_NIBBLES + 1];
        NibblePath path = NibblePath.of(overlong);
        byte[] value = PoseidonMpfHash.digest(bytes("bounded-value"));
        var commitments = new PoseidonMpfCommitmentScheme();

        assertThrows(IllegalArgumentException.class,
                () -> commitments.commitLeaf(path, value));
        assertThrows(IllegalArgumentException.class,
                () -> commitments.commitBranch(path, new byte[16][], null));
        assertThrows(IllegalArgumentException.class,
                () -> commitments.commitExtension(path, value));
    }

    @Test
    void inputsBeyondInternalNinetySixByteBoundUseFallback() {
        byte[] input = new byte[257];
        Arrays.fill(input, (byte) 0xa5);

        byte[] first = PoseidonMpfHash.digest(input);
        byte[] second = PoseidonMpfHash.digest(input);

        assertArrayEquals(first, second);
        assertEquals("zeroj-poseidon-mpf-v1", PoseidonMpfHash.PROFILE_ID);
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

    @Test
    void zerojHostVerifierFailsClosedForCclTerminalForkExclusion() {
        var byFirstNibble = new HashMap<Integer, byte[]>();
        byte[] first = null;
        byte[] second = null;
        int sharedNibble = -1;
        PoseidonMpfHashFunction hash = PoseidonMpfHashFunction.INSTANCE;
        for (int i = 0; i < 1_000 && second == null; i++) {
            byte[] candidate = bytes("fork-entry-" + i);
            int nibble = (hash.digest(candidate)[0] >>> 4) & 0x0f;
            byte[] previous = byFirstNibble.putIfAbsent(nibble, candidate);
            if (previous != null) {
                first = previous;
                second = candidate;
                sharedNibble = nibble;
            }
        }
        assertNotNull(second, "failed to find deterministic shared-prefix keys");

        byte[] query = null;
        for (int i = 0; i < 1_000; i++) {
            byte[] candidate = bytes("fork-query-" + i);
            if (((hash.digest(candidate)[0] >>> 4) & 0x0f) != sharedNibble) {
                query = candidate;
                break;
            }
        }
        assertNotNull(query);

        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(first, bytes("one"));
        trie.put(second, bytes("two"));
        byte[] proof = trie.getProofWire(query).orElseThrow();
        var steps = PoseidonMpfCodec.decode(proof);
        assertEquals(1, steps.size());
        assertEquals(PoseidonMpfCodec.KIND_FORK, steps.getFirst().kind());
        assertTrue(ProofVerifier.verify(
                        trie.getRootHash(), query, null, false, proof,
                        new PoseidonMpfHashFunction(PoseidonParamsBLS12_381T3.INSTANCE),
                        new PoseidonMpfCommitmentScheme()),
                "genuine CCL terminal-fork proof documents the upstream behavior");
        assertFalse(trie.verifyProofWire(trie.getRootHash(), query, null, false, proof),
                "production facade must not expose the generic verifier's unsafe behavior");
        assertFalse(PoseidonMpfReference.excluding(trie.getRootHash(), query, proof),
                "ZeroJ must fail closed until the terminal commitment is fully authenticated");

        byte[] forged = proof.clone();
        byte[] exposedForkRoot = PoseidonMpfHash.toDigestBytes(steps.getFirst().forkRoot());
        int rootOffset = indexOf(forged, exposedForkRoot);
        assertTrue(rootOffset >= 0, "fork root must occur in its wire encoding");
        System.arraycopy(trie.getRootHash(), 0, forged, rootOffset, PoseidonMpfHash.DIGEST_LENGTH);
        assertTrue(ProofVerifier.verify(
                        trie.getRootHash(), query, null, false, forged,
                        new PoseidonMpfHashFunction(PoseidonParamsBLS12_381T3.INSTANCE),
                        new PoseidonMpfCommitmentScheme()),
                "regression fixture: generic CCL verifier accepts attacker-selected terminal root");
        assertFalse(trie.verifyProofWire(trie.getRootHash(), query, null, false, forged));
        assertFalse(PoseidonMpfReference.excluding(trie.getRootHash(), query, forged));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            for (int i = 0; i < needle.length; i++) {
                if (haystack[offset + i] != needle[i]) continue outer;
            }
            return offset;
        }
        return -1;
    }

    private static void assertTaggedMutationRejected(
            byte[] root,
            byte[] key,
            byte[] value,
            byte[] proof,
            java.util.function.Consumer<DataItem> mutation) throws Exception {
        CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(proof));
        DataItem item = decoder.decode().getFirst();
        mutation.accept(item);
        byte[] mutated = encode(item);
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(mutated));
        assertFalse(PoseidonMpfReference.including(root, key, value, mutated));
    }

    private static byte[] encode(DataItem item) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new CborEncoder(output).encode(item);
        return output.toByteArray();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
