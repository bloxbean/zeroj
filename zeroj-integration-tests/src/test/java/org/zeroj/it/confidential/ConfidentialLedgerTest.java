package org.zeroj.it.confidential;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.bulletproofs.G1RangeProver;
import org.zeroj.bls12381.bulletproofs.G1RangeVerifier;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;
import org.zeroj.blst.BlstBls12381Provider;
import org.zeroj.it.confidential.ConfidentialLedger.Result;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M5: the reference confidential-accounting state machine over
 * {@code bulletproof-range-bls12-381-g1-v1}. Honest transfers and merges apply; every attack listed
 * in the ADR and found in review is rejected deterministically on both the pure-Java and the blst
 * provider; and two replicas on different providers stay identical.
 */
class ConfidentialLedgerTest {

    private static final String CHAIN = "zeroj-test-chain-1";
    private static final BigInteger Q = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ConfidentialLedger.Config CONFIG = new ConfidentialLedger.Config(CHAIN, 65536, 8);

    /** A client: the openings of its balance and of the incoming amounts it was told, never seen by the ledger. */
    private static final class Wallet {
        final String name;
        final byte[] key;
        BigInteger value;
        BigInteger blinding = BigInteger.ZERO;
        long sequence;
        /** Pending id → (value, blinding), as delivered by payers off-chain. */
        final TreeMap<Long, BigInteger[]> inbox = new TreeMap<>();

        Wallet(String name, BigInteger value) {
            this.name = name;
            this.key = ("authorization-key-of-" + name).getBytes(StandardCharsets.US_ASCII);
            this.value = value;
        }

        /** Builds a transfer of {@code amount} to {@code to}. */
        Built transfer(Wallet to, BigInteger amount) {
            BigInteger rAmount = G1Pedersen.randomBlinding(RANDOM);
            BigInteger rChange = blinding.subtract(rAmount).mod(Q);
            BigInteger change = value.subtract(amount);
            G1Pedersen pedersen = G1Pedersen.pureJava();
            byte[] cAmount = pedersen.commitScalar(amount, rAmount).toPointBytes();
            byte[] cChange = pedersen.commitScalar(change, rChange).toPointBytes();
            byte[] pAmount = G1RangeProver.pureJava().prove(G1PedersenOpening.of(amount, rAmount), 64,
                    ConfidentialLedger.context(CHAIN, name, to.name, sequence, (byte) 0)).toBytes();
            byte[] pChange = G1RangeProver.pureJava().prove(G1PedersenOpening.of(change, rChange), 64,
                    ConfidentialLedger.context(CHAIN, name, to.name, sequence, (byte) 1)).toBytes();
            return new Built(this, to, amount, rAmount, change, rChange,
                    signTransfer(key, name, to.name, sequence, cAmount, cChange, pAmount, pChange));
        }

        /** A merge of the named pending ids. */
        byte[] merge(long... ids) {
            return sign(key, ConfidentialLedger.Merge.encodeBody(name, sequence, ids));
        }

        /** The off-chain side of an accepted merge. */
        void merged(long... ids) {
            for (long id : ids) {
                BigInteger[] o = inbox.remove(id);
                value = value.add(o[0]);
                blinding = blinding.add(o[1]).mod(Q);
            }
            sequence++;
        }
    }

    private record Built(Wallet from, Wallet to, BigInteger amount, BigInteger rAmount, BigInteger change, BigInteger rChange,
                         byte[] message) {
        /**
         * The off-chain side of an accepted transfer: the payer's change, and the opening delivered to the
         * payee under the pending id the ledger gave the amount.
         */
        long settle(ConfidentialLedger ledger) {
            from.value = change;
            from.blinding = rChange;
            from.sequence++;
            G1PedersenCommitment c = G1Pedersen.pureJava().commitScalar(amount, rAmount);
            long id = -1;
            for (Map.Entry<Long, G1PedersenCommitment> e : ledger.pendingOf(to.name).entrySet()) {
                if (e.getValue().equals(c)) id = e.getKey();
            }
            assertTrue(id >= 0, "the amount is pending for the payee");
            to.inbox.put(id, new BigInteger[] {amount, rAmount});
            return id;
        }
    }

    static byte[] sign(byte[] key, byte[] body) {
        byte[] auth = ConfidentialLedger.hmac(key, ConfidentialLedger.authInput(CHAIN, body));
        byte[] message = Arrays.copyOf(body, body.length + auth.length);
        System.arraycopy(auth, 0, message, body.length, auth.length);
        return message;
    }

    static byte[] signTransfer(byte[] key, String from, String to, long sequence, byte[] cAmount, byte[] cChange,
                               byte[] pAmount, byte[] pChange) {
        return sign(key, ConfidentialLedger.Transfer.encodeBody(from, to, sequence, cAmount, cChange, pAmount, pChange));
    }

    private static G1RangeVerifier verifier(String provider) {
        return provider.equals("blst") ? G1RangeVerifier.withProvider(BlstBls12381Provider.createDefault())
                : G1RangeVerifier.pureJava();
    }

    private static ConfidentialLedger ledger(G1RangeVerifier verifier, ConfidentialLedger.Config config, Wallet... wallets) {
        Map<String, byte[]> keys = new TreeMap<>();
        Map<String, BigInteger> balances = new TreeMap<>();
        for (Wallet w : wallets) {
            keys.put(w.name, w.key);
            balances.put(w.name, w.value);
        }
        return new ConfidentialLedger(config, verifier, keys, balances);
    }

    private static ConfidentialLedger ledger(G1RangeVerifier verifier, Wallet... wallets) {
        return ledger(verifier, CONFIG, wallets);
    }

    private static void assertBalance(ConfidentialLedger ledger, Wallet w) {
        assertEquals(G1Pedersen.pureJava().commitScalar(w.value, w.blinding), ledger.balanceOf(w.name), w.name);
        assertEquals(w.sequence, ledger.nextSequence(w.name), w.name);
    }

    private static byte[] emptyTransfer(byte[] key, String from, String to, long sequence) {
        return signTransfer(key, from, to, sequence, new byte[48], new byte[48], new byte[0], new byte[0]);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("Honest transfers and merges keep every balance commitment equal to its owner's opening")
    void honestFlow(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(1_000));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(50));
        Wallet carol = new Wallet("carol", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), alice, bob, carol);

        Built t1 = alice.transfer(bob, BigInteger.valueOf(100));
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(t1.message())));
        long p1 = t1.settle(ledger);
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(bob.merge(p1))));
        bob.merged(p1);
        Built t2 = bob.transfer(carol, BigInteger.valueOf(150));   // bob's whole balance: change 0
        Built t3 = alice.transfer(carol, BigInteger.ONE);
        assertEquals(List.of(Result.ACCEPTED, Result.ACCEPTED), ledger.apply(List.of(t2.message(), t3.message())));
        long p2 = t2.settle(ledger);
        long p3 = t3.settle(ledger);
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(carol.merge(p2, p3))));
        carol.merged(p2, p3);
        for (Wallet w : List.of(alice, bob, carol)) assertBalance(ledger, w);
        assertEquals(BigInteger.valueOf(899), alice.value);
        assertEquals(BigInteger.ZERO, bob.value);
        assertEquals(BigInteger.valueOf(151), carol.value);
        assertEquals(0, ledger.pendingOf("carol").size());
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("Withheld openings cannot freeze an account, and incoming transfers do not invalidate spends (reviewer M3–M6 F1)")
    void griefingAndFrontRunning(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(500));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(500));
        Wallet mallory = new Wallet("mallory", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), alice, bob, mallory);
        // Mallory (balance 0, commitment O) sends alice a zero-value amount and keeps its blinding.
        Built grief = mallory.transfer(alice, BigInteger.ZERO);
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(grief.message())));
        assertEquals(1, ledger.pendingOf("alice").size());
        assertBalance(ledger, alice);
        // An incoming transfer placed before alice's spend in the same block does not invalidate it.
        Built incoming = bob.transfer(alice, BigInteger.TEN);
        Built spend = alice.transfer(bob, BigInteger.valueOf(20));
        assertEquals(List.of(Result.ACCEPTED, Result.ACCEPTED), ledger.apply(List.of(incoming.message(), spend.message())));
        long known = incoming.settle(ledger);
        spend.settle(ledger);
        assertBalance(ledger, alice);
        // Alice merges only what she can open; the griefing entry stays pending, harmlessly.
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(alice.merge(known))));
        alice.merged(known);
        assertBalance(ledger, alice);
        assertEquals(1, ledger.pendingOf("alice").size());
        assertEquals(BigInteger.valueOf(490), alice.value);
    }

    @Test
    @DisplayName("The pending pool is bounded: past the limit, transfers to that account are rejected; its own spends still work")
    void pendingLimit() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(100));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(10_000));
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), new ConfidentialLedger.Config(CHAIN, 65536, 64), alice, bob);
        for (int i = 0; i < ConfidentialLedger.MAX_PENDING; i++) {
            Built t = bob.transfer(alice, BigInteger.ONE);
            assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(t.message())), "entry " + i);
            t.settle(ledger);
        }
        Built over = bob.transfer(alice, BigInteger.ONE);
        assertEquals(List.of(Result.PENDING_FULL), ledger.apply(List.of(over.message())));
        Built spend = alice.transfer(bob, BigInteger.valueOf(5));
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(spend.message())));
        spend.settle(ledger);
        assertBalance(ledger, alice);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("Replay, bad tags (including another chain's), unknown accounts, self-transfers and bad merges are rejected")
    void authorizationAndReplay(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(500));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), alice, bob);
        Built t = alice.transfer(bob, BigInteger.TEN);
        byte[] forged = t.message().clone();
        forged[forged.length - 1] ^= 1;
        byte[] before = ledger.stateDigest();
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(forged)));
        assertArrayEquals(before, ledger.stateDigest());
        assertEquals(List.of(Result.ACCEPTED, Result.REPLAY), ledger.apply(List.of(t.message(), t.message())));
        long id = t.settle(ledger);
        assertBalance(ledger, alice);
        // A tag made for another chain id does not verify here.
        byte[] body = ConfidentialLedger.Transfer.encodeBody("alice", "bob", 1, new byte[48], new byte[48], new byte[0], new byte[0]);
        byte[] auth = ConfidentialLedger.hmac(alice.key, ConfidentialLedger.authInput("other-chain", body));
        byte[] otherChain = Arrays.copyOf(body, body.length + 32);
        System.arraycopy(auth, 0, otherChain, body.length, 32);
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(otherChain)));
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(emptyTransfer(bob.key, "alice", "bob", 1))));
        assertEquals(List.of(Result.UNKNOWN_ACCOUNT), ledger.apply(List.of(emptyTransfer(alice.key, "alice", "mallory", 1))));
        assertEquals(List.of(Result.UNKNOWN_ACCOUNT), ledger.apply(List.of(emptyTransfer(alice.key, "alice", "alice", 1))));
        // Merges: another account's key, an unknown id, an id named twice, then a replay.
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(sign(alice.key,
                ConfidentialLedger.Merge.encodeBody("bob", 0, id)))));
        assertEquals(List.of(Result.UNKNOWN_PENDING), ledger.apply(List.of(bob.merge(id + 7))));
        assertEquals(List.of(Result.UNKNOWN_PENDING), ledger.apply(List.of(bob.merge(id, id))));
        byte[] merge = bob.merge(id);
        assertEquals(List.of(Result.ACCEPTED, Result.REPLAY), ledger.apply(List.of(merge, merge)));
        bob.merged(id);
        assertBalance(ledger, bob);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("Inflation: spending more than the balance needs a negative change, which no range proof covers")
    void inflation(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(100));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), alice, bob);
        BigInteger amount = BigInteger.valueOf(105);
        BigInteger rAmount = BigInteger.valueOf(7);
        BigInteger change = alice.value.subtract(amount).mod(Q);       // q − 5
        BigInteger rChange = alice.blinding.subtract(rAmount).mod(Q);
        CommitmentFormatException refusal = assertThrows(CommitmentFormatException.class,
                () -> G1RangeProver.pureJava().prove(G1PedersenOpening.of(change, rChange), 64, new byte[] {1}));
        assertEquals(CommitmentError.OUT_OF_RANGE, refusal.reason());
        byte[] cAmount = G1Pedersen.pureJava().commitScalar(amount, rAmount).toPointBytes();
        byte[] cChange = G1Pedersen.pureJava().commitScalar(change, rChange).toPointBytes();
        byte[] pAmount = G1RangeProver.pureJava().prove(G1PedersenOpening.of(amount, rAmount), 64,
                ConfidentialLedger.context(CHAIN, "alice", "bob", 0, (byte) 0)).toBytes();
        // The attacker reuses the valid amount proof for the change output.
        byte[] message = signTransfer(alice.key, "alice", "bob", 0, cAmount, cChange, pAmount, pAmount);
        assertEquals(List.of(Result.RANGE_PROOF, Result.REPLAY), ledger.apply(List.of(message, message)));
        alice.sequence++;                       // a failed transfer consumes the sequence
        assertBalance(ledger, alice);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("A proof moved to another message (recipient or output role) fails: the context binds it")
    void proofsAreBoundToTheirMessage(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(300));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        Wallet carol = new Wallet("carol", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), alice, bob, carol);
        Built t = alice.transfer(bob, BigInteger.valueOf(20));
        ConfidentialLedger.Transfer d = (ConfidentialLedger.Transfer) ConfidentialLedger.Message.decode(t.message());
        byte[] redirected = signTransfer(alice.key, "alice", "carol", 0, d.amountCommitment(), d.changeCommitment(),
                d.amountProof(), d.changeProof());
        // Each failed transfer consumes a sequence, so the next attack is signed with the next one.
        byte[] swapped = signTransfer(alice.key, "alice", "bob", 1, d.amountCommitment(), d.changeCommitment(),
                d.changeProof(), d.amountProof());
        assertEquals(List.of(Result.RANGE_PROOF, Result.RANGE_PROOF, Result.REPLAY),
                ledger.apply(List.of(redirected, swapped, t.message())));
        alice.sequence = 2;
        Built honest = alice.transfer(bob, BigInteger.valueOf(20));
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(honest.message())));
        honest.settle(ledger);
        assertBalance(ledger, alice);
        assertNotEquals(Arrays.toString(ConfidentialLedger.context(CHAIN, "ab", "c", 0, (byte) 0)),
                Arrays.toString(ConfidentialLedger.context(CHAIN, "a", "bc", 0, (byte) 0)), "context is injective");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("Malformed inputs are deterministic rejections: bad lengths, other widths, identity and malformed commitments")
    void malformedInputs(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(300));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), alice, bob);
        Built t = alice.transfer(bob, BigInteger.valueOf(20));
        ConfidentialLedger.Transfer d = (ConfidentialLedger.Transfer) ConfidentialLedger.Message.decode(t.message());
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        byte[] narrow = G1RangeProver.pureJava().prove(G1PedersenOpening.of(BigInteger.valueOf(20), BigInteger.valueOf(3)), 32,
                ConfidentialLedger.context(CHAIN, "alice", "bob", 0, (byte) 0)).toBytes();
        byte[] flipped = d.amountProof().clone();
        flipped[100] ^= 0x10;
        List<byte[]> block = new ArrayList<>();
        block.add(Arrays.copyOf(t.message(), t.message().length - 1));                 // truncated
        block.add(Arrays.copyOf(t.message(), t.message().length + 1));                 // trailing octet
        block.add(new byte[0]);
        block.add(signTransfer(alice.key, "alice", "bob", 0, new byte[48], d.changeCommitment(), d.amountProof(), d.changeProof()));
        // Each of the next three reaches verification and fails, consuming a sequence: 0, 1, 2.
        block.add(signTransfer(alice.key, "alice", "bob", 0, identity, ledger.balanceOf("alice").toPointBytes(),
                d.amountProof(), d.changeProof()));
        block.add(signTransfer(alice.key, "alice", "bob", 1, d.amountCommitment(), d.changeCommitment(), narrow, d.changeProof()));
        block.add(signTransfer(alice.key, "alice", "bob", 2, d.amountCommitment(), d.changeCommitment(), flipped, d.changeProof()));
        assertEquals(List.of(Result.MALFORMED, Result.MALFORMED, Result.MALFORMED, Result.MALFORMED, Result.RANGE_PROOF,
                Result.RANGE_PROOF, Result.RANGE_PROOF), ledger.apply(block));
        assertEquals(Result.TOO_LARGE, ledger.validate(new byte[65537]));
        alice.sequence = 3;
        assertBalance(ledger, alice);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"pure", "blst"})
    @DisplayName("Per-block proof budget: counted only when verification is reached; excess transfers wait for a later block")
    void blockLimit(String provider) {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(10_000));
        Wallet carol = new Wallet("carol", BigInteger.valueOf(10_000));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(verifier(provider), new ConfidentialLedger.Config(CHAIN, 65536, 2), alice, carol, bob);
        byte[] junk = emptyTransfer(bob.key, "alice", "bob", 0);                       // bad tag: no proof is checked
        Built first = alice.transfer(bob, BigInteger.ONE);
        Built second = carol.transfer(bob, BigInteger.TWO);
        assertEquals(List.of(Result.BAD_AUTH, Result.ACCEPTED, Result.OVER_BLOCK_LIMIT),
                ledger.apply(List.of(junk, first.message(), second.message())));
        first.settle(ledger);
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(second.message())));
        second.settle(ledger);
        assertBalance(ledger, alice);
        assertBalance(ledger, carol);
    }

    @Test
    @DisplayName("A pending pool filled with withheld zero-value entries is cleared by the owner's discard (reviewer M3–M6 F9)")
    void discardClearsGriefing() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(100));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(100));
        Wallet mallory = new Wallet("mallory", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), new ConfidentialLedger.Config(CHAIN, 65536, 64),
                alice, bob, mallory);
        for (int i = 0; i < ConfidentialLedger.MAX_PENDING; i++) {
            Built grief = mallory.transfer(alice, BigInteger.ZERO);
            assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(grief.message())));
            grief.settle(ledger);
        }
        Built honest = bob.transfer(alice, BigInteger.TEN);
        assertEquals(List.of(Result.PENDING_FULL), ledger.apply(List.of(honest.message())));
        long[] ids = ledger.pendingOf("alice").keySet().stream().mapToLong(Long::longValue).toArray();
        // A discard needs the owner's tag and names existing entries only.
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(sign(bob.key,
                ConfidentialLedger.Merge.encodeDiscardBody("alice", 0, ids)))));
        assertEquals(List.of(Result.UNKNOWN_PENDING), ledger.apply(List.of(sign(alice.key,
                ConfidentialLedger.Merge.encodeDiscardBody("alice", 0, ids[0] + 1000)))));
        byte[] discard = sign(alice.key, ConfidentialLedger.Merge.encodeDiscardBody("alice", 0, ids));
        assertEquals(List.of(Result.ACCEPTED, Result.REPLAY), ledger.apply(List.of(discard, discard)));
        alice.sequence++;
        alice.inbox.clear();
        assertEquals(0, ledger.pendingOf("alice").size());
        assertBalance(ledger, alice);
        // The honest transfer is now received.
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(honest.message())));
        long id = honest.settle(ledger);
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(alice.merge(id))));
        alice.merged(id);
        assertBalance(ledger, alice);
        assertEquals(BigInteger.valueOf(110), alice.value);
    }

    @Test
    @DisplayName("A signed transfer whose proofs fail consumes the sequence, so replaying it cannot burn the proof budget (reviewer M3–M6 F10)")
    void replayedJunkCannotBurnTheBudget() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(100));
        Wallet mallory = new Wallet("mallory", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), new ConfidentialLedger.Config(CHAIN, 65536, 4),
                alice, mallory);
        // Balanced (amount (0, r), change (0, −r), sum O = mallory's balance) with all-zero proofs.
        BigInteger r = BigInteger.valueOf(12345);
        byte[] cAmount = G1Pedersen.pureJava().commitScalar(BigInteger.ZERO, r).toPointBytes();
        byte[] cChange = G1Pedersen.pureJava().commitScalar(BigInteger.ZERO, Q.subtract(r)).toPointBytes();
        byte[] junk = signTransfer(mallory.key, "mallory", "alice", 0, cAmount, cChange, new byte[928], new byte[928]);
        for (int block = 0; block < 3; block++) {
            Built honest = alice.transfer(mallory, BigInteger.ONE);
            List<Result> expected = block == 0
                    ? List.of(Result.RANGE_PROOF, Result.REPLAY, Result.REPLAY, Result.ACCEPTED)
                    : List.of(Result.REPLAY, Result.REPLAY, Result.REPLAY, Result.ACCEPTED);
            assertEquals(expected, ledger.apply(List.of(junk, junk, junk, honest.message())), "block " + block);
            honest.settle(ledger);
        }
        assertEquals(1, ledger.nextSequence("mallory"));
        assertBalance(ledger, alice);
    }

    @Test
    @DisplayName("Configuration invariants: canonical identifiers and usable keys, checked once at construction (Codex M3–M6 F1, F2)")
    void configuration() {
        for (String bad : List.of("?", "\uD800", "Alice", "a b", "", "x".repeat(65), "café")) {
            assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger.Config(bad, 65536, 8), bad);
            assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger(CONFIG, G1RangeVerifier.pureJava(),
                    Map.of(bad, new byte[16]), Map.of()), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger(CONFIG, G1RangeVerifier.pureJava(),
                Map.of("alice", new byte[0]), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger(CONFIG, G1RangeVerifier.pureJava(),
                Map.of("alice", new byte[15]), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger(CONFIG, G1RangeVerifier.pureJava(),
                Map.of("alice", new byte[16]), Map.of("bob", BigInteger.ONE)));
        assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger(CONFIG, G1RangeVerifier.pureJava(),
                Map.of("a", new byte[16]), Map.of("a", ConfidentialLedger.SUPPLY_CAP)));
        assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger.Config(CHAIN, 65536, 1));
        assertThrows(IllegalArgumentException.class, () -> ConfidentialLedger.context(CHAIN, "\uD800", "bob", 0, (byte) 0));
        // The longest identifiers keep the context far below the protocol's 1,024-octet limit.
        String longest = "x".repeat(64);
        assertTrue(ConfidentialLedger.context(longest, longest, longest, Long.MAX_VALUE, (byte) 1).length < 300);
    }

    @Test
    @DisplayName("A message whose sender octets are not a canonical identifier is MALFORMED")
    void nonCanonicalIdentifiersInMessages() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(10));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), alice, bob);
        byte[] good = emptyTransfer(alice.key, "alice", "bob", 0);
        assertEquals(Result.ACCEPTED, ledger.validate(good));
        // Version, type, a 4-octet length, then "alice": replace its first octet.
        for (int replacement : new int[] {0x80, 0x81, 'A', '?', 0}) {
            byte[] bad = good.clone();
            bad[6] = (byte) replacement;
            assertEquals(Result.MALFORMED, ledger.validate(bad), "octet " + replacement);
            assertEquals(List.of(Result.MALFORMED), ledger.apply(List.of(bad)), "octet " + replacement);
        }
    }

    @Test
    @DisplayName("Two replicas, pure Java and blst, apply the same blocks (good and bad) to identical results and state")
    void replicasAgree() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(777));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(1));
        ConfidentialLedger pure = ledger(G1RangeVerifier.pureJava(), alice, bob);
        ConfidentialLedger blst = ledger(verifier("blst"), alice, bob);
        assertArrayEquals(pure.stateDigest(), blst.stateDigest());
        for (int round = 0; round < 3; round++) {
            Built good = alice.transfer(bob, BigInteger.valueOf(round + 5));
            byte[] bad = good.message().clone();
            bad[200] ^= 1;
            List<byte[]> block = List.of(bad, good.message(), good.message());
            assertEquals(pure.apply(block), blst.apply(block), "round " + round);
            long id = good.settle(pure);
            List<byte[]> merges = List.of(bob.merge(id), bob.merge(id));
            assertEquals(pure.apply(merges), blst.apply(merges), "merge round " + round);
            bob.merged(id);
            assertArrayEquals(pure.stateDigest(), blst.stateDigest(), "round " + round);
        }
        assertBalance(pure, alice);
        assertBalance(blst, bob);
        assertEquals(3, alice.sequence);
    }
}
