package org.zeroj.it.confidential;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M5: the reference confidential-accounting state machine over
 * {@code bulletproof-range-bls12-381-g1-v1}. Honest transfers apply; every attack listed in the
 * ADR is rejected deterministically, and two replicas on different providers stay identical.
 */
class ConfidentialLedgerTest {

    private static final String CHAIN = "zeroj-test-chain-1";
    private static final BigInteger Q = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ConfidentialLedger.Config CONFIG = new ConfidentialLedger.Config(CHAIN, 65536, 8);

    /** A client: the opening of its own balance, which the ledger never sees. */
    private static final class Wallet {
        final String name;
        final byte[] key;
        BigInteger value;
        BigInteger blinding;
        long sequence;

        Wallet(String name, BigInteger value) {
            this.name = name;
            this.key = ("key-of-" + name).getBytes(StandardCharsets.US_ASCII);
            this.value = value;
            this.blinding = BigInteger.ZERO;
        }

        /** Builds a transfer of {@code amount} to {@code to}; updates this wallet only once applied. */
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
            return new Built(this, to, amount, rAmount, change, rChange, sign(key, name, to.name, sequence, cAmount, cChange, pAmount, pChange));
        }
    }

    private record Built(Wallet from, Wallet to, BigInteger amount, BigInteger rAmount, BigInteger change, BigInteger rChange,
                         byte[] message) {
        /** The off-chain side of an accepted transfer: both wallets learn their new openings. */
        void settle() {
            from.value = change;
            from.blinding = rChange;
            from.sequence++;
            to.value = to.value.add(amount);
            to.blinding = to.blinding.add(rAmount).mod(Q);
        }
    }

    static byte[] sign(byte[] key, String from, String to, long sequence, byte[] cAmount, byte[] cChange, byte[] pAmount,
                       byte[] pChange) {
        byte[] body = ConfidentialLedger.Transfer.encodeBody(from, to, sequence, cAmount, cChange, pAmount, pChange);
        byte[] auth = ConfidentialLedger.hmac(key, body);
        byte[] message = Arrays.copyOf(body, body.length + auth.length);
        System.arraycopy(auth, 0, message, body.length, auth.length);
        return message;
    }

    private static ConfidentialLedger ledger(G1RangeVerifier verifier, Wallet... wallets) {
        Map<String, byte[]> keys = new TreeMap<>();
        Map<String, BigInteger> balances = new TreeMap<>();
        for (Wallet w : wallets) {
            keys.put(w.name, w.key);
            balances.put(w.name, w.value);
        }
        return new ConfidentialLedger(CONFIG, verifier, keys, balances);
    }

    private static void assertBalance(ConfidentialLedger ledger, Wallet w) {
        G1PedersenCommitment expected = G1Pedersen.pureJava().commitScalar(w.value, w.blinding);
        assertEquals(expected, ledger.balanceOf(w.name), w.name);
        assertEquals(w.sequence, ledger.nextSequence(w.name), w.name);
    }

    @Test
    @DisplayName("Honest transfers apply and keep every balance commitment equal to its owner's opening")
    void honestFlow() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(1_000));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(50));
        Wallet carol = new Wallet("carol", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), alice, bob, carol);

        Built t1 = alice.transfer(bob, BigInteger.valueOf(100));
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(t1.message())));
        t1.settle();
        Built t2 = bob.transfer(carol, BigInteger.valueOf(150));   // bob's whole balance: change 0
        Built t3 = alice.transfer(carol, BigInteger.ONE);
        assertEquals(List.of(Result.ACCEPTED, Result.ACCEPTED), ledger.apply(List.of(t2.message(), t3.message())));
        t2.settle();
        t3.settle();
        for (Wallet w : List.of(alice, bob, carol)) assertBalance(ledger, w);
        assertEquals(BigInteger.valueOf(899), alice.value);
        assertEquals(BigInteger.ZERO, bob.value);
        assertEquals(BigInteger.valueOf(151), carol.value);
    }

    @Test
    @DisplayName("Replay, a bad authorization tag, an unknown account and a self-transfer are rejected and change nothing")
    void authorizationAndReplay() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(500));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), alice, bob);
        Built t = alice.transfer(bob, BigInteger.TEN);
        byte[] forged = t.message().clone();
        forged[forged.length - 1] ^= 1;
        byte[] before = ledger.stateDigest();
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(forged)));
        assertArrayEquals(before, ledger.stateDigest());
        assertEquals(List.of(Result.ACCEPTED, Result.REPLAY), ledger.apply(List.of(t.message(), t.message())));
        t.settle();
        assertBalance(ledger, alice);
        // Signed by bob's key for alice's account.
        byte[] wrongKey = sign(bob.key, "alice", "bob", 1, new byte[48], new byte[48], new byte[0], new byte[0]);
        assertEquals(List.of(Result.BAD_AUTH), ledger.apply(List.of(wrongKey)));
        byte[] unknown = sign(alice.key, "alice", "mallory", 1, new byte[48], new byte[48], new byte[0], new byte[0]);
        assertEquals(List.of(Result.UNKNOWN_ACCOUNT), ledger.apply(List.of(unknown)));
        byte[] self = sign(alice.key, "alice", "alice", 1, new byte[48], new byte[48], new byte[0], new byte[0]);
        assertEquals(List.of(Result.UNKNOWN_ACCOUNT), ledger.apply(List.of(self)));
    }

    @Test
    @DisplayName("Inflation: spending more than the balance needs a negative change, which no range proof covers")
    void inflation() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(100));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), alice, bob);
        BigInteger amount = BigInteger.valueOf(105);
        BigInteger rAmount = BigInteger.valueOf(7);
        BigInteger change = alice.value.subtract(amount).mod(Q);       // q − 5
        BigInteger rChange = alice.blinding.subtract(rAmount).mod(Q);
        // The honest prover refuses the change value.
        CommitmentFormatException refusal = assertThrows(CommitmentFormatException.class,
                () -> G1RangeProver.pureJava().prove(G1PedersenOpening.of(change, rChange), 64, new byte[] {1}));
        assertEquals(CommitmentError.OUT_OF_RANGE, refusal.reason());
        byte[] cAmount = G1Pedersen.pureJava().commitScalar(amount, rAmount).toPointBytes();
        byte[] cChange = G1Pedersen.pureJava().commitScalar(change, rChange).toPointBytes();
        byte[] pAmount = G1RangeProver.pureJava().prove(G1PedersenOpening.of(amount, rAmount), 64,
                ConfidentialLedger.context(CHAIN, "alice", "bob", 0, (byte) 0)).toBytes();
        // The attacker reuses the valid amount proof for the change output.
        byte[] message = sign(alice.key, "alice", "bob", 0, cAmount, cChange, pAmount, pAmount);
        assertEquals(List.of(Result.RANGE_PROOF), ledger.apply(List.of(message)));
        assertBalance(ledger, alice);
    }

    @Test
    @DisplayName("A proof moved to another message (recipient, sequence or output role) fails: the context binds it")
    void proofsAreBoundToTheirMessage() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(300));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        Wallet carol = new Wallet("carol", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), alice, bob, carol);
        Built t = alice.transfer(bob, BigInteger.valueOf(20));
        ConfidentialLedger.Transfer decoded = ConfidentialLedger.Transfer.decode(t.message());
        // Same commitments and proofs, re-addressed to carol and correctly signed by alice.
        byte[] redirected = sign(alice.key, "alice", "carol", 0, decoded.amountCommitment(), decoded.changeCommitment(),
                decoded.amountProof(), decoded.changeProof());
        // Same everything, outputs' proofs swapped.
        byte[] swapped = sign(alice.key, "alice", "bob", 0, decoded.amountCommitment(), decoded.changeCommitment(),
                decoded.changeProof(), decoded.amountProof());
        assertEquals(List.of(Result.RANGE_PROOF, Result.RANGE_PROOF, Result.ACCEPTED),
                ledger.apply(List.of(redirected, swapped, t.message())));
        t.settle();
        assertBalance(ledger, alice);
        assertNotEquals(Arrays.toString(ConfidentialLedger.context(CHAIN, "ab", "c", 0, (byte) 0)),
                Arrays.toString(ConfidentialLedger.context(CHAIN, "a", "bc", 0, (byte) 0)), "context is injective");
    }

    @Test
    @DisplayName("Malformed inputs are deterministic rejections: bad lengths, other widths, identity and malformed commitments, garbage")
    void malformedInputs() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(300));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = ledger(G1RangeVerifier.pureJava(), alice, bob);
        Built t = alice.transfer(bob, BigInteger.valueOf(20));
        ConfidentialLedger.Transfer d = ConfidentialLedger.Transfer.decode(t.message());
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        BigInteger rAmount = BigInteger.valueOf(3);
        byte[] narrow = G1RangeProver.pureJava().prove(G1PedersenOpening.of(BigInteger.valueOf(20), rAmount), 32,
                ConfidentialLedger.context(CHAIN, "alice", "bob", 0, (byte) 0)).toBytes();
        List<byte[]> block = new ArrayList<>();
        block.add(Arrays.copyOf(t.message(), t.message().length - 1));                 // truncated
        block.add(Arrays.copyOf(t.message(), t.message().length + 1));                 // trailing octet
        block.add(new byte[0]);
        block.add(sign(alice.key, "alice", "bob", 0, new byte[48], d.changeCommitment(), d.amountProof(), d.changeProof()));
        block.add(sign(alice.key, "alice", "bob", 0, identity, ledger.balanceOf("alice").toPointBytes(), d.amountProof(), d.changeProof()));
        block.add(sign(alice.key, "alice", "bob", 0, d.amountCommitment(), d.changeCommitment(), narrow, d.changeProof()));
        byte[] flipped = d.amountProof().clone();
        flipped[100] ^= 0x10;
        block.add(sign(alice.key, "alice", "bob", 0, d.amountCommitment(), d.changeCommitment(), flipped, d.changeProof()));
        assertEquals(List.of(Result.MALFORMED, Result.MALFORMED, Result.MALFORMED, Result.MALFORMED, Result.RANGE_PROOF,
                Result.RANGE_PROOF, Result.RANGE_PROOF), ledger.apply(block));
        assertEquals(Result.TOO_LARGE, ledger.validate(new byte[65537]));
        assertBalance(ledger, alice);
    }

    @Test
    @DisplayName("Per-block proof limit: transfers beyond it are rejected in order, and a later block accepts them")
    void blockLimit() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(10_000));
        Wallet bob = new Wallet("bob", BigInteger.ZERO);
        ConfidentialLedger ledger = new ConfidentialLedger(new ConfidentialLedger.Config(CHAIN, 65536, 2), G1RangeVerifier.pureJava(),
                Map.of("alice", alice.key, "bob", bob.key), Map.of("alice", alice.value));
        Built first = alice.transfer(bob, BigInteger.ONE);
        first.settle();
        Built second = alice.transfer(bob, BigInteger.TWO);
        assertEquals(List.of(Result.ACCEPTED, Result.OVER_BLOCK_LIMIT), ledger.apply(List.of(first.message(), second.message())));
        assertEquals(List.of(Result.ACCEPTED), ledger.apply(List.of(second.message())));
        second.settle();
        assertBalance(ledger, alice);
        assertThrows(IllegalArgumentException.class, () -> new ConfidentialLedger(CONFIG, G1RangeVerifier.pureJava(),
                Map.of("a", new byte[1]), Map.of("a", ConfidentialLedger.SUPPLY_CAP)));
    }

    @Test
    @DisplayName("Two replicas, pure Java and blst, apply the same blocks (good and bad) to identical results and state")
    void replicasAgree() {
        Wallet alice = new Wallet("alice", BigInteger.valueOf(777));
        Wallet bob = new Wallet("bob", BigInteger.valueOf(1));
        ConfidentialLedger pure = ledger(G1RangeVerifier.pureJava(), alice, bob);
        ConfidentialLedger blst = ledger(G1RangeVerifier.withProvider(BlstBls12381Provider.createDefault()), alice, bob);
        assertArrayEquals(pure.stateDigest(), blst.stateDigest());
        List<List<byte[]>> blocks = new ArrayList<>();
        for (int round = 0; round < 3; round++) {
            Built good = alice.transfer(bob, BigInteger.valueOf(round + 5));
            byte[] bad = good.message().clone();
            bad[200] ^= 1;
            blocks.add(List.of(bad, good.message(), good.message()));
            assertEquals(pure.apply(blocks.get(round)), blst.apply(blocks.get(round)), "round " + round);
            good.settle();
            assertArrayEquals(pure.stateDigest(), blst.stateDigest(), "round " + round);
        }
        assertBalance(pure, alice);
        assertFalse(Arrays.equals(new byte[32], pure.stateDigest()));
        assertTrue(alice.sequence == 3);
    }
}
