package org.zeroj.it.confidential;

import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.bulletproofs.G1RangeProof;
import org.zeroj.bls12381.bulletproofs.G1RangeVerifier;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * TEST-ONLY reference confidential-accounting state machine (ADR-0061 M5, D9; spec §13). It has the
 * shape of a Yano-X {@code AppStateMachine}: a stateless {@link #validate} for admission, a
 * deterministic {@link #apply} per block, and a state digest. It does not depend on Yano. It shows
 * what the HOST must add around {@code bulletproof-range-bls12-381-g1-v1}, because a verified range
 * proof provides none of it (spec §1.1, §13):
 *
 * <ul>
 *   <li><b>Authorization:</b> every message carries a tag under the sender's key (HMAC-SHA256,
 *       standing in for a signature), over a domain-separated input naming the chain.</li>
 *   <li><b>Replay protection:</b> a per-account sequence number that must equal the next expected
 *       one.</li>
 *   <li><b>Binding:</b> each proof's context is the chain id, sender, recipient, sequence and output
 *       role, each length-prefixed or fixed-width (spec §5.1), so a proof cannot move to another
 *       message or output. Identifiers are canonical ASCII ({@code [a-z0-9-]{1,64}}), so the encoding
 *       is injective.</li>
 *   <li><b>Incoming amounts are pending, not balance.</b> A recipient can spend only what it can open.
 *       If incoming amounts were added straight to its balance, a payer who withheld the blinding,
 *       even of a zero-value transfer, would freeze the recipient's whole balance, and any incoming
 *       transfer would invalidate the recipient's pending spends (reviewer, M3–M6 F1). So each incoming
 *       amount is a separate pending entry; the owner merges into its balance only entries whose
 *       openings it has, with its own authorized message. Delivering openings to the recipient
 *       (for example ADR-0052/0054 encryption) is the host's choice and outside this reference.</li>
 *   <li><b>Balance invariant.</b> Every balance and pending entry opens to a value equal to genesis
 *       plus what it received minus what it sent, and the total S over all of them is constant, with
 *       S below {@code 2^63} at genesis. By induction every value is in {@code [0, S]}:
 *       <ul>
 *         <li>a transfer needs {@code C_balance == C_amount + C_change}, with a {@value #BITS}-bit range
 *             proof on each output; so {@code v_amount + v_change ≡ b (mod q)} with the left side at
 *             most {@code 2^65 − 2 < q} and {@code b < q}, which makes it an integer equality, and the
 *             amount is in {@code [0, b]} (ADR-0051 D3a, with the balance's bound coming from the
 *             invariant rather than a proof);</li>
 *         <li>a merge adds pending entries whose values sum to at most {@code S < q}, so it does not
 *             wrap.</li>
 *       </ul>
 *       The cap below {@code 2^63} keeps every balance below {@code 2^64}, so it can move in one
 *       transfer. <b>Every change to a balance must keep this invariant:</b> a plugin that adds, say,
 *       a deposit with a depositor-chosen blinding and no proof would break it.</li>
 *   <li><b>Limits:</b> message size, pending entries per account, and verified proofs per block
 *       (counted only when verification is reached, so unauthenticated junk does not use the
 *       budget).</li>
 *   <li><b>Determinism:</b> no randomness, clock or I/O; ordered maps only; every malformed input is a
 *       deterministic rejection, never an exception escaping {@code apply}. Configuration invariants
 *       (canonical identifiers, usable keys) are checked once, at construction.</li>
 * </ul>
 *
 * <p>Not product code: no persistence, no real signatures, no fees (so the pending pool can be filled
 * by spam, up to its limit; a real host prices or rate-limits incoming entries), no privacy of who
 * pays whom.
 */
final class ConfidentialLedger {

    /** The range-proof width for every output. */
    static final int BITS = 64;
    /** Total-supply cap at genesis: below 2^63, so every balance stays below 2^64. */
    static final BigInteger SUPPLY_CAP = BigInteger.ONE.shiftLeft(63);
    /** Shortest accepted authorization key. */
    static final int MIN_KEY_BYTES = 16;
    /** Most pending entries an account holds, and most a merge names. */
    static final int MAX_PENDING = 16;

    private static final byte[] CONTEXT_PREFIX = "zeroj-reference-confidential-ledger-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AUTH_PREFIX = "zeroj-reference-confidential-ledger-v1/auth".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;
    private static final byte TYPE_TRANSFER = 1;
    private static final byte TYPE_MERGE = 2;
    /** Chain and account identifiers: lowercase ASCII, digits and '-', 1 to 64 octets. */
    private static final Pattern IDENTIFIER = Pattern.compile("[a-z0-9-]{1,64}");

    record Config(String chainId, int maxMessageBytes, int maxProofsPerBlock) {
        Config {
            requireIdentifier(chainId);
            if (maxMessageBytes < 1 || maxProofsPerBlock < 2) {
                throw new IllegalArgumentException("limits must allow at least one transfer");
            }
        }
    }

    /** Why a message was rejected; {@code ACCEPTED} otherwise. */
    enum Result {
        ACCEPTED, TOO_LARGE, MALFORMED, UNKNOWN_ACCOUNT, BAD_AUTH, REPLAY, BALANCE, RANGE_PROOF, OVER_BLOCK_LIMIT,
        PENDING_FULL, UNKNOWN_PENDING
    }

    private record Account(byte[] authKey, G1PedersenCommitment balance, long nextSequence,
                           TreeMap<Long, G1PedersenCommitment> pending, long nextPendingId) {
    }

    private final Config config;
    private final G1RangeVerifier verifier;
    private final TreeMap<String, Account> accounts = new TreeMap<>();

    /**
     * Genesis: accounts with public initial balances, committed with blinding 0 (deposits are public).
     *
     * @throws IllegalArgumentException if an identifier or key is unusable, a balance names an unknown
     *                                  account, or the balances reach {@link #SUPPLY_CAP}
     */
    ConfidentialLedger(Config config, G1RangeVerifier verifier, Map<String, byte[]> authKeys,
                       Map<String, BigInteger> initialBalances) {
        this.config = Objects.requireNonNull(config, "config");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        for (String account : initialBalances.keySet()) {
            if (!authKeys.containsKey(account)) throw new IllegalArgumentException("balance for an unknown account");
        }
        BigInteger total = BigInteger.ZERO;
        for (Map.Entry<String, byte[]> e : new TreeMap<>(authKeys).entrySet()) {
            requireIdentifier(e.getKey());
            // Configuration invariant: every key is usable, so apply() never fails on one.
            if (e.getValue() == null || e.getValue().length < MIN_KEY_BYTES) {
                throw new IllegalArgumentException("authorization keys are at least " + MIN_KEY_BYTES + " octets");
            }
            BigInteger initial = initialBalances.getOrDefault(e.getKey(), BigInteger.ZERO);
            if (initial.signum() < 0) throw new IllegalArgumentException("negative balance");
            total = total.add(initial);
            accounts.put(e.getKey(), new Account(e.getValue().clone(), publicCommitment(initial), 0, new TreeMap<>(), 0));
        }
        if (total.compareTo(SUPPLY_CAP) >= 0) {
            throw new IllegalArgumentException("total supply must be below 2^63");
        }
    }

    /**
     * Identifiers are restricted to one canonical octet form, so that the context encoding is injective
     * over them: a lossy text encoding (for example UTF-8 with replacement) would let two identifiers
     * share a context.
     */
    static boolean isIdentifier(String s) {
        return s != null && IDENTIFIER.matcher(s).matches();
    }

    private static String requireIdentifier(String s) {
        if (!isIdentifier(s)) {
            throw new IllegalArgumentException("identifiers are [a-z0-9-]{1,64}");
        }
        return s;
    }

    /** {@code [value]·G + [0]·H}: a public deposit. */
    static G1PedersenCommitment publicCommitment(BigInteger value) {
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        return G1PedersenCommitment.decode(identity).withPublicDelta(value, BITS);
    }

    /** Mempool admission: stateless and side-effect free (size and structure only). */
    Result validate(byte[] message) {
        if (message == null || message.length > config.maxMessageBytes()) {
            return Result.TOO_LARGE;
        }
        return Message.decode(message) == null ? Result.MALFORMED : Result.ACCEPTED;
    }

    /** One block, in order: the deterministic transition. Never throws for message content. */
    List<Result> apply(List<byte[]> block) {
        List<Result> results = new ArrayList<>();
        int[] proofBudget = {config.maxProofsPerBlock()};
        for (byte[] message : block) {
            Result admission = validate(message);
            if (admission != Result.ACCEPTED) {
                results.add(admission);
                continue;
            }
            Message m = Message.decode(message);
            results.add(m instanceof Transfer t ? applyTransfer(t, proofBudget) : applyMerge((Merge) m));
        }
        return results;
    }

    private Result authorize(Message m, Account from) {
        if (!MessageDigest.isEqual(hmac(from.authKey(), authInput(config.chainId(), m.body())), m.auth())) {
            return Result.BAD_AUTH;
        }
        return m.sequence() == from.nextSequence() ? Result.ACCEPTED : Result.REPLAY;
    }

    private Result applyTransfer(Transfer t, int[] proofBudget) {
        Account from = accounts.get(t.from());
        Account to = accounts.get(t.to());
        if (from == null || to == null || t.from().equals(t.to())) {
            return Result.UNKNOWN_ACCOUNT;
        }
        Result auth = authorize(t, from);
        if (auth != Result.ACCEPTED) {
            return auth;
        }
        G1PedersenCommitment amount;
        G1PedersenCommitment change;
        try {
            amount = G1PedersenCommitment.decode(t.amountCommitment());
            change = G1PedersenCommitment.decode(t.changeCommitment());
        } catch (CommitmentFormatException e) {
            return Result.MALFORMED;
        }
        if (!amount.add(change).equals(from.balance())) {
            return Result.BALANCE;
        }
        if (to.pending().size() >= MAX_PENDING) {
            return Result.PENDING_FULL;
        }
        // The proof budget is charged only here, where verification is actually reached.
        if (proofBudget[0] < 2) {
            return Result.OVER_BLOCK_LIMIT;
        }
        proofBudget[0] -= 2;
        if (!rangeProofHolds(amount, t.amountProof(), context(t, (byte) 0))
                || !rangeProofHolds(change, t.changeProof(), context(t, (byte) 1))) {
            return Result.RANGE_PROOF;
        }
        accounts.put(t.from(), new Account(from.authKey(), change, from.nextSequence() + 1, from.pending(),
                from.nextPendingId()));
        TreeMap<Long, G1PedersenCommitment> pending = new TreeMap<>(to.pending());
        pending.put(to.nextPendingId(), amount);
        accounts.put(t.to(), new Account(to.authKey(), to.balance(), to.nextSequence(), pending, to.nextPendingId() + 1));
        return Result.ACCEPTED;
    }

    /** The owner moves the named pending entries into its balance; it must be able to open them to spend later. */
    private Result applyMerge(Merge m) {
        Account owner = accounts.get(m.account());
        if (owner == null) {
            return Result.UNKNOWN_ACCOUNT;
        }
        Result auth = authorize(m, owner);
        if (auth != Result.ACCEPTED) {
            return auth;
        }
        TreeMap<Long, G1PedersenCommitment> pending = new TreeMap<>(owner.pending());
        G1PedersenCommitment balance = owner.balance();
        for (long id : m.ids()) {
            G1PedersenCommitment entry = pending.remove(id);
            if (entry == null) {
                return Result.UNKNOWN_PENDING;    // also rejects an id named twice
            }
            balance = balance.add(entry);
        }
        accounts.put(m.account(), new Account(owner.authKey(), balance, owner.nextSequence() + 1, pending,
                owner.nextPendingId()));
        return Result.ACCEPTED;
    }

    /** A verified proof, or false: every format error of the proof is a deterministic rejection. */
    private boolean rangeProofHolds(G1PedersenCommitment c, byte[] proof, byte[] ctx) {
        try {
            return verifier.verify(c, proof, BITS, ctx);
        } catch (CommitmentFormatException e) {
            return false;
        }
    }

    /**
     * The proof context (spec §5.1): a namespace, then every field length-prefixed or fixed-width,
     * so no two (chain, from, to, sequence, role) give the same octets. At most about 250 octets.
     */
    static byte[] context(String chainId, String from, String to, long sequence, byte role) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(CONTEXT_PREFIX);
        for (String s : List.of(chainId, from, to)) {
            writeField(out, requireIdentifier(s).getBytes(StandardCharsets.US_ASCII));
        }
        out.writeBytes(ByteBuffer.allocate(8).putLong(sequence).array());
        out.write(role);
        return out.toByteArray();
    }

    private byte[] context(Transfer t, byte role) {
        return context(config.chainId(), t.from(), t.to(), t.sequence(), role);
    }

    /** The authorized octets: a domain-separation prefix and the chain id, then the message body. */
    static byte[] authInput(String chainId, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(AUTH_PREFIX);
        writeField(out, requireIdentifier(chainId).getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** The account's balance commitment (public state). */
    G1PedersenCommitment balanceOf(String account) {
        return accounts.get(account).balance();
    }

    /** The account's pending entries, by id (public state). */
    Map<Long, G1PedersenCommitment> pendingOf(String account) {
        return new TreeMap<>(accounts.get(account).pending());
    }

    long nextSequence(String account) {
        return accounts.get(account).nextSequence();
    }

    /** SHA-256 over the state in key order: equal on every replica that applied the same blocks. */
    byte[] stateDigest() {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, Account> e : accounts.entrySet()) {
                sha.update(e.getKey().getBytes(StandardCharsets.US_ASCII));
                sha.update((byte) 0);
                sha.update(e.getValue().balance().toPointBytes());
                sha.update(ByteBuffer.allocate(16).putLong(e.getValue().nextSequence())
                        .putLong(e.getValue().nextPendingId()).array());
                for (Map.Entry<Long, G1PedersenCommitment> p : e.getValue().pending().entrySet()) {
                    sha.update(ByteBuffer.allocate(8).putLong(p.getKey()).array());
                    sha.update(p.getValue().toPointBytes());
                }
            }
            return sha.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] hmac(byte[] key, byte[] input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void writeField(ByteArrayOutputStream out, byte[] field) {
        out.writeBytes(ByteBuffer.allocate(4).putInt(field.length).array());
        out.writeBytes(field);
    }

    /** A length-prefixed field of at most {@code max} octets (bounded before allocating). */
    private static byte[] readField(ByteBuffer in, int max) {
        int length = in.getInt();
        if (length < 0 || length > max || length > in.remaining()) {
            throw new IllegalArgumentException("field length");
        }
        byte[] out = new byte[length];
        in.get(out);
        return out;
    }

    /** An identifier field: ASCII decoding cannot merge two octet strings, then the pattern is enforced. */
    private static String readIdentifier(ByteBuffer in) {
        String s = new String(readField(in, 64), StandardCharsets.US_ASCII);
        if (!isIdentifier(s)) throw new IllegalArgumentException("identifier");
        return s;
    }

    /** A decoded message: its authorized body, the tag, and its sender's sequence number. */
    sealed interface Message permits Transfer, Merge {
        byte[] body();

        byte[] auth();

        long sequence();

        /** The message, or null if the octets are not exactly one well-formed message. */
        static Message decode(byte[] message) {
            ByteBuffer in = ByteBuffer.wrap(message);
            try {
                if (in.get() != VERSION) return null;
                byte type = in.get();
                Message m;
                if (type == TYPE_TRANSFER) {
                    String from = readIdentifier(in);
                    String to = readIdentifier(in);
                    long sequence = in.getLong();
                    byte[] amount = new byte[48];
                    in.get(amount);
                    byte[] change = new byte[48];
                    in.get(change);
                    byte[] amountProof = readField(in, G1RangeProof.length(BITS));
                    byte[] changeProof = readField(in, G1RangeProof.length(BITS));
                    byte[] body = Arrays.copyOf(message, in.position());
                    byte[] auth = new byte[32];
                    in.get(auth);
                    m = new Transfer(from, to, sequence, amount, change, amountProof, changeProof, body, auth);
                } else if (type == TYPE_MERGE) {
                    String account = readIdentifier(in);
                    long sequence = in.getLong();
                    int count = in.getInt();
                    if (count < 1 || count > MAX_PENDING) return null;
                    long[] ids = new long[count];
                    for (int i = 0; i < count; i++) ids[i] = in.getLong();
                    byte[] body = Arrays.copyOf(message, in.position());
                    byte[] auth = new byte[32];
                    in.get(auth);
                    m = new Merge(account, sequence, ids, body, auth);
                } else {
                    return null;
                }
                return in.hasRemaining() || m.sequence() < 0 ? null : m;
            } catch (RuntimeException e) {
                return null;
            }
        }
    }

    /**
     * A transfer: {@code version ‖ type 1 ‖ len‖from ‖ len‖to ‖ sequence(8) ‖ C_amount(48) ‖
     * C_change(48) ‖ len‖amountProof ‖ len‖changeProof ‖ auth(32)}.
     */
    record Transfer(String from, String to, long sequence, byte[] amountCommitment, byte[] changeCommitment,
                    byte[] amountProof, byte[] changeProof, byte[] body, byte[] auth) implements Message {

        static byte[] encodeBody(String from, String to, long sequence, byte[] amountCommitment, byte[] changeCommitment,
                                 byte[] amountProof, byte[] changeProof) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(VERSION);
            out.write(TYPE_TRANSFER);
            writeField(out, requireIdentifier(from).getBytes(StandardCharsets.US_ASCII));
            writeField(out, requireIdentifier(to).getBytes(StandardCharsets.US_ASCII));
            out.writeBytes(ByteBuffer.allocate(8).putLong(sequence).array());
            out.writeBytes(amountCommitment);
            out.writeBytes(changeCommitment);
            writeField(out, amountProof);
            writeField(out, changeProof);
            return out.toByteArray();
        }
    }

    /** A merge: {@code version ‖ type 2 ‖ len‖account ‖ sequence(8) ‖ count(4) ‖ ids(8 each) ‖ auth(32)}. */
    record Merge(String account, long sequence, long[] ids, byte[] body, byte[] auth) implements Message {

        static byte[] encodeBody(String account, long sequence, long... ids) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(VERSION);
            out.write(TYPE_MERGE);
            writeField(out, requireIdentifier(account).getBytes(StandardCharsets.US_ASCII));
            out.writeBytes(ByteBuffer.allocate(8).putLong(sequence).array());
            out.writeBytes(ByteBuffer.allocate(4).putInt(ids.length).array());
            for (long id : ids) out.writeBytes(ByteBuffer.allocate(8).putLong(id).array());
            return out.toByteArray();
        }
    }
}
