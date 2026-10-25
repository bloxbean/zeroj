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

/**
 * TEST-ONLY reference confidential-accounting state machine (ADR-0061 M5, D9; spec §13). It has the
 * shape of a Yano-X {@code AppStateMachine} (a stateless {@link #validate} for admission, a
 * deterministic {@link #apply} per block, a state digest) without depending on Yano. It shows what
 * the HOST must add around {@code bulletproof-range-bls12-381-g1-v1}, because a verified range proof
 * provides none of it (spec §1.1, §13):
 *
 * <ul>
 *   <li><b>Authorization:</b> every transfer carries a tag over its body under the sender's key
 *       (HMAC-SHA256, standing in for a signature).</li>
 *   <li><b>Replay protection:</b> a per-sender sequence number that must equal the next expected one.</li>
 *   <li><b>Binding:</b> each proof's context is the chain id, sender, recipient, sequence and output
 *       role, length-prefixed (spec §5.1), so a proof cannot move to another message or output.</li>
 *   <li><b>Balance (ADR-0051 D3a):</b> the sender's balance commitment must equal the amount plus the
 *       change commitment, and both carry their own {@value #BITS}-bit range proof. With coefficients
 *       1 and 1, {@code 2·(2^64 − 1) < q}, so the commitment equation is integer conservation. Total
 *       supply is capped below {@code 2^63} at genesis, so every honest balance stays spendable.</li>
 *   <li><b>Limits:</b> message size, and proofs per block (excess transfers are rejected, in order).</li>
 *   <li><b>Determinism:</b> no randomness, clock or I/O; ordered maps only; every malformed input is a
 *       deterministic rejection, never an exception escaping {@code apply}.</li>
 * </ul>
 *
 * <p>Not product code: no persistence, no real signatures, no fee or nullifier logic.
 */
final class ConfidentialLedger {

    /** The range-proof width for every output. */
    static final int BITS = 64;
    /** Total-supply cap at genesis: below 2^63, so sums of balances stay below 2^64. */
    static final BigInteger SUPPLY_CAP = BigInteger.ONE.shiftLeft(63);

    private static final byte[] CONTEXT_PREFIX = "zeroj-reference-confidential-ledger-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;

    record Config(String chainId, int maxMessageBytes, int maxProofsPerBlock) {
    }

    /** Why a message was rejected; {@code ACCEPTED} otherwise. */
    enum Result {
        ACCEPTED, TOO_LARGE, MALFORMED, UNKNOWN_ACCOUNT, BAD_AUTH, REPLAY, BALANCE, RANGE_PROOF, OVER_BLOCK_LIMIT
    }

    private record Account(byte[] authKey, G1PedersenCommitment balance, long nextSequence) {
    }

    private final Config config;
    private final G1RangeVerifier verifier;
    private final TreeMap<String, Account> accounts = new TreeMap<>();

    /**
     * Genesis: accounts with public initial balances, committed with blinding 0 (deposits are public).
     *
     * @throws IllegalArgumentException if the balances exceed {@link #SUPPLY_CAP}
     */
    ConfidentialLedger(Config config, G1RangeVerifier verifier, Map<String, byte[]> authKeys,
                       Map<String, BigInteger> initialBalances) {
        this.config = Objects.requireNonNull(config, "config");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        BigInteger total = BigInteger.ZERO;
        for (Map.Entry<String, byte[]> e : new TreeMap<>(authKeys).entrySet()) {
            BigInteger initial = initialBalances.getOrDefault(e.getKey(), BigInteger.ZERO);
            if (initial.signum() < 0) throw new IllegalArgumentException("negative balance");
            total = total.add(initial);
            accounts.put(e.getKey(), new Account(e.getValue().clone(), publicCommitment(initial), 0));
        }
        if (total.compareTo(SUPPLY_CAP) >= 0) {
            throw new IllegalArgumentException("total supply must be below 2^63");
        }
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
        return Transfer.decode(message) == null ? Result.MALFORMED : Result.ACCEPTED;
    }

    /** One block, in order: the deterministic transition. Never throws for message content. */
    List<Result> apply(List<byte[]> block) {
        List<Result> results = new ArrayList<>();
        int proofs = 0;
        for (byte[] message : block) {
            Result admission = validate(message);
            if (admission != Result.ACCEPTED) {
                results.add(admission);
                continue;
            }
            if (proofs + 2 > config.maxProofsPerBlock()) {
                results.add(Result.OVER_BLOCK_LIMIT);
                continue;
            }
            proofs += 2;
            results.add(applyTransfer(Transfer.decode(message)));
        }
        return results;
    }

    private Result applyTransfer(Transfer t) {
        Account from = accounts.get(t.from());
        Account to = accounts.get(t.to());
        if (from == null || to == null || t.from().equals(t.to())) {
            return Result.UNKNOWN_ACCOUNT;
        }
        if (!MessageDigest.isEqual(hmac(from.authKey(), t.body()), t.auth())) {
            return Result.BAD_AUTH;
        }
        if (t.sequence() != from.nextSequence()) {
            return Result.REPLAY;
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
        if (!rangeProofHolds(amount, t.amountProof(), context(t, (byte) 0))
                || !rangeProofHolds(change, t.changeProof(), context(t, (byte) 1))) {
            return Result.RANGE_PROOF;
        }
        accounts.put(t.from(), new Account(from.authKey(), change, from.nextSequence() + 1));
        accounts.put(t.to(), new Account(to.authKey(), to.balance().add(amount), to.nextSequence()));
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
     * so no two (chain, from, to, sequence, role) give the same octets.
     */
    static byte[] context(String chainId, String from, String to, long sequence, byte role) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(CONTEXT_PREFIX);
        for (String s : List.of(chainId, from, to)) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            out.writeBytes(ByteBuffer.allocate(4).putInt(b.length).array());
            out.writeBytes(b);
        }
        out.writeBytes(ByteBuffer.allocate(8).putLong(sequence).array());
        out.write(role);
        return out.toByteArray();
    }

    private byte[] context(Transfer t, byte role) {
        return context(config.chainId(), t.from(), t.to(), t.sequence(), role);
    }

    /** The sender's balance commitment (public state). */
    G1PedersenCommitment balanceOf(String account) {
        return accounts.get(account).balance();
    }

    long nextSequence(String account) {
        return accounts.get(account).nextSequence();
    }

    /** SHA-256 over the state in key order: equal on every replica that applied the same blocks. */
    byte[] stateDigest() {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, Account> e : accounts.entrySet()) {
                sha.update(e.getKey().getBytes(StandardCharsets.UTF_8));
                sha.update((byte) 0);
                sha.update(e.getValue().balance().toPointBytes());
                sha.update(ByteBuffer.allocate(8).putLong(e.getValue().nextSequence()).array());
            }
            return sha.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] hmac(byte[] key, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(body);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A transfer message: {@code version ‖ len‖from ‖ len‖to ‖ sequence(8) ‖ C_amount(48) ‖ C_change(48)
     * ‖ len‖amountProof ‖ len‖changeProof ‖ auth(32)}. The auth tag covers everything before it.
     */
    record Transfer(String from, String to, long sequence, byte[] amountCommitment, byte[] changeCommitment,
                    byte[] amountProof, byte[] changeProof, byte[] body, byte[] auth) {

        static byte[] encodeBody(String from, String to, long sequence, byte[] amountCommitment, byte[] changeCommitment,
                                 byte[] amountProof, byte[] changeProof) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(VERSION);
            writeField(out, from.getBytes(StandardCharsets.UTF_8));
            writeField(out, to.getBytes(StandardCharsets.UTF_8));
            out.writeBytes(ByteBuffer.allocate(8).putLong(sequence).array());
            out.writeBytes(amountCommitment);
            out.writeBytes(changeCommitment);
            writeField(out, amountProof);
            writeField(out, changeProof);
            return out.toByteArray();
        }

        /** The transfer, or null if the octets are not exactly one well-formed message. */
        static Transfer decode(byte[] message) {
            ByteBuffer in = ByteBuffer.wrap(message);
            try {
                if (in.get() != VERSION) return null;
                String from = new String(readField(in, 64), StandardCharsets.UTF_8);
                String to = new String(readField(in, 64), StandardCharsets.UTF_8);
                long sequence = in.getLong();
                byte[] amount = new byte[48];
                in.get(amount);
                byte[] change = new byte[48];
                in.get(change);
                byte[] amountProof = readField(in, G1RangeProof.length(BITS));
                byte[] changeProof = readField(in, G1RangeProof.length(BITS));
                int bodyLength = in.position();
                byte[] auth = new byte[32];
                in.get(auth);
                if (in.hasRemaining() || sequence < 0) return null;
                return new Transfer(from, to, sequence, amount, change, amountProof, changeProof,
                        Arrays.copyOf(message, bodyLength), auth);
            } catch (RuntimeException e) {
                return null;
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
    }
}
