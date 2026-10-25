# Confidential accounting on Yano-X with Bulletproof range proofs: handoff note (ADR-0061 D9, M5)

**Status:** handoff note for a future Yano-X ADR. ZeroJ ships no Yano-X plugin; the plugin belongs
in `yano-x` (ADR-0061 D9, Q4). Experimental: nothing here is approved for value-bearing use.

**What ZeroJ provides:**
- the proof protocol `bulletproof-range-bls12-381-g1-v1` (`docs/specs/bulletproof-range-bls12-381-g1-v1.md`), with
  `G1RangeProver` and `G1RangeVerifier` in `zeroj-bls12381` (`org.zeroj.bls12381.bulletproofs`);
- the deterministic-verifier contract of spec §13;
- a reference state machine with no Yano dependency, in `zeroj-integration-tests` test sources:
  `org.zeroj.it.confidential.ConfidentialLedger` and `ConfidentialLedgerTest`. It is a test, not a
  product.

## What the host must do

The verifier establishes one statement: a commitment `V ≠ O` opens to a value in `[0, 2^n)`
(spec §1.1). Everything else is the host's job:

| Concern | In the reference ledger | Notes for a Yano-X plugin |
|---|---|---|
| Authorization | HMAC-SHA256 under the sender's key, standing in for a signature, over a domain-separated input: a ledger prefix, the chain id, then the message body | Use the chain's signature scheme, domain-separated, and check it before any proof |
| Replay | a per-account sequence number that must equal the next expected one | Any rule works if it is part of the transition state |
| Identifiers | chain and account ids are canonical ASCII, `[a-z0-9-]{1,64}`, enforced at genesis and in decoding | A lossy text encoding would let two ids share a proof context |
| Proof binding | `ctx` = namespace ‖ chain id, sender, recipient (each length-prefixed) ‖ sequence (8 octets) ‖ output role | `ctx` must be injective over the fields (spec §5.1); a proof under one `ctx` fails under any other |
| **Incoming amounts** | each incoming amount becomes a separate **pending entry** of the recipient; the owner moves the entries it can open into its balance with its own authorized merge message | A payee can spend only what it can open. Adding incoming amounts straight to the balance lets any payer freeze it by withholding a blinding, even with a zero-value transfer, and lets any incoming transfer invalidate the payee's pending spends (found in M3–M6 review). Delivering openings (for example ADR-0052/0054 encryption) is the host's choice; a note/UTXO model (ADR-0055) avoids the problem differently |
| Balance | `C_balance == C_amount + C_change`, each output with its own 64-bit proof | See the invariant below |
| Supply | total supply below `2^63` at genesis | Keeps every balance below `2^64`, so it can move in one transfer |
| Width | `n = 64` for every output, from configuration | Never take `n` from the proof or its length (spec §13 item 5) |
| Limits | message size (65,536 octets, Yano-X's default), at most 16 pending entries per account, and verified proofs per block | Yano-X's `zk.max-proofs-per-block` is advisory; the plugin must enforce its own limit in `apply()`. Count only proofs actually verified, so unauthenticated messages do not use the budget. With no fees, the pending pool can be filled by spam up to its limit, which blocks receiving (not spending); a real host prices or rate-limits incoming entries |
| Determinism | ordered maps, no randomness, clock or I/O; every malformed input is a rejection; configuration (ids, keys) is checked at construction | `apply()` must never throw on message content; catch `CommitmentFormatException` and reject |

**The balance invariant.** Every balance and pending entry opens to genesis plus what it received
minus what it sent, and the total S is constant, below `2^63`. By induction every value is in
`[0, S]`:
- A transfer needs `C_balance == C_amount + C_change`, with a 64-bit range proof on each output. So
  `v_amount + v_change ≡ b (mod q)`, with the left side at most `2^65 − 2 < q` and `b < q`. That makes
  it an integer equality, and the amount is in `[0, b]`. This is ADR-0051 D3a, with the balance's
  bound coming from the invariant rather than from a proof.
- A merge adds pending entries whose values sum to at most `S < q`, so it does not wrap.

**Every change to a balance must keep this invariant.** For example, a deposit with a
depositor-chosen blinding and no proof would break it.

## What the tests show

The negative tests run on both the pure-Java and the blst provider:
- honest transfers and merges keep each balance commitment equal to its owner's opening;
- a zero-value transfer whose opening is withheld lands in pending and does not affect the payee's
  balance;
- an incoming transfer placed before the payee's spend in the same block does not invalidate it;
- replay, bad tags (including a tag for another chain), unknown accounts, self-transfers and bad
  merges are rejected, and the state is unchanged;
- inflation, a spend that needs a negative change, is refused: the honest prover refuses the
  value, and a proof borrowed from the other output fails;
- a proof moved to another recipient or output fails;
- malformed messages, malformed and identity commitments, proofs of another width, flipped proof
  bytes and non-canonical identifiers are rejected;
- the proof budget is charged only when verification is reached.

Separately:
- the pending limit (pure Java);
- configuration invariants (no provider involved);
- two replicas on different providers apply the same good and bad blocks with identical results and
  state digests.

## Before a plugin

1. **Dependency.** Yano-X pins ZeroJ `0.1.0-pre10`, from before the `org.zeroj` namespace, and its
   ZK modules are outside its build. A plugin needs an `org.zeroj` release that contains ADR-0061.
2. **Verification time.** Verification is measured in
   `docs/benchmarks/bulletproof-range-g1-2026-10-25.md`: about 1.3 s per 64-bit proof on one core
   of an M4 Max, on either provider. blst is not faster today: every provider call re-validates its
   points in pure Java. Each transfer carries two proofs. Size the per-block limit from that
   measurement on the slowest member's hardware; verification parallelises across cores. The two
   providers give identical verdicts (ADR-0061 I7).
3. **Proving is offline or isolated** (ADR-0038). The Java prover is not constant-time and must
   not run where an adversary can observe its timing. Its randomness depends on the runtime's
   entropy configuration, which is trusted (spec §7.3).
4. **External review.** ADR-0061 requires an external cryptographic review of the protocol before
   any value-bearing use.
5. **What a range proof does not give:** privacy of who pays whom (the reference ledger's accounts
   are public), fee logic, delivery of openings to payees, or recovery for an owner who loses their
   balance opening (the funds become unspendable).
