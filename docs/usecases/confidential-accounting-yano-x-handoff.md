# Confidential accounting on Yano-X with Bulletproof range proofs: handoff note (ADR-0061 D9, M5)

**Status:** handoff note for a future Yano-X ADR. ZeroJ ships no Yano-X plugin; the plugin belongs
in `yano-x` (ADR-0061 D9, Q4). Experimental: nothing here is approved for value-bearing use.

**What ZeroJ provides:**
- the proof protocol `bulletproof-range-bls12-381-g1-v1` (`docs/specs/bulletproof-range-bls12-381-g1-v1.md`), with
  `G1RangeProver` and `G1RangeVerifier` in `zeroj-bls12381` (`org.zeroj.bls12381.bulletproofs`);
- the deterministic-verifier contract of spec §13;
- a reference state machine with no Yano dependency, in `zeroj-integration-tests` test sources:
  `org.zeroj.it.confidential.ConfidentialLedger` and `ConfidentialLedgerTest`.

## What the host must do

The verifier establishes one statement: a commitment `V ≠ O` opens to a value in `[0, 2^n)`
(spec §1.1). Everything else is the host's job:

| Concern | In the reference ledger | Notes for a Yano-X plugin |
|---|---|---|
| Authorization | HMAC-SHA256 over the message body under the sender's key, standing in for a signature | Use the chain's signature scheme; verify it before any proof |
| Replay | a per-sender sequence number that must equal the next expected one | Any rule works if it is part of the transition state |
| Proof binding | `ctx` = namespace ‖ (length-prefixed) chain id, sender, recipient ‖ sequence (8 octets) ‖ output role | `ctx` must be injective over the fields (spec §5.1); a proof under one `ctx` fails under any other |
| Balance | `C_balance == C_amount + C_change`, each output with its own 64-bit proof | This is ADR-0051 D3a: with coefficients 1 and 1, `2·(2^64 − 1) < q`, so equality is integer conservation |
| Supply | total supply capped below `2^63` at genesis | Keeps every honest balance below `2^64`, so it stays spendable |
| Width | `n = 64` for every output, from configuration | Never take `n` from the proof or its length (spec §13 item 5) |
| Limits | message size (65,536 octets, Yano-X's default) and proofs per block | Excess transfers are rejected in order; no gas metering exists |
| Determinism | ordered maps, no randomness, clock or I/O; every malformed input is a rejection | `apply` must never throw on message content; catch `CommitmentFormatException` and reject |

The tests show, deterministically on both the pure-Java and the blst provider:
- honest transfers keep each balance commitment equal to its owner's opening;
- replay, a bad tag, an unknown account and a self-transfer are rejected, and the state is
  unchanged;
- inflation, a spend that needs a negative change, is refused: the honest prover refuses the
  value, and a proof borrowed from the other output fails;
- a proof moved to another recipient or output fails, because the context binds it;
- malformed messages, malformed and identity commitments, proofs of another width and flipped
  proof bytes are rejected;
- the per-block limit holds;
- two replicas on different providers produce identical results and state digests.

## Before a plugin

1. **Dependency.** Yano-X pins ZeroJ `0.1.0-pre10`, from before the `org.zeroj` namespace, and its
   ZK modules are outside its build. A plugin needs an `org.zeroj` release that contains ADR-0061.
2. **Verification time.** Verification is measured in
   `docs/benchmarks/bulletproof-range-g1-2026-10-25.md`, about 1.2 s per 64-bit proof on pure Java
   on an M4 Max. Two proofs per transfer bound the block rate. Set `zk.max-proofs-per-block` from
   that measurement, on the slowest member's hardware. The blst provider is faster, and the two
   give identical verdicts (ADR-0061 I7).
3. **Proving is offline or isolated** (ADR-0038). The Java prover is not constant-time and must
   not run where an adversary can observe its timing. Its randomness depends on the runtime's
   entropy configuration, which is trusted (spec §7.3).
4. **External review.** ADR-0061 requires an external cryptographic review of the protocol before
   any value-bearing use.
5. **What a range proof does not give:** privacy of who pays whom (the reference ledger's
   accounts are public), fee logic, or protection against a sender who loses their opening (the
   funds become unspendable).
