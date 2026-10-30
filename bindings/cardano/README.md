# Browser membership proof → local Cardano claim

An opt-in, disposable Yaci DevKit example for [ADR-0064](../../docs/adr/0064-portable-circuits-and-typescript-frontend.md).
The browser compiles a TS-authored Merkle relation with the existing Java gadget and generates
a Groth16 BLS12-381 proof. This JVM runner uses ZeroJ's existing checked Cardano point codec
and JuLC Groth16 library to submit that exact Chromium proof. It implements no new cryptography.

The [M3 report](../circuit/M3-MERKLE.md) records costs, limits and security boundaries.
This is a two-leaf tree with published test inputs and disposable setup, **not a production allowlist**.
The runner creates an ephemeral signing account in memory and requests 100 local test ADA.
It writes public evidence only under ignored `bindings/cardano/build/evidence`.

## Prerequisites and run

1. Run `GRAALVM_HOME=... python3 bindings/wasm/circuit-check.py` from the repository root.
   This creates the matching development key/VK, a fresh `chromium-proof.json` and an independently
   verified valid `unapproved-root-proof.json`. No browser wallet or upload endpoint is needed.
2. Run a **local** Yaci DevKit with protocol major 11, store API at `http://localhost:8080/api/v1/`,
   faucet at `http://localhost:10000/local-cluster/api/addresses/topup`, testnet magic 42, and
   node container `node1-yaci-cli-1`. The tested node socket is
   `/clusters/nodes/default/node/node.sock`. Other node/socket profiles are not silently inferred.
3. Install the pinned JuLC experimental dependencies into Maven Local. This isolated runner uses
   `0.1.0-pre20-c3a31c2-SNAPSHOT`, source commit
   `c3a31c2a1a74b5de8d3f604f17b597c76395b664` of `https://github.com/bloxbean/julc`.
   This commit-labelled snapshot was not available in the public repositories during validation.
   In a separate clean checkout of that commit, with Java 25, run `./gradlew publishToMavenLocal`.
   The build derives the snapshot suffix from the checked-out commit. Do not publish remotely.
4. From this ZeroJ repository root:

```sh
export JAVA_HOME="$GRAALVM_HOME"
./gradlew -p bindings/cardano run --args=--local-devnet --max-workers=2 --console=plain
```

The composite build uses the current ZeroJ source for `zeroj-onchain-julc` and its checked codec.
The runner alone pins JuLC pre20 / Cardano Client Lib 0.8.0-pre7; it does not change the root
project's dependency profile or claim that the root profile was tested against this node.
The JVM evaluator can use native support for ledger builtins; browser proving remains pure Java
compiled to Wasm, with WebCrypto-backed entropy and no native blst dependency.

`YACI_STORE_URL` and `YACI_FAUCET_URL` may select another loopback port/path; non-loopback URLs,
userinfo, query strings and fragments reject. `CARDANO_CONTAINER` selects the local Docker
container. The CLI flag is deliberately required, and this example is not a mainnet/preprod runner.
The browser proof/VK/manifest are trusted local development artifacts; this harness is not a
service for admitting arbitrary uploaded cryptographic files. Never reuse its development keys
as production ceremony artifacts.

## What the validator actually authorizes

The script parameters pin the approved root, verification key and one payment-key hash.
The inline datum must contain exactly that one root. The redeemer carries action `1` and the
compressed proof. The validator requires the pinned key in transaction signatories, the exact
action, the approved root, and a valid proof against the pinned VK. Ledger signature validation
then authorizes the transaction's contents. The authorized signer chooses the recipient/output;
this is not an issuer-restricted payout or a private state transition.

Membership is reusable. A published proof can be reused for other deposits protected by the
same root/signer policy; it is not tied to a nullifier or a unique user. The signer is public.
Cardano prevents consuming **the same UTxO** twice; that does not provide global one-use
membership or anonymous spending. The test values (leaf 42, sibling 100, direction true) are
public fixtures, so there is no privacy claim about this particular witness.

## Checks and evidence

- Independent snarkjs and JVM checks cover fresh browser proofs before this runner is used.
- The valid signed claim is evaluated by JuLC Java, the remote evaluator, and Haskell
  `cardano-cli calculate-plutus-script-cost`; their execution budgets must be identical.
- Signed submissions with a valid proof for an **unapproved root**, wrong action, missing required
  signer, and negated proof A must all fail phase 2 with `ValidationTagMismatch`.
- The valid transaction must be submitted and confirmed in the store.
- A different transaction ID attempting to consume the same UTxO is constructed before that
  confirmation and submitted afterwards. It must fail for spent/missing inputs. The observed
  node error was `ConwayMempoolFailure: All inputs are spent`; `BadInputsUTxO` is also admitted.
  Resubmitting identical bytes alone would not be a useful replay test.

The runner records live protocol parameters, script/transaction sizes, consumed and declared
execution units, execution/total fees, artifact hashes, transaction hashes and all verdicts.
Fees exclude the 5 ADA locked output, change and returned collateral; these are values moved
through the example, not verification fees. The valid claim fee and separate funding/locking
fee are reported independently. Raw transaction/vector/log files remain untracked.
