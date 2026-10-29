# Prove a private SHA-256 approval

> Run a Java Groth16 proof for a private approval record, bind all SHA-256 digest bits, reject invalid records, and distinguish proof validity from a trusted issuer registry.

Canonical URL: https://zeroj.dev/tutorials/sha256-record/

A vendor-onboarding service has approved a record and registered its SHA-256 digest. A partner
wants to check “approved for program 7” without receiving the subject reference or the record's
private nonce. You will build that statement and verify it in Java.

**What you'll run:** a 48-byte private record, a circuit that checks its format and approval
policy, a BLS12-381 Groth16 proof, and an application verifier that trusts a particular issuer
digest. The example includes rejection cases, including a valid proof about an unregistered record.

**What you'll learn:** exact byte encoding, private witnesses versus public inputs, full digest
packing, and why “proof verified” is only one part of application acceptance. The
[Web2 use-case guide](https://zeroj.dev/use-cases/sha2-web2/) extends the idea to documents, eligibility, voting,
private state and audit proofs.

**Note: Run against the source checkout:** 

You need Java 25 and a checkout containing the SHA-256 gadget and this example. The command
uses the repository's Gradle wrapper and a local composite build, so it does not depend on the
docsite's pinned Maven release having the new API. No Node.js, Circom or Yaci DevKit is needed
for the Java tutorial. See [Installation](https://zeroj.dev/start/installation/) for Java setup.

**Caution: Public teaching data and development setup:** 

The sample record and nonce are deliberately public and deterministic. Do not use them for
private records. Each run makes fresh single-party development keys, enables the existing
insecure-setup flag for the demo process, and deletes its temporary key directory afterwards.
The example is not an issuer service, a holder-authentication protocol or a production ceremony.
SHA-256 remains experimental pending external review.

## See the statement before running it

Try **Edit the record**, **Denied record**, and **Unregistered record**. The first two cannot
satisfy the circuit; the last satisfies the circuit but fails the trusted-registry check.

_The web version of this page has an interactive illustration here._

```text
Private: record[48] = header + subject reference + nonce
Public:  digest0, digest1 = all 32 bytes of the issuer's registered SHA-256 digest
Circuit: correct header AND approved status AND SHA256(record) = public digest
App:     expected issuer digest AND trusted circuit key AND valid proof
```

## Run the complete example

1. **Open the source checkout.** The complete example is under
   [`www/examples/sha256-record`](https://github.com/bloxbean/zeroj/blob/main/www/examples/sha256-record).
   Its `settings.gradle` includes the repository root as a composite build; its dependencies are
   substituted with the local ZeroJ projects. It is separate from the default library build.

2. **Run from the repository root.**

   ```sh
   ./gradlew -p www/examples/sha256-record run --max-workers=2
   ```

   The first invocation may download Gradle dependencies. Development-setup warnings are expected.
   The Java process uses a maximum 4 GiB heap. The demo generates and verifies real proofs;
   the illustration above is only an explanation of those steps.

3. **Read the acceptance and rejection results.** Alongside Gradle output, you should see:

   ```text
   Trusted SHA-256: e0dea9dc571d39771bfef376bd3fa167458246ee8a3492f1f3c601532a88e891
   Public input order: [digest0, digest1]
   Registered approved record: accepted
   Changed record: rejected
   Denied record with its own matching hash: rejected
   Wrong program with its own matching hash: rejected
   Changed public digest: rejected
   Unregistered approved record: proof is mathematically valid
   Unregistered approved record: application rejects
   ```

   Unexpected acceptance or rejection makes the program fail. Proof bytes change between runs
   because proving uses random blinding; the public fixture's digest stays the same.

## 1. Define the exact record bytes

This is an **illustrative fixed-width format**, not an existing credential standard. A real
integration must reproduce the issuer's actual format.

| Byte offsets | Length | Meaning | Circuit rule |
|---|---:|---|---|
| 0–3 | 4 | ASCII `ZJAP`, a format/domain tag | Equals those four bytes |
| 4 | 1 | Format version | Equals `1` |
| 5 | 1 | Approval status | Equals `1` (approved) |
| 6–7 | 2 | Unsigned program ID, big-endian | Equals `7` (`00 07`) |
| 8–15 | 8 | Opaque subject reference | Private bytes; not otherwise interpreted |
| 16–47 | 32 | Private issuance nonce | Private bytes included in the hash |

All 48 bytes are private inputs. The accepted predicate reveals the required header/status
values; it does not reveal the subject reference or nonce. The sample subject is ASCII
`USER0042` and its nonce is the byte sequence `00` through `1f` so you can reproduce the digest.
For a new private-record format, generate fresh 32-byte nonces with a cryptographic RNG such as
`SecureRandom` at issuance and keep them with the private record. A circuit can bind a nonce;
it does not certify that the issuer sampled it randomly.

The issuer hashes the entire record with ordinary Java `MessageDigest`. Inside the circuit,
`Sha256.hashBytes` constrains the *same* hash relation. Computing the hash only in host Java
would not constrain a dishonest prover's witness.

## 2. Constrain the hash and the policy

The core below is the `circuit()` method from
[`ApprovedRecordDemo`](https://github.com/bloxbean/zeroj/blob/main/www/examples/sha256-record/src/main/java/org/zeroj/docs/sha2/ApprovedRecordDemo.java).
`RECORD_BYTES` is the class constant `48`. The imports are `CircuitBuilder`, `Variable` and
`Sha256`; the full runnable class includes setup, proving, verification and rejection cases.

```java
    public static CircuitBuilder circuit() {
        var builder = CircuitBuilder.create("sha256-approved-record-v1");
        builder.publicVar("digest0").publicVar("digest1");
        for (int i = 0; i < RECORD_BYTES; i++) builder.secretVar("byte" + i);
        return builder.define(api -> {
            Variable[] record = new Variable[RECORD_BYTES];
            for (int i = 0; i < record.length; i++) record[i] = api.var("byte" + i);

            // "ZJAP", version 1, approved=1, program=7 (unsigned 16-bit big-endian).
            int[] requiredHeader = {0x5a, 0x4a, 0x41, 0x50, 1, 1, 0, 7};
            for (int i = 0; i < requiredHeader.length; i++)
                api.assertEqual(record[i], api.constant(requiredHeader[i]));

            Variable[] digest = Sha256.hashBytes(api, record); // All bytes range-constrained.
            for (int limb = 0; limb < 2; limb++) {
                Variable packed = api.constant(0);
                for (int j = 0; j < 16; j++)
                    packed = api.add(api.mul(packed, api.constant(256)), digest[16 * limb + j]);
                api.assertEqual(packed, api.var("digest" + limb));
            }
        });
    }
```

Every input byte is constrained to 0–255 by the hash gadget. Its padding and length suffix
are circuit constants. The header assertions enforce the policy, and the final assertions
bind every output digest byte to the public statement. Version and program are constants of
this circuit; changing them changes the relation and requires matching setup keys.

For annotation-based circuits the equivalent hash adapter is `ZkSha256.hash(zk, message)`.
It returns a `ZkBytes` digest: callers still need to constrain the policy and bind that digest
to their chosen public representation. See [gadgets](https://zeroj.dev/guides/circuits/gadgets/#standard-sha-2-digests)
for the API conventions.

## 3. Preserve the complete digest

The BLS12-381 scalar field cannot represent every 256-bit SHA-256 digest as one scalar without
loss. This example uses two unsigned 128-bit pieces, called **limbs**:

```text
digest0 = integer from digest bytes  0..15, big-endian
digest1 = integer from digest bytes 16..31, big-endian
public inputs, in order = [digest0, digest1]
```

On the host, `new BigInteger(1, bytes)` supplies the positive sign explicitly. The circuit's
multiply-by-256 loop reproduces the same big-endian packing. Each limb fits in the field, and
both limbs together retain the full digest. Reducing the entire digest modulo the scalar field
or truncating it would change the statement.

For SHA-512, use `Sha512.hashBytes`, retain all 64 output bytes and bind **four** 128-bit limbs.
That is a different circuit with different keys and public-input arity. Do not swap verification
keys or reuse the SHA-256 limb schema.

## 4. Check the application statement before the proof

The sample's `accept` method compares the claimed public limbs with the digest obtained from
its trusted registry, then verifies with the application's trusted verification key. Both actors
are simulated in one program; no remote registry is contacted. A real service must authenticate
the registry and decide which record is acceptable.

The **unregistered record** case is deliberate: another record has a correct hash and an approved
status, so its proof verifies mathematically. The partner still rejects it because its digest is
not the one the issuer registered. Letting the prover supply both the claimed digest and the
“trusted” digest would remove this trust boundary.

| Negative case | What rejects it |
|---|---|
| Change the subject bytes but claim the original digest | Hash constraints during witness generation |
| Denied status with its own correct digest | Approval constraint during witness generation |
| Program 8 with its own correct digest | Program constraint during witness generation |
| Change a digest limb after proof generation | Cryptographic verifier |
| A valid proof for another approved record | Application's trusted-registry policy |

These checks explain the tutorial's behavior. They are not an exhaustive circuit audit. The
[gadget assurance suite](https://github.com/bloxbean/zeroj/blob/main/assurance/sha2-circom/README.md)
also checks compiled R1CS directly, independently of honest witness generation, with NIST vectors
and pinned Circom implementations.

## 5. Adapt the boundary to Cardano

The runnable example stops at Java verification. To use the statement on Cardano, start with
[Verify your proof on Cardano](https://zeroj.dev/tutorials/verify-on-cardano/) and add the application bindings:

- Pin the intended verification key/circuit and digest-limb order.
- Obtain the trusted digest or membership root from authenticated on-chain state, not an
  arbitrary redeemer or untrusted reference input.
- Bind the permitted action, beneficiary, policy context and relevant state to the proof and
  the actual transaction. The current two-input circuit does not bind those actions.
- Add expiry/revocation, holder authorization and one-use enforcement where the application
  requires them. This tutorial deliberately does not implement those protocols.
- Measure the complete validator's execution units, serialized script and transaction sizes,
  and fees. Host proof-generation time is not an on-chain fee measurement.

Anyone who obtains the private record can prove this statement, and an existing proof can be
copied. Knowledge of a record is not authentication of a specific wallet. A standalone valid
proof also does not remember whether it was used before.

## Advanced choices and costs

**Fixed lengths.** Both low-level SHA APIs accept a fixed-length array at circuit construction.
`hashBits` expects byte-aligned, MSB-first input. The low-level APIs support empty messages;
symbolic `ZkBytes` currently requires a nonempty vector. This is not a streaming or secret-length
interface. A variable-length protocol needs constrained padding/length handling of its own.

**Existing JSON, XML or PDFs.** Match the exact bytes the existing system hashes. Constrain any
field extraction used by the predicate. Supplying an extracted status separately from a file
digest leaves them unrelated unless the circuit proves their connection. The 48-byte example
avoids that parser problem by specifying each field's offset.

**Public hash privacy.** A public digest can reveal a predictable record by guessing and can
link repeated uses. The example's deterministic nonce is only a test fixture. A fresh secret
nonce can help a new format, but adding one to an existing digest format breaks compatibility.
Hiding which approved record was used needs a different statement, such as private membership
under a shared root. Issuers and outsourced provers can still know the data they handle.

**Optimized reference measurements.** These runs use 32-byte preimage circuits with complete
public digests, not this 48-byte approval policy. Each time is a pure-Java median of three proofs
after one warmup, on a shared Apple M4 Max with Java 25.0.2 and eight visible processors.

| 32-byte preimage | ZeroJ constraints | Proof median, 6 GiB heap cap | Proof median, 8 GiB heap cap |
|---|---:|---:|---:|
| SHA-256 | 25,758 | 1.15 s | 1.11 s |
| SHA-512 | 64,980 | 1.55 s | 1.91 s |

Both `-Xmx6g` and `-Xmx8g` completed the full compile, witness, development-setup and proving
pipeline. These are maximum Java heap settings, not total-process memory limits or minimum
requirements. Timings vary with workload and host activity; a larger heap is not automatically
faster. The same comparison also tested 128-byte and 1 KiB messages. Some individual runs had
higher memory peaks or slower timings after optimization, so do not assume every metric improves.

Rebuild circuit artifacts and generate new circuit-specific keys after upgrading. The digest
format is unchanged, but the optimized constraint layout differs. Keep old proofs with their
original verification keys.

**Document-sized messages.** A follow-up used the same machine, pure-Java prover and full
public digest at 2, 4, 8 and 16 KiB (one KiB is 1,024 bytes). This original measurement
used the compatibility API path. These are proof-time medians;
compilation, witness generation and one-time development setup are separate.

| Hash | Message | Proof seconds, 6 GiB heap | Proof seconds, 8 GiB heap |
|---|---:|---:|---:|
| SHA-256 | 2 KiB | 10.9 s | 11.7 s |
| SHA-512 | 2 KiB | 17.1 s | 16.5 s |
| SHA-256 | 4 KiB | 17.4 s | 17.2 s |
| SHA-512 | 4 KiB | 27.9 s | 28.4 s |
| SHA-256 | 8 KiB | 27.9 s | 39.1 s |
| SHA-512 | 8 KiB | 65.2 s | 65.4 s |
| SHA-256 | 16 KiB | Setup ran out of heap | 67.8 s |
| SHA-512 | 16 KiB | Setup ran out of heap | Setup ran out of heap |

All three failures occurred during setup, after compilation and witness generation. They
measure this pipeline's memory use, not an intrinsic hash-size limit. The 16 KiB SHA-256
success at 8 GiB used about 365 seconds for development setup, a 2.61 GiB key store and
10.88 GiB peak total-process RSS. A heap cap is not a physical-RAM budget. More heap was
not consistently faster, and these shared-machine timings are not latency guarantees.

**Memory-conscious pipeline follow-up.** A separate test of the existing `Groth16Pipeline`
completed full 16 KiB SHA-256 and SHA-512 proofs at both 6 GiB and 8 GiB heap caps, with the
same constraints. It releases the circuit graph before setup and loads cached constraints
after witness generation, avoiding the earlier memory overlap. Each profile used one warmup
and one measured proof, so its timings should not be substituted into the median table above.
Total-process RSS was about 9.28–12.62 GiB; these results do not establish operation on a
6 GB or 8 GB physical machine. See the
[setup-memory report](https://github.com/bloxbean/zeroj/blob/main/docs/reviews/sha2-setup-memory-investigation.md)
for the working example, measurements, independent checks and remaining limits.

This hashes the exact file bytes; it does not parse a PDF/JSON document or prove predicates
about extracted fields. Additional application logic, multiple hash calls and Merkle paths
need separate measurements. See the
[document-size report](https://github.com/bloxbean/zeroj/blob/main/docs/reviews/sha2-document-scaling-results.md)
for all stages, memory limits and reproducible commands, and the
[optimization report](https://github.com/bloxbean/zeroj/blob/main/docs/reviews/sha2-optimization-results.md)
for the earlier before/after comparison.

### When to use Groth16Pipeline

**Use `Groth16Pipeline` as the default application flow for BLS12-381 Groth16 with stored
keys**, particularly when proving repeatedly or hashing larger documents. It coordinates
compilation, witness generation, cached constraints and proving. You still use `Sha256` or
`Sha512` to define the complete hash relation; the pipeline controls how that circuit is run.

| Your situation | Suggested approach | Why |
|---|---|---|
| A small teaching example or an in-memory test | The direct `Groth16Keys` flow is sufficient | Fewer callbacks and no constraint-cache files to manage |
| Repeated proofs with stored keys for the same circuit | Prefer `Groth16Pipeline` | Reuse the key bundle and validated constraint cache, while generating a fresh witness and proof each time |
| Larger documents, multiple hashes or a constrained heap | Prefer `Groth16Pipeline` and measure the whole application | Its ordering helps avoid retaining the circuit graph alongside setup/proving allocations |

A **circuit graph** is the Java object structure describing the circuit's operations. A
**witness** contains the values for one proof. Both can be large, and setup/proving need their
own working arrays. Keeping an already-used graph reachable can exhaust the heap even when
the next phase would fit on its own. The 16 KiB follow-up above resolved this overlap with the
existing pipeline and the same exact circuit constraints.

**Separate preparing a circuit from proving a document:**

1. **Prepare the circuit's key bundle and constraint cache.** For local development,
   compile in a helper that returns only `Groth16Pipeline.Compiled`, then call
   `Groth16Pipeline.setup` after its graph is out of scope. Release the compiled heap
   constraints after setup. This setup API is development-only; production keys require
   the separate [ceremony and import process](https://zeroj.dev/guides/proving/trusted-setup-ceremony/).
2. **For each document, load the matching keys and create a fresh witness.** Build and
   evaluate the graph inside a helper that returns only the witness array. After that helper
   returns, pack with `FlatScalars.packConsuming`. On a valid cache hit, the pipeline then
   validates and memory-maps the constraints, and generates the randomized proof.

Keys and cached constraints can be reused for different messages and public digests **only
when the exact compiled relation is unchanged**. For these fixed-length circuits, changing
message length, SHA-256 to SHA-512, policy constants or constraint layout requires matching
artifacts. Reusing the keys does not reuse the witness or the proof. A SHA-512 document proof
observed at about 89 seconds therefore does not include a new setup for every document; see
the report for the separate setup and witness/cache timings.

**Trade-offs and integration details.** The pipeline needs compile/witness callbacks and,
for the cached path, disk space and a managed cache location. It rebuilds the witness graph
for each proof and validates the cached relation; those operations still cost time. A missing,
stale or unreadable cache can trigger compilation, increasing latency and retaining heap
constraints during witness construction. Benchmark cache misses separately from cache hits;
use `Groth16Pipeline.Progress` to observe which path ran.

The caller must respect the lifetime boundaries: avoid capturing an outer `CircuitBuilder`
or retaining a compiled relation in a service field or callback. The pipeline cannot release
objects your application still references. Close loaded keys with try-with-resources, retain
the expected exact circuit fingerprint, and follow the ceremony guide's binding-row rules
for imported keys. Memory-mapped files also use physical memory outside the Java heap, so
measure RSS as well as `-Xmx` and budget for concurrent proofs.

See the [pipeline API walkthrough](https://zeroj.dev/guides/proving/groth16/#groth16pipeline-for-very-large-circuits)
and [memory-sizing guide](https://zeroj.dev/guides/proving/performance/). The
[SHA-2 investigation example](https://github.com/bloxbean/zeroj/blob/main/assurance/sha2-optimization/java/org/zeroj/assurance/sha2/Sha2MemoryInvestigation.java)
implements the measured helper boundaries and cache-hit checks for public fixtures. The
48-byte approval demo earlier on this page keeps its simpler direct flow.

### Estimated Cardano verification cost

For initial planning, a simple SHA-256 proof-consuming transaction is **about 0.43 ADA**;
SHA-512 is **about 0.46 ADA** in the reference measurements below. These totals include the
transaction's size fee and proof-verification execution fee, with the script carried in the
transaction. They exclude the separate transaction that creates the locked output.

These are retained **local Yaci DevKit measurements from 2026-10-29**, rechecked with
optimized proofs under both heap caps with unchanged costs. They use ZeroJ's Groth16
verifier, JuLC and full-digest preimage proofs. They are not a mainnet submission or a benchmark
of this tutorial's 48-byte approval application. Use them as a starting estimate, then evaluate
your complete validator with your target network's parameters.

| Reference profile | SHA-256 | SHA-512 |
|---|---:|---:|
| Public inputs (128-bit digest limbs) | 2 | 4 |
| CPU steps | 2,191,936,964 | 2,471,295,658 |
| Memory units | 167,718 | 225,480 |
| Verification execution fee | 0.167716 ADA | 0.191191 ADA |
| Full signed spending transaction | 2,399 bytes | 2,499 bytes |
| Actual spending transaction fee | 0.433097 ADA | 0.460972 ADA |

**Why SHA-512 is only slightly more expensive here.** The chain checks a Groth16 proof;
it does not rerun the SHA circuit. In this verifier, the additional public digest limbs add
work. Bigger private messages primarily increase off-chain proving cost when the public-input
shape stays the same. More public inputs and application checks still need their own budget.

**How to update the estimate.** The captured prices were 0.0000721 lovelace per CPU step,
0.0577 lovelace per memory unit, and a size fee of `155381 + 44 × transaction_bytes` lovelace.
One ADA is 1,000,000 lovelace. The execution fee is the rounded-up sum of the two execution
charges. The recorded totals include 4,444 lovelace of builder overestimation above that
size-plus-execution calculation. A reference script changes the transaction size and introduces
a reference-script charge; its publication also costs a separate transaction. Locked minimum
ADA and collateral requirements are separate from the fee paid for a successful spend.

See the [measurement provenance and fee arithmetic](https://github.com/bloxbean/zeroj/blob/main/docs/reviews/sha2-cardano-cost-baseline.md)
and Cardano's [transaction-fee explanation](https://developers.cardano.org/docs/learn/core-concepts/fees/).
The Java command above does not submit a Cardano transaction; follow
[Verify your proof on Cardano](https://zeroj.dev/tutorials/verify-on-cardano/) to measure your integration.

## Try these changes

- Change a format byte and supply its new, correct digest. The header constraints must still reject it.
- Change the program policy and regenerate keys. A verification key identifies a particular relation.
- Run the retained independent proof checks in
  [the proof-vector directory](https://github.com/bloxbean/zeroj/blob/main/assurance/sha2-proof-vectors/README.md).
- Design the public statement for your own workflow before adding hashing: whose digest is trusted,
  what fact is revealed, who knows the witness, and what action must be bound?

Continue with [Web2 scenarios and private state](https://zeroj.dev/use-cases/sha2-web2/),
[application security](https://zeroj.dev/guides/verifying/application-security/) and
[private allowlists](https://zeroj.dev/tutorials/private-allowlist/).
