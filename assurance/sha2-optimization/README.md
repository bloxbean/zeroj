# SHA-2 optimization comparison

Optional benchmark for the optimization extension to
[ADR-0063](../../docs/adr/0063-sha256-gadget-and-sha2-assurance.md). It measures the
actual library gadgets in two source checkouts with **the same harness**, rather
than comparing a new run with unrelated historical timings. Nothing is added to
the default build, published modules or runtime dependencies.

All inputs are public ascending-byte fixtures. Groth16 setup is fresh, explicitly
opted-in **insecure single-party development setup**. This is not a ceremony,
constant-time claim, audit, production approval or post-quantum proof system.
Temporary proving keys are removed when the Java process exits normally or throws;
an externally killed process can leave a `zeroj-sha2-benchmark-keys-*` temporary
directory for the operator to remove. Verification keys and public proof vectors
are retained. Never use these keys for production.

## Prepare and run

Requirements: Java 25, the repository's Gradle wrapper and Python 3.11+. The
optional independent oracle needs pinned snarkjs 0.7.6. No Circom compilation is
part of this benchmark. Use two checkouts; do not run source edits, other Gradle
builds or other benchmark workloads concurrently with measurements.

From the candidate repository root, create an immutable baseline checkout at the
last pre-optimization commit:

```sh
git worktree add --detach ../zeroj-sha2-baseline 3f1570f33ef2f45d26abeaf6085de5a2dc7a1c5e
```

Compile the external harness against either checkout without running proofs:

```sh
python3 -B assurance/sha2-optimization/run.py prepare \
  --checkout ../zeroj-sha2-baseline \
  --output assurance/sha2-optimization/build/prepare-baseline
```

The complete primary comparison uses both **`-Xmx6g` and `-Xmx8g`**, SHA-256 and
SHA-512, and 32/128/1,024-byte messages. It launches **24 fresh JVMs sequentially**:
two checkouts × two heap caps × two algorithms × three message lengths. One proof
is a first-call warmup; the next three are measured. Baseline/candidate order
alternates between profiles to reduce order bias, though this is not a randomized
benchmark campaign.

```sh
python3 -B assurance/sha2-optimization/run.py run \
  --baseline ../zeroj-sha2-baseline --candidate . \
  --output assurance/sha2-optimization/build/comparison
```

Every output directory must be new. The runner prepares both checkouts before
starting timed processes, fixes visible CPU count at eight, and verifies source,
harness, compiled runtime and Java executable hashes before and after each case.
Each result must report the requested effective maximum heap and processor count;
an environment override that changes either control fails that case.
Unrelated documentation edits do not alter the measured source identity; changing
the harness README does, because it is retained with the experiment's protocol.

Useful explicit controls:

```sh
# Smaller optional cross-provider comparison. Requires the existing blst support.
python3 -B assurance/sha2-optimization/run.py run \
  --baseline ../zeroj-sha2-baseline --candidate . \
  --lengths 32 128 --backends blst --heaps 6g 8g \
  --output assurance/sha2-optimization/build/blst-comparison
```

`--processors`, `--samples` (3..20 measured proofs), `--algorithms`, `--lengths`,
`--heaps`, `--backends` and `--timeout` are recorded controls. The timeout defaults
to 900 seconds per Java process. It kills the entire owned process group, including
the timing wrapper and Java child. Failed/OOM/timed-out profiles retain their logs
and process status; the remaining profiles continue, and the run ultimately exits
nonzero. A source/runtime-identity change stops the matrix immediately.

## Measurements and correctness checks

Each process records:

- Java runtime, JVM flags, visible processors, actual maximum heap and load average.
- Circuit construction plus compilation time; fingerprinting is a separate timer.
- Exact constraint, wire, A/B/C term counts, resource-pressure flag and canonical
  R1CS identity. No circuit-friendly replacement for SHA is used.
- First witness time; fresh development setup time; FFT domain and complete sparse
  key-store bytes.
- One warmup and at least three measured witness/proof/strict-verification samples.
  Every proof must verify and randomized proof identities must differ.
- Rejection of every changed public digest limb and a canonical negated-A proof.
- Simultaneous heap usage sampled every 20 ms, per-pool MXBean peak usage, and GC
  counts/time. The sampler can miss brief peaks; **individual pool peaks must not
  be summed and described as a measured simultaneous peak**.
- Whole-process peak RSS from macOS `/usr/bin/time -l` or Linux `/usr/bin/time -v`,
  when available, including compile/setup/prove/verification. JVM `-Xmx` is a heap
  cap, not an RSS limit; native memory, mmap pages and JVM overhead are separate.

The public statement is the complete digest as two/four consecutive big-endian
128-bit limbs. Each case gets a newly generated key; neither keys nor fingerprints
are reused between baseline and candidate. The `proof.json`, `verification_key.json`,
`public.json`, `message.hex` and `digest.hex` files can feed a separate Cardano
integration harness. This runner does not submit transactions or measure fees.

Compilation, setup and first-witness figures are one-shot measurements in each
fresh JVM. Proving medians use the three post-warmup samples; a single warmup is
not a guarantee of complete JIT stabilization. Compare full sample distributions
and repeats before claiming a general speedup. Host activity, thermal conditions,
GC and filesystem caching remain possible sources of variation.

## Independent verification and reports

Use the pinned optional oracle installed by `assurance/sha2-circom/bootstrap.sh`:

```sh
python3 -B assurance/sha2-optimization/run.py verify \
  assurance/sha2-optimization/build/comparison \
  --snarkjs assurance/sha2-circom/node_modules/snarkjs/build/cli.cjs
```

The oracle verifies **every generated randomized proof**, every changed public
limb, and each negated-A fixture. It checks exact retained artifact hashes and
expected success/rejection output. An unrelated tool crash does not count as a
rejected proof. Independent verification is explicitly separate from measurement;
the benchmark cannot silently imply that the oracle ran.

`summary.json` records before/after values and reduction percentages for constraints,
wires, terms, domain, key bytes, compile/witness/setup/prove/verify and memory.
`summary.md` gives a compact comparison. Negative reductions mean regressions.
To rebuild the summaries without running proofs:

```sh
python3 -B assurance/sha2-optimization/run.py summarize \
  assurance/sha2-optimization/build/comparison
```

All generated output belongs under ignored `build/`. Only explicitly selected
small evidence records and public vectors should be retained for a PR. Existing
gadget/NIST/malicious-witness/Circom relation tests remain necessary: successful
proofs for honest witnesses do not establish circuit soundness.
