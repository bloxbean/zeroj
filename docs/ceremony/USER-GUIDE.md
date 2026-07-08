# zeroj-ceremony — User Guide

The standalone tool for participating in (or coordinating) a **Groth16 MPC trusted-setup ceremony**
for a ZeroJ circuit. Most readers are **contributors**: you receive a `.zkey` file, run **one
command** to mix in your randomness, send the result back, and publish a short attestation. Your
contribution makes the setup trustworthy — the ceremony is secure as long as *any one* contributor
was honest and destroyed their randomness.

## 1. Get the tool (from the GitHub release)

Download from the release page (`https://github.com/bloxbean/zeroj/releases`) — either artifact
works; they behave identically:

| artifact | needs | best for |
|---|---|---|
| `zeroj-ceremony-<version>-all.jar` | Java 25+ | anyone with a JVM |
| `zeroj-ceremony-linux-x86_64` / `zeroj-ceremony-macos-arm64` | nothing (single native binary) | contributors who don't want to install Java |

```bash
# fat jar
java -jar zeroj-ceremony-<version>-all.jar --help

# native binary
chmod +x zeroj-ceremony-macos-arm64
./zeroj-ceremony-macos-arm64 --help
```

Below, `zeroj-ceremony` stands for whichever form you use.

## 2. Contribute (what almost everyone is here to do)

You received `key_N.zkey` from the ceremony coordinator, plus the published hash to check it against.

```bash
# 1. check what you received matches what the coordinator published
shasum -a 256 key_N.zkey

# 2. contribute (seconds for small circuits; ~1 h for a 19M-constraint circuit — multi-core)
zeroj-ceremony contribute --in key_N.zkey --out key_N+1.zkey --name "your name / org"

# 3. record the Contribution Hash the tool prints — it goes in your attestation

# 4. send key_N+1.zkey back and publish your attestation (see §5)
```

**Options**

| option | required | meaning |
|---|---|---|
| `--in <file>` | yes | the `.zkey` you received |
| `--out <file>` | yes | the `.zkey` you send back |
| `--name <text>` | no | recorded in the public transcript (default: "zeroj contributor") |

Your randomness is drawn from the OS secure random source, used once, and never written anywhere.
The output is byte-compatible with snarkjs: anyone can independently check the whole ceremony with
`snarkjs zkey verify <circuit.r1cs> <pot.ptau> key_N+1.zkey` — the verifying tool is *not* ZeroJ.

## 3. Coordinator commands

### `export-r1cs` — turn a ZeroJ circuit into ceremony input

```bash
zeroj-ceremony export-r1cs \
  --circuit com.example.OwnershipProof \
  --circuit-jar my-circuits.jar \
  --out ownership.r1cs
```

| option | required | meaning |
|---|---|---|
| `--circuit <FQCN>` | yes | the `@ZKCircuit` class (or its generated `*Circuit` companion — any class with a static `build()`) |
| `--circuit-jar <jar>` | no | jar with the compiled circuit classes (omit if already on the classpath) |
| `--out <file>` | yes | output `.r1cs` |

> Native-binary note: `export-r1cs` loads circuit classes reflectively, so run it with the **fat
> jar on a JVM** (or compile the circuit into a custom native image). `contribute`/`finalize`
> work identically in both forms.

Then key genesis with snarkjs: `snarkjs groth16 setup ownership.r1cs <prepared.ptau> key_0000.zkey`.
(Phase-1 `.ptau` acquisition — Filecoin reuse or your own — is covered in
[OPTION-A-RUNBOOK.md](OPTION-A-RUNBOOK.md).)

### `finalize` — turn the completed ceremony key into a ZeroJ proving-key store

```bash
zeroj-ceremony finalize --zkey key_final.zkey --pk-store ./ownership-pk
```

| option | required | meaning |
|---|---|---|
| `--zkey <file>` | yes | the final (post-beacon, verified) ceremony `.zkey` — streaming import, multi-GB safe |
| `--pk-store <dir>` | yes | output directory (loadable with `Groth16PkStore.load(dir)`) |

Applications then prove with `Groth16PkStore.load(dir)` + 
`ZkeyPkStoreImporter.snarkjsConstraints(compiledConstraints, numPublic)` (snarkjs setup appends one
binding row per public input — the helper synthesizes them).

## 4. A complete ceremony at a glance

```bash
# coordinator
zeroj-ceremony export-r1cs --circuit com.example.MyProof --circuit-jar circuits.jar --out my.r1cs
snarkjs groth16 setup my.r1cs prepared.ptau key_0000.zkey

# contributors, in sequence — each may use EITHER tool; transcripts mix freely
zeroj-ceremony contribute --in key_0000.zkey --out key_0001.zkey --name "alice"
snarkjs zkey contribute key_0001.zkey key_0002.zkey --name="bob" -e="..."
zeroj-ceremony contribute --in key_0002.zkey --out key_0003.zkey --name "carol"

# coordinator: pre-announced public beacon, independent verification, finalize
snarkjs zkey beacon key_0003.zkey key_final.zkey <beaconHashHex> 10 -n="final beacon"
snarkjs zkey verify my.r1cs prepared.ptau key_final.zkey        # anyone can re-run this
zeroj-ceremony finalize --zkey key_final.zkey --pk-store ./pk
```

A runnable rehearsal of exactly this flow: [`rehearsal.sh`](rehearsal.sh). Full coordinator
procedure (attestations, transcript publication, checklist): [OPTION-A-RUNBOOK.md](OPTION-A-RUNBOOK.md).

## 5. Contributor attestation (publish after contributing)

Post publicly (gist / PR to the ceremony's transcript repo):

```
Ceremony: <circuit name>, contribution #N
Who: <name/org>, <date>
Received: key_N.zkey     sha256=<...>
Produced: key_N+1.zkey   sha256=<...>
Contribution Hash: <as printed by the tool>
Machine: <e.g. my laptop, air-gapped>
I confirm the entropy was generated fresh and destroyed after use.
```

## 6. Building the tool yourself (instead of downloading)

```bash
./gradlew :zeroj-ceremony:fatJar          # -> zeroj-ceremony/build/libs/zeroj-ceremony-<v>-all.jar

# optional native binary (GraalVM 25):
native-image -jar zeroj-ceremony/build/libs/zeroj-ceremony-<v>-all.jar \
  --no-fallback --enable-native-access=ALL-UNNAMED -o zeroj-ceremony
```

## 7. FAQ

- **Do I have to trust this tool?** No — verification is always done with *snarkjs* (`zkey verify`),
  which independently re-checks every contribution including ZeroJ-made ones.
- **zeroj-ceremony or snarkjs for contributing?** Identical result; ZeroJ is ~3× faster on large
  circuits (measured: ~0.9 h vs ~2.5–3 h for a 19M-constraint key) and ships as a single binary.
- **How much machine do I need?** Contributing needs modest memory (the tool streams the file);
  disk = ~2× the `.zkey` size. A 19M-constraint key is ~30 GB.
- **What must I keep secret?** Nothing after you finish — your randomness is used and discarded.
  What you must *do* is not let anyone observe the machine during the contribution, and publish
  your attestation.
