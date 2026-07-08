# Groth16 MPC Ceremony Runbook — Option A (snarkjs)

The standard-tooling ceremony for a ZeroJ Groth16 circuit ([ADR-0031](../adr/0031-groth16-mpc-trusted-setup-ceremony.md)).
Every artifact is verifiable with stock `snarkjs` — nothing in the trust chain is ZeroJ-authored.
Roles: one **coordinator** (runs the heavy one-time steps, sequences contributors, publishes the
transcript) and **N contributors** (each runs one command on their own machine and destroys their
entropy). Soundness requires only that **one** contributor was honest.

> **Prerequisite — circuit freeze.** The ceremony binds to the exact R1CS. Do not start the
> production ceremony until the circuit is final (gadget audit done, replay-binding public inputs
> added — ADR-0030). Machinery can be rehearsed any time on a throwaway circuit.

---

## Phase 0 — Coordinator: one-time universal powers (`.ptau`)

Needed once per (curve, max-size) — **not** per circuit. Reused for every future ceremony ≤ 2^POWER.

**Primary source — Filecoin's attested BLS12-381 ceremony (2²⁷):** see ADR-0031 M3. Acquire,
convert, then — non-negotiable regardless of source:

```bash
snarkjs powersoftau verify pot_imported.ptau            # pairing-structure check (hours at 2^25+)
snarkjs powersoftau truncate pot_imported.ptau          # cut 2^27 -> smaller powers incl. 2^25
snarkjs powersoftau prepare phase2 pot25.ptau pot25_final.ptau   # HEAVY: ~60-105h at 2^25, one-time
```

**Fallback — own phase 1** (measured costs in ADR-0031 M3; contributions ~2.5-3 h each at 2²⁵):

```bash
snarkjs powersoftau new bls12-381 25 pot_0000.ptau
# each phase-1 contributor, in sequence:
snarkjs powersoftau contribute pot_<i>.ptau pot_<i+1>.ptau --name="<who>" -v
# close with a public beacon (see Beacon below), then:
snarkjs powersoftau beacon pot_<last>.ptau pot_beacon.ptau <beaconHash> 10 -n="final beacon"
snarkjs powersoftau prepare phase2 pot_beacon.ptau pot25_final.ptau
```

Publish `pot25_final.ptau` + its `snarkjs powersoftau verify` output. Cache it — it serves all
future circuits.

## Phase 1 — Coordinator: circuit key genesis

```bash
# from the frozen circuit (the @ZKCircuit class, compiled into your circuits jar):
java -cp zeroj-ceremony.jar:your-circuits.jar com.bloxbean.cardano.zeroj.ceremony.CeremonyCli \
     export-r1cs --circuit com.example.OwnershipProof --out ownership.r1cs

snarkjs groth16 setup ownership.r1cs pot25_final.ptau key_0000.zkey
shasum -a 256 ownership.r1cs key_0000.zkey    # publish these hashes before contributions start
```

## Phase 2 — Contributors (sequenced by the coordinator)

Each contributor, on their own machine (for the 19M ownership circuit budget ~hours in Node — or
use the ZeroJ-native contributor, Option B/M5, for ~minutes-to-an-hour):

```bash
shasum -a 256 key_<i>.zkey                     # must match the coordinator's published hash
snarkjs zkey contribute key_<i>.zkey key_<i+1>.zkey --name="<who>" -v
# type a long random string when prompted; then:
shasum -a 256 key_<i+1>.zkey                   # send file + hash back; PUBLISH an attestation
```

Contributor attestation (publish publicly — gist/PR to the transcript repo): who, when, machine,
the input/output zkey hashes, the contribution hash snarkjs printed, and a statement that the
entropy was destroyed.

## Phase 3 — Coordinator: beacon + verification + finalize

```bash
# Beacon: pre-announce the source BEFORE the last contribution lands, e.g.
#   "the hash of Bitcoin block N" or "drand round R" for a specific future N/R.
snarkjs zkey beacon key_<last>.zkey key_final.zkey <beaconHashHex> 10 -n="final beacon"

# The independent check anyone can re-run:
snarkjs zkey verify ownership.r1cs pot25_final.ptau key_final.zkey

snarkjs zkey export verificationkey key_final.zkey verification_key.json

# Into ZeroJ (streaming; handles multi-GB keys):
java -cp zeroj-ceremony.jar com.bloxbean.cardano.zeroj.ceremony.CeremonyCli \
     finalize --zkey key_final.zkey --pk-store ./ownership-pk
```

Proving afterwards: `Groth16PkStore.load(dir)` + `ZkeyPkStoreImporter.snarkjsConstraints(compiled, numPublic)`
(snarkjs appends one public-input binding row per public signal — the helper synthesizes them; it is
asserted against real zkeys in `ZkeyPkStoreImporterTest`). The VK for the on-chain validator comes
from the same store (`loaded.gammaG2()`, `loaded.ic()`).

## Transcript publication (what makes it trustworthy)

Publish in a public repo: the `.r1cs` + its hash and the exact circuit source/commit it was built
from; every intermediate zkey hash; every contributor attestation; the beacon pre-announcement and
value; the `zkey verify` output. **Anyone** can then re-run
`snarkjs zkey verify ownership.r1cs pot25_final.ptau key_final.zkey` and rebuild `ownership.r1cs`
from source to confirm the key binds to the claimed circuit.

## Checklist

- [ ] circuit frozen (audit + binding publics) and tagged in git
- [ ] prepared `.ptau` acquired + `powersoftau verify` output published
- [ ] `ownership.r1cs` + `key_0000.zkey` hashes published before contributions
- [ ] ≥ 3 contributors from independent orgs, attestations published
- [ ] beacon source pre-announced, applied, published
- [ ] `zkey verify` green; final key + VK hashes published
- [ ] `finalize` run; a test proof generated and verified off-chain and on-chain
