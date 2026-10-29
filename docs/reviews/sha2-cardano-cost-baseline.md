# SHA-2 Cardano cost baseline for the docsite

This note supports the planning estimates in the SHA-256 approval tutorial. It
imports two retained **2026-10-29 local Yaci DevKit** research results; it does not
claim a new ledger run of issue #111 or of the tutorial's approval circuit.

The [optimization report](sha2-optimization-results.md#fresh-cardano-regression)
adds four fresh local spends with optimized proofs at 6/8 GiB heap caps. Costs
matched the table below. This note preserves the original baseline provenance.

## Provenance and scope

The adjacent [JSON extract](sha2-cardano-cost-baseline.json) preserves the original
ZeroJ SHA-256/32-byte and SHA-512/32-byte result records, source-file SHA-256 hashes,
verifier/toolchain identities and protocol comparison from the separate
`sha2-groth16-cardano-poc` research workspace. Its full signed transactions, proof
artifacts and submission harness are not bundled in this extract. The local
transaction IDs are not mainnet explorer links.

The research used ZeroJ source `c98f45a433fd198017995d8e2dbdbc82d25af422`, JuLC
`0.1.0-pre20-c3a31c2-SNAPSHOT`, and Cardano Client Lib `0.8.0-pre7`. These are earlier
research artifacts, distinct from the new library gadget validation and the
48-byte tutorial. The verifier uses BLS12-381 Groth16 with two/four public 128-bit
limbs retaining the complete digest. SHA computation occurs off chain. The script
pins the verification key, and the consumed datum supplies the expected digest.

The records report confirmed local spends, agreement between Java/backend/Haskell
execution budgets, eight rejected VM negative cases, and rejection of signed
invalid-proof and wrong-digest transactions. They use development setup and a
cryptographic preimage verifier without application authorization or replay binding.
No production, public-network or post-quantum security claim follows.

## Measured spending costs

| Metric | SHA-256 | SHA-512 |
|---|---:|---:|
| Public inputs | 2 | 4 |
| CPU steps | 2,191,936,964 | 2,471,295,658 |
| Memory units | 167,718 | 225,480 |
| Compressed proof bytes (before transaction framing) | 192 | 192 |
| Applied script FLAT bytes | 1,727 | 1,827 |
| Script CBOR bytes | 1,733 | 1,833 |
| Signed spending transaction bytes | 2,399 | 2,499 |
| Execution fee, lovelace | 167,716 | 191,191 |
| Size fee, lovelace | 260,937 | 265,337 |
| Calculated minimum, lovelace | 428,653 | 456,528 |
| Actual paid fee, lovelace | 433,097 | 460,972 |

The script is carried in the transaction; these are not reference-script prices.
The expected digest is already in the consumed datum. Each signed spend has one
payment-key witness. Creating the locked output is a separate transaction. Locked
ADA, minimum-output ADA and collateral requirements are not added to the successful
spending fee. Extra inputs, outputs, signatures, public inputs and application
logic change the estimate.

The retained PV11 snapshot has a 10-billion-step, 16.5-million-memory-unit and
16,384-byte per-transaction cap. The two cases consume about 21.92%/24.71% of that
CPU cap. Its prices are 721/10,000,000 lovelace per step and 577/10,000 lovelace per
memory unit; the size fee is 44 lovelace per byte plus 155,381 lovelace.
The retained comparison reports equality with the captured mainnet epoch 664
parameters and all 350 Plutus V3 cost-model entries. This is a comparison of saved
snapshots, not an assertion that parameters stay unchanged.

## Recheck the arithmetic

From the ZeroJ repository root, this reads only the retained extract:

```sh
python3 - <<'PY'
import json
from fractions import Fraction
from math import ceil
from pathlib import Path

data = json.loads(Path('docs/reviews/sha2-cardano-cost-baseline.json').read_text())
for result in data['results']:
    execution = ceil(result['cpu_steps'] * Fraction(721, 10_000_000)
                     + result['memory_units'] * Fraction(577, 10_000))
    size = 155381 + 44 * result['transaction_bytes']
    assert execution == result['execution_fee_lovelace']
    assert size == result['linear_size_fee_lovelace']
    assert size + execution == result['calculated_min_fee_lovelace']
    assert result['fee_lovelace'] - size - execution == 4444
    print(result['case'], result['fee_lovelace'] / 1_000_000, 'ADA')
PY
```

The recorded builder overestimation is 4,444 lovelace: the research traced this to
one extra estimated 101-byte payment witness at 44 lovelace/byte. That witness is
absent from the final signed transaction. Therefore the docsite reports the actual
paid fee separately from the calculated minimum.

This command verifies arithmetic, not ledger acceptance. For a new integration,
follow the docsite's Cardano verification tutorial, evaluate the complete validator
against current target-network parameters, and record its signed transaction and
declared execution budget. Reference scripts need their own fee calculation and
publication transaction. Cardano's
[fee documentation](https://developers.cardano.org/docs/learn/core-concepts/fees/)
explains size, execution and reference-script charges.
