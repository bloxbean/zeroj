#!/usr/bin/env bash
#
# ADR-0031 M6 — ceremony REHEARSAL: the full mixed-tool Groth16 phase-2 ceremony on a small
# fixture circuit, end to end, exactly as the production runbook prescribes (OPTION-A-RUNBOOK.md)
# but at rehearsal scale. Exercises: export-r1cs -> snarkjs setup -> a ZeroJ-native contribution ->
# a snarkjs contribution -> a second ZeroJ contribution -> BEACON -> snarkjs zkey verify (the
# independent transcript check) -> finalize into a ZeroJ proving-key store.
#
# Usage:  docs/ceremony/rehearsal.sh [workdir]
# Needs:  snarkjs on PATH (or SNARKJS=...), a built zeroj repo (gradle classes), java 25.
set -euo pipefail

WORK="${1:-$(mktemp -d)}"
SNARKJS="${SNARKJS:-$(command -v snarkjs || echo "$HOME/.npm-global/bin/snarkjs")}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BC_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/org.bouncycastle -name 'bcprov-jdk18on-1.83.jar' | head -1)
PICO_JAR=$(find ~/.gradle/caches/modules-2/files-2.1/info.picocli -name 'picocli-4.7.6.jar' | head -1)
CP="$ROOT/zeroj-ceremony/build/classes/java/main:$ROOT/zeroj-ceremony/build/classes/java/test"
CP="$CP:$ROOT/zeroj-crypto/build/classes/java/main:$ROOT/zeroj-circuit-dsl/build/classes/java/main"
CP="$CP:$ROOT/zeroj-api/build/classes/java/main:$ROOT/zeroj-bls12381/build/classes/java/main:$BC_JAR:$PICO_JAR"
CLI="java -cp $CP com.bloxbean.cardano.zeroj.ceremony.CeremonyCli"

echo ">> Rehearsal workdir: $WORK"
cd "$WORK"

echo ">> [coordinator] export the circuit"
$CLI export-r1cs --circuit com.bloxbean.cardano.zeroj.ceremony.MulFixtureCircuit --out mul.r1cs

echo ">> [coordinator] phase 1 (rehearsal-scale ptau) + key genesis"
"$SNARKJS" powersoftau new bls12-381 8 pot0.ptau
"$SNARKJS" powersoftau contribute pot0.ptau pot1.ptau --name="rehearsal-p1" -e="rehearsal phase1 entropy"
"$SNARKJS" powersoftau prepare phase2 pot1.ptau pot.ptau
"$SNARKJS" groth16 setup mul.r1cs pot.ptau key_0000.zkey
shasum -a 256 mul.r1cs key_0000.zkey | tee transcript.txt

echo ">> [contributor 1 — ZeroJ native]"
$CLI contribute --in key_0000.zkey --out key_0001.zkey --name "alice (zeroj)" | tee -a transcript.txt

echo ">> [contributor 2 — snarkjs]"
"$SNARKJS" zkey contribute key_0001.zkey key_0002.zkey --name="bob (snarkjs)" -e="bob entropy" | tee -a transcript.txt

echo ">> [contributor 3 — ZeroJ native]"
$CLI contribute --in key_0002.zkey --out key_0003.zkey --name "carol (zeroj)" | tee -a transcript.txt

echo ">> [coordinator] beacon (pre-announced public randomness) + independent verification"
"$SNARKJS" zkey beacon key_0003.zkey key_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="rehearsal beacon"
"$SNARKJS" zkey verify mul.r1cs pot.ptau key_final.zkey | tee -a transcript.txt

echo ">> [coordinator] finalize into a ZeroJ proving-key store + export VK"
"$SNARKJS" zkey export verificationkey key_final.zkey verification_key.json
$CLI finalize --zkey key_final.zkey --pk-store ./pk-store

echo ""
echo ">> REHEARSAL COMPLETE. Artifacts in $WORK (transcript.txt = the publishable record)."
