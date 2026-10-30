#!/usr/bin/env python3
"""Opt-in full experimental binding check. No publication or default-build integration."""
from pathlib import Path
import os,subprocess
ROOT=Path(__file__).resolve().parents[2]
JS=ROOT/'bindings/js'
home=os.environ.get('GRAALVM_HOME')
if not home: raise SystemExit('Set GRAALVM_HOME to the pinned toolchain')
env={**os.environ,'JAVA_HOME':home}
def run(command,cwd=ROOT):
 print('Running:', ' '.join(command),flush=True)
 subprocess.run(command,cwd=cwd,env=env,check=True)
run(['npm','ci','--ignore-scripts'],JS)
run(['npm','run','build'],JS)
run(['npx','tsc','-p','examples/circuit'],JS)
run(['node','scripts/circuit-recipes.mjs'],JS)
profiles=['hash','crypto','verifier','prover','confidential','all','probe','unprotected','circuit']
run(['python3','bindings/wasm/build.py',*profiles])
run(['python3','bindings/wasm/package.py',*profiles])
run(['python3','bindings/wasm/tutorial-fixture.py'])
run(['./gradlew','-p','bindings/wasm',':bundles:confidentialFixtures',':adapter-common:test',':adapter-hash:test',':adapter-circuit:test',':adapter-circuit:fixtures','--max-workers=2','--console=plain'])
run(['node','scripts/circuit-setup.mjs'],JS)
run(['npm','run','build'],JS)
run(['npm','test'],JS)
run(['node','tests/browser.mjs'],JS)
run(['node','tests/circuit-browser.mjs'],JS)
run(['./gradlew','-p','bindings/wasm',':adapter-circuit:circuitInterop','--max-workers=2','--console=plain'])
run(['node','--experimental-wasm-exnref','scripts/circuit-interop.mjs'],JS)
run(['node','scripts/pack-test.mjs'],JS)
run(['node','scripts/circuit-pack-test.mjs'],JS)
