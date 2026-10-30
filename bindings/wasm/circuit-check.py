#!/usr/bin/env python3
"""Focused ADR-0064 validation. Generated artifacts stay ignored; never publishes."""
from pathlib import Path
import os, subprocess
ROOT=Path(__file__).resolve().parents[2];JS=ROOT/'bindings/js'
home=os.environ.get('GRAALVM_HOME')
if not home: raise SystemExit('Set GRAALVM_HOME to the pinned toolchain')
env={**os.environ,'JAVA_HOME':home}
def run(args,cwd=ROOT):
    print('Running:', ' '.join(args),flush=True)
    subprocess.run(args,cwd=cwd,env=env,check=True)
run(['npm','ci','--ignore-scripts'],JS)
run(['npm','run','build'],JS)
run(['npx','tsc','-p','examples/circuit'],JS)
run(['node','scripts/circuit-recipes.mjs'],JS)
run(['./gradlew','-p','bindings/wasm',':adapter-circuit:test',':adapter-circuit:fixtures',':adapter-common:test',':adapter-hash:test','--max-workers=2','--console=plain'])
run(['python3','bindings/wasm/build.py','circuit'])
run(['python3','bindings/wasm/package.py','circuit'])
run(['node','scripts/circuit-setup.mjs'],JS)
run(['npx','tsc','--noEmit','--target','ES2022','--module','NodeNext','--strict','--skipLibCheck','tests/circuit-types.ts'],JS)
run(['node','packages/circuit-lint/src/index.mjs','examples/circuit/symbolic-examples.ts','examples/circuit/operation-examples.ts'],JS)
run(['node','--experimental-wasm-exnref','--test','tests/circuit-frontend.test.mjs','tests/circuit.test.mjs','tests/circuit-key.test.mjs'],JS)
run(['node','tests/circuit-browser.mjs'],JS)
run(['./gradlew','-p','bindings/wasm',':adapter-circuit:circuitInterop','--max-workers=2','--console=plain'])
run(['node','--experimental-wasm-exnref','scripts/circuit-interop.mjs'],JS)
run(['node','scripts/circuit-pack-test.mjs'],JS)
