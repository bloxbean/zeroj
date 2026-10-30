#!/usr/bin/env python3
"""Summarize exported JFR allocation samples. Weighted volume, never peak/retained heap.
Usage: jfr print --json --stack-depth 64 --events jdk.ObjectAllocationSample recording.jfr > allocations.json
       python3 bindings/wasm/summarize-circuit-jfr.py allocations.json
"""
import json, sys
from collections import Counter
with open(sys.argv[1]) as source:
    events = json.load(source)['recording']['events']
volume, counts, imports, classes = Counter(), Counter(), Counter(), Counter()
for event in events:
    if event['type'] != 'jdk.ObjectAllocationSample':
        continue
    value = event['values']
    frames = (value.get('stackTrace') or {}).get('frames', [])
    names = ' '.join(f["method"]["type"]["name"] + '.' + f['method']['name'] for f in frames)
    weight = value['weight']
    category = 'other_or_startup'
    if 'ZkeyImporterBLS381.' in names:
        category = 'key_import'
        group = 'other_import'
        if 'G1Point.isInSubgroup' in names:
            group = 'G1_subgroup'
        elif 'G2Point.isInSubgroup' in names:
            group = 'G2_subgroup'
        imports[group] += weight
    elif 'Groth16ProverBLS381.' in names:
        category = 'proving'
    elif 'WitnessCalculator.' in names:
        category = 'witness'
    elif 'Groth16VerifierAdapter.verify' in names:
        category = 'verification_including_self_check'
    elif 'CompiledGraph.' in names or 'GraphCodec.' in names:
        category = 'compile_or_graph'
    volume[category] += weight
    counts[category] += 1
    classes[value['objectClass']['name']] += weight
print(json.dumps({'meaning': 'sample-weight estimates of cumulative JVM allocation, not retained bytes, peak heap, or Wasm GC',
    'samples': sum(counts.values()), 'weightedBytes': dict(volume), 'counts': dict(counts),
    'importWeightedBytes': dict(imports), 'topClassesWeightedBytes': dict(classes.most_common(8))}, indent=2))
