#!/usr/bin/env python3
"""Optional SHA-2 cross-check: ZeroJ byte/bit APIs, Circom, NIST and hashlib.

Run bootstrap.sh once, then `python3 assurance/sha2-circom/run.py all`.
The prepare/export/check phases can be scheduled separately. No trusted setup is used.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import struct
import subprocess
import time

BASE = pathlib.Path(__file__).resolve().parent
ROOT = BASE.parents[1]
BUILD = BASE / 'build'
FIXTURE = ROOT / 'zeroj-circuit-lib/src/test/resources/standard-vectors/nist-sha2-selected.json'
FR = 52435875175126190479447740508185965837690552500527637822603658699938581184513
PINS = {'circomlib': '35e54ea21da3e8762557234298dbb553c175ea8d',
        'sha512': 'be9f01d870c40c3fe4e0ff27c93232d205bc46f7'}
SNARK = ['node', str(BASE / 'node_modules/snarkjs/build/cli.cjs')]
CIRCOM = os.environ.get('CIRCOM', 'circom')


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + '\n')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(name, args, expected=0, marker=None):
    started = time.perf_counter()
    result = subprocess.run([str(a) for a in args], cwd=ROOT, capture_output=True,
                            text=True, timeout=600)
    output = result.stdout + '\n' + result.stderr
    log = BUILD / 'logs' / (name + '.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(output)
    row = {'name': name, 'elapsed_ms': (time.perf_counter() - started) * 1000,
           'returncode': result.returncode, 'command': [str(a) for a in args]}
    with (BUILD / 'commands.jsonl').open('a') as stream:
        stream.write(json.dumps(row) + '\n')
    if result.returncode != expected or (marker and marker not in output):
        raise RuntimeError(f'{name}: expected exit {expected} and marker {marker!r}; see {log}\n{output[-2000:]}')
    return row, output


def preflight():
    if subprocess.check_output([CIRCOM, '--version'], text=True).strip() != 'circom compiler 2.2.3':
        raise RuntimeError('Circom 2.2.3 required')
    if json.loads((BASE / 'node_modules/snarkjs/package.json').read_text())['version'] != '0.7.6':
        raise RuntimeError('snarkjs 0.7.6 required; run bootstrap.sh')
    for name, revision in PINS.items():
        folder = BUILD / 'vendor' / name
        actual = subprocess.check_output(['git', '-C', str(folder), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(folder), 'status', '--porcelain'], text=True).strip()
        if actual != revision or dirty:
            raise RuntimeError('Unpinned or modified Circom dependency: ' + name)


def prepare():
    source = json.loads(FIXTURE.read_text())
    cases = []
    for item in source['cases']:
        alg, length = item['algorithm'], item['length_bytes']
        row = dict(item, id=f'nist-{alg}-{length}', adversarial=False)
        cases.append(row)
    if len(cases) != 21:
        raise RuntimeError('Expected the pinned selection of 21 NIST cases')
    for alg in ['sha256', 'sha512']:
        for length in [32, 128]:
            message = bytes(i % 256 for i in range(length))
            cases.append({'id': f'pattern-{alg}-{length}', 'algorithm': alg,
                          'length_bytes': length, 'message_hex': message.hex(),
                          'digest_hex': hashlib.new(alg, message).hexdigest(), 'adversarial': True})
    for row in cases:
        message = bytes.fromhex(row['message_hex'])
        if len(message) != row['length_bytes'] or hashlib.new(row['algorithm'], message).hexdigest() != row['digest_hex']:
            raise RuntimeError('Independent hashlib/fixture disagreement: ' + row['id'])
    save(BUILD / 'cases.json', cases)
    print(f'Prepared {len(cases)} fixtures: 21 NIST, 4 deterministic profiles', flush=True)


def source_identities():
    paths = [FIXTURE, BUILD / 'cases.json', BASE / 'java/org/zeroj/assurance/sha2/Sha2InteropExport.java',
             ROOT / 'zeroj-circuit-lib/src/main/java/org/zeroj/circuit/lib/hash/Sha256.java',
             ROOT / 'zeroj-circuit-lib/src/main/java/org/zeroj/circuit/lib/hash/Sha512.java']
    paths += sorted((ROOT / 'zeroj-circuit-dsl/src/main/java').rglob('*.java'))
    paths += [ROOT / 'zeroj-integration-tests/src/test/java/org/zeroj/examples/dsl/common/WitnessExporter.java']
    return {str(path.relative_to(ROOT)): sha(path) for path in paths}


def export():
    prepare()
    before = source_identities()
    command('zeroj-export', [ROOT / 'gradlew', '-I', BASE / 'export.gradle',
                           ':zeroj-circuit-lib:sha2InteropExport', '--console=plain'])
    if source_identities() != before:
        raise RuntimeError('Gadget/compiler sources changed during export; rerun after edits finish')
    save(BUILD / 'zeroj-source-identities.json', before)
    print('ZeroJ byte/bit relations and witnesses exported', flush=True)


def read_witness(path):
    data = bytearray(path.read_bytes())
    if len(data) < 12 or struct.unpack_from('<4sII', data) != (b'wtns', 2, 2):
        raise ValueError('Not a two-section WTNS v2 file')
    pos, sections = 12, {}
    for _ in range(2):
        kind, length = struct.unpack_from('<IQ', data, pos)
        pos += 12
        if kind in sections or pos + length > len(data):
            raise ValueError('Malformed WTNS section')
        sections[kind] = (pos, length)
        pos += length
    if pos != len(data) or set(sections) != {1, 2}:
        raise ValueError('WTNS section layout mismatch')
    start, length = sections[1]
    n8 = struct.unpack_from('<I', data, start)[0]
    if n8 != 32 or length != n8 + 8:
        raise ValueError('Unexpected witness field width')
    prime = int.from_bytes(data[start + 4:start + 4 + n8], 'little')
    count = struct.unpack_from('<I', data, start + 4 + n8)[0]
    if prime != FR or sections[2][1] != count * n8:
        raise ValueError('Wrong field or witness count')
    offset = sections[2][0]
    values = [int.from_bytes(data[offset + i*n8:offset + (i+1)*n8], 'little') for i in range(count)]
    if any(value >= prime for value in values) or values[0] != 1:
        raise ValueError('Noncanonical witness')
    return data, offset, values


def check_witness(name, relation, witness, valid=True):
    marker = 'WITNESS IS CORRECT' if valid else 'WITNESS IS NOT CORRECT'
    command(name, SNARK + ['wtns', 'check', relation, witness], 0 if valid else 1, marker)


def reject_mutations(name, relation, witness, digest_wires, input_wire, bit_input):
    data, offset, values = read_witness(witness)
    if any(wire < 0 or wire >= len(values) for wire in digest_wires):
        raise ValueError('Digest is not mapped to retained witness wires')
    if input_wire is not None and not 0 <= input_wire < len(values):
        raise ValueError('Input is not mapped to a retained witness wire')
    mutations = [(f'digest-{i}', wire, values[wire] ^ 1) for i, wire in enumerate(digest_wires)]
    if input_wire is not None:
        mutations += [('nonboolean' if bit_input else 'byte-256', input_wire, 2 if bit_input else 256),
                      ('negative-input', input_wire, FR - 1)]
    target = witness.with_name(witness.stem + '-mutated.wtns')
    for label, wire, value in mutations:
        bad = data.copy()
        bad[offset + 32*wire:offset + 32*(wire+1)] = value.to_bytes(32, 'little')
        target.write_bytes(bad)
        check_witness(name + '-reject-' + label, relation, target, valid=False)
    target.unlink(missing_ok=True)
    return [label for label, _, _ in mutations]


def input_values(row):
    digest = bytes.fromhex(row['digest_hex'])
    return {'message': list(bytes.fromhex(row['message_hex'])),
            'digest': [str(int.from_bytes(digest[i:i+16], 'big')) for i in range(0, len(digest), 16)]}


def check():
    # A failed rerun must not leave an earlier success at the advertised output path.
    (BUILD / 'result.json').unlink(missing_ok=True)
    preflight()
    export_identities = json.loads((BUILD / 'zeroj-source-identities.json').read_text())
    if export_identities != source_identities():
        raise RuntimeError('Stale ZeroJ export; run the export phase after gadget/compiler changes')
    nist_provenance = json.loads((BUILD / 'nist-source-verification.json').read_text())
    if nist_provenance.get('fixture_sha256') != sha(FIXTURE):
        raise RuntimeError('NIST source verification is stale; run bootstrap.sh again')
    harness_paths = [BASE / 'run.py', BASE / 'export.gradle', BASE / 'bootstrap.sh',
                     BASE / 'verify-nist-source.py', BASE / 'package.json', BASE / 'package-lock.json',
                     BASE / 'circuits/sha256.circom', BASE / 'circuits/sha512.circom']
    harness_hashes = {str(path.relative_to(ROOT)): sha(path) for path in harness_paths}
    fixtures = json.loads((BUILD / 'cases.json').read_text())
    exported = json.loads((BUILD / 'zeroj/export.json').read_text())
    expected_pairs = {(row['id'], api) for row in fixtures for api in ['bytes', 'bits']}
    if {(row['id'], row['api']) for row in exported} != expected_pairs or len(exported) != len(expected_pairs):
        raise RuntimeError('Incomplete or duplicate ZeroJ export')
    by_pair = {(row['id'], row['api']): row for row in exported}
    compiled, results = {}, []
    for fixture in fixtures:
        case, alg, length = fixture['id'], fixture['algorithm'], fixture['length_bytes']
        inputs = input_values(fixture)
        profile = f'{alg}-{length}'
        folder = BUILD / 'circom' / profile
        if profile not in compiled:
            folder.mkdir(parents=True, exist_ok=True)
            source = folder / 'main.circom'
            include = pathlib.Path(os.path.relpath(BASE / 'circuits' / (alg + '.circom'), folder)).as_posix()
            source.write_text(f'pragma circom 2.2.3;\ninclude "{include}";\ncomponent main {{public [digest]}} = Sha{alg[3:]}Preimage({length});\n')
            timing, output = command(profile + '-compile', [CIRCOM, source, '--prime', 'bls12381', '--O2',
                                                            '--r1cs', '--wasm', '--sym', '--simplification_substitution', '-o', folder])
            counts = {k: int(v) for k, v in re.findall(r'(non-linear constraints|linear constraints|wires): (\d+)', output)}
            compiled[profile] = {'compile_ms': timing['elapsed_ms'], 'constraints': counts['non-linear constraints'] + counts['linear constraints'],
                                 'wires': counts['wires'], 'r1cs_sha256': sha(folder / 'main.r1cs'),
                                 'symbols_sha256': sha(folder / 'main.sym'),
                                 'substitutions_sha256': sha(folder / 'main_substitutions.json')}
        save(folder / (case + '-input.json'), inputs)
        witness = folder / (case + '.wtns')
        wasm = folder / 'main_js/main.wasm'
        timing, _ = command(case + '-circom-calculate', SNARK + ['wtns', 'calculate', wasm, folder / (case + '-input.json'), witness])
        check_witness(case + '-circom-check', folder / 'main.r1cs', witness)
        symbols, signal_ids, signal_wires = {}, {}, {0: 0}
        for line in (folder / 'main.sym').read_text().splitlines():
            signal, wire, _, name = line.split(',', 3)
            symbols[name] = int(wire)
            signal_ids[name] = int(signal)
            signal_wires[int(signal)] = int(wire)
        digest_wires = [symbols[f'main.digest[{i}]'] for i in range(len(inputs['digest']))]
        _, _, actual = read_witness(witness)
        substitutions = json.loads((folder / 'main_substitutions.json').read_text())
        resolved, resolving = {0: 1}, set()

        def signal_value(signal):
            # O2 may remove both a byte and some of its decomposition bits. Apply
            # the compiler's exact affine substitutions, including nested ones.
            # Neither a -1 symbol nor an absent mapping may index the witness.
            if signal in resolved:
                return resolved[signal]
            if signal in resolving or signal not in signal_wires:
                raise RuntimeError('Invalid Circom substitution graph: ' + case)
            wire = signal_wires[signal]
            if wire >= 0:
                if wire >= len(actual):
                    raise RuntimeError('Circom wire outside witness: ' + case)
                value = actual[wire]
            else:
                if str(signal) not in substitutions:
                    raise RuntimeError('Missing Circom substitution: ' + case)
                resolving.add(signal)
                value = sum(int(coefficient) * signal_value(int(term))
                            for term, coefficient in substitutions[str(signal)].items()
                            if int(coefficient)) % FR
                resolving.remove(signal)
            resolved[signal] = value
            return value

        if any(wire < 0 or wire >= len(actual) for wire in digest_wires):
            raise RuntimeError('Missing public digest wire: ' + case)
        if [actual[wire] for wire in digest_wires] != [int(x) for x in inputs['digest']]:
            raise RuntimeError('Circom digest packing mismatch: ' + case)
        for i, expected in enumerate(inputs['message']):
            observed = signal_value(signal_ids[f'main.message[{i}]'])
            bits = [signal_value(signal_ids[f'main.bytes[{i}].out[{j}]']) for j in range(8)]
            if any(bit not in [0, 1] for bit in bits):
                raise RuntimeError('Non-Boolean Circom input decomposition: ' + case)
            if observed != expected or sum(bit << j for j, bit in enumerate(bits)) != expected:
                raise RuntimeError('Circom input witness mismatch: ' + case)
        result = {'id': case, 'algorithm': alg, 'message_bytes': length, 'digest_hex': fixture['digest_hex'],
                  'circom': dict(compiled[profile], witness_process_ms=timing['elapsed_ms'],
                                 witness_sha256=sha(witness), r1cs_check=True), 'zeroj': {}}
        if fixture['adversarial']:
            input_signal = 'main.message[0]'
            input_wire = symbols[input_signal]
            input_is_bit = input_wire < 0
            if input_is_bit:
                retained_bits = [(f'main.bytes[0].out[{j}]', symbols[f'main.bytes[0].out[{j}]']) for j in range(8)
                                 if symbols[f'main.bytes[0].out[{j}]'] >= 0]
                if not retained_bits:
                    raise RuntimeError('No retained input bit to mutate: ' + case)
                input_signal, input_wire = retained_bits[0]
            result['circom']['mutated_input_kind'] = 'retained-decomposition-bit' if input_is_bit else 'byte'
            result['circom']['mutated_input_signal'] = input_signal
            result['circom']['mutated_input_wire'] = input_wire
            result['circom']['rejected_compiled_mutations'] = reject_mutations(case + '-circom', folder / 'main.r1cs', witness,
                                                                             digest_wires, input_wire, input_is_bit)
            generator_rejects = []
            for label, value in [('byte-256', 256), ('negative-byte', -1)]:
                invalid = dict(inputs, message=inputs['message'].copy())
                invalid['message'][0] = value
                bad_input = folder / (case + '-invalid-input.json')
                save(bad_input, invalid)
                command(case + '-circom-generator-' + label, SNARK + ['wtns', 'calculate', wasm, bad_input, folder / 'invalid.wtns'],
                        1, 'Assert Failed')
                generator_rejects.append(label)
            result['circom']['rejected_generator_inputs'] = generator_rejects
        for api in ['bytes', 'bits']:
            row = by_pair[(case, api)]
            relation = BUILD / 'zeroj' / row['r1cs']
            zeroj_witness = BUILD / 'zeroj' / row['witness']
            if sha(relation) != row['r1cs_sha256']:
                raise RuntimeError('Changed ZeroJ relation: ' + case)
            _, _, values = read_witness(zeroj_witness)
            if values[1:1+len(inputs['digest'])] != [int(x) for x in inputs['digest']]:
                raise RuntimeError('ZeroJ digest packing mismatch: ' + case)
            message = inputs['message'] if api == 'bytes' else [(b >> bit) & 1 for b in inputs['message'] for bit in range(7, -1, -1)]
            start = len(inputs['digest']) + 1
            if values[start:start+len(message)] != message:
                raise RuntimeError('ZeroJ input witness mismatch: ' + case)
            check_witness(case + '-zeroj-' + api + '-check', relation, zeroj_witness)
            checked = dict(row, witness_sha256=sha(zeroj_witness), r1cs_check=True)
            if fixture['adversarial']:
                checked['rejected_compiled_mutations'] = reject_mutations(case + '-zeroj-' + api, relation, zeroj_witness,
                                                                         list(range(1, len(inputs['digest'])+1)), row['first_private_wire'], api == 'bits')
            result['zeroj'][api] = checked
        results.append(result)
        print(f'PASS {case}: Circom + ZeroJ byte/bit R1CS', flush=True)
    if source_identities() != export_identities:
        raise RuntimeError('Gadget/compiler/fixture source changed during checks; rerun export and check')
    if harness_hashes != {str(path.relative_to(ROOT)): sha(path) for path in harness_paths}:
        raise RuntimeError('Assurance harness changed during checks; rerun check')
    report = {'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'curve': 'BLS12-381', 'circom': '2.2.3', 'snarkjs': '0.7.6', 'dependencies': PINS,
              'node': subprocess.check_output(['node', '--version'], text=True).strip(),
              'java': json.loads((BUILD / 'zeroj/environment.json').read_text()),
              'platform': platform.platform(), 'fixture_sha256': sha(FIXTURE),
              'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'nist_source': nist_provenance, 'harness_sha256': harness_hashes,
              'source_sha256': export_identities, 'cases': results,
              'scope': 'Independent compiled-relation checks, no proof/setup or production security claim. Timings are one-shot shared-host diagnostics; Circom timings include process/file overhead.'}
    report['counts'] = {'fixtures': len(results), 'positive_r1cs_checks': len(results)*3,
                        'compiled_witness_rejections': sum(len(r['circom'].get('rejected_compiled_mutations', [])) +
                                                          sum(len(z.get('rejected_compiled_mutations', [])) for z in r['zeroj'].values()) for r in results),
                        'circom_generator_rejections': sum(len(r['circom'].get('rejected_generator_inputs', [])) for r in results)}
    save(BUILD / 'result.json', report)
    print(json.dumps(report['counts']), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'export', 'check', 'all'])
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    if args.phase == 'prepare': prepare()
    if args.phase in ['export', 'all']: export()
    if args.phase in ['check', 'all']: check()


if __name__ == '__main__':
    main()
