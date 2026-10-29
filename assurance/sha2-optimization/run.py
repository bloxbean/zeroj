#!/usr/bin/env python3
"""Optional sequential SHA-2 before/after benchmark; never part of the product build."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import signal
import statistics
import subprocess
import time

HERE = pathlib.Path(__file__).resolve().parent


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(checkout, *args):
    return subprocess.check_output(['git', '-C', str(checkout), *args], text=True).strip()


def identities(checkout):
    paths = set(checkout.glob('zeroj-*/src/main/**/*.java'))
    paths.update(checkout.glob('zeroj-*/build.gradle'))
    paths.update(checkout / name for name in ['build.gradle', 'settings.gradle', 'gradle.properties'])
    return {'revision': git(checkout, 'rev-parse', 'HEAD'),
            'sourceSha256': {str(p.relative_to(checkout)): digest(p) for p in sorted(paths)},
            'harnessSha256': {str(p.relative_to(HERE)): digest(p) for p in sorted(HERE.rglob('*'))
                             if p.is_file() and 'build' not in p.relative_to(HERE).parts
                             and '__pycache__' not in p.parts and p.suffix in ('.java', '.py', '.gradle', '.md')}}


def runtime_identities(launch):
    results = {}
    for entry in launch['classpath'].split(os.pathsep):
        path = pathlib.Path(entry)
        if path.is_file():
            results[str(path)] = digest(path)
        elif path.is_dir():
            for child in sorted(path.rglob('*')):
                if child.is_file():
                    results[str(child)] = digest(child)
        elif path.suffix == '.jar':
            raise RuntimeError('Missing prepared runtime JAR: ' + str(path))
    results[launch['java']] = digest(pathlib.Path(launch['java']))
    return results


def prepare(checkout, output):
    checkout = checkout.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = identities(checkout)
    manifest = output / 'launch.json'
    command = [str(checkout / 'gradlew'), '-I', str(HERE / 'benchmark.gradle'),
               f'-Psha2Harness={HERE}', f'-Psha2LaunchManifest={manifest}',
               ':zeroj-crypto-blst:sha2OptimizationPrepare', '--max-workers=2', '--console=plain']
    with (output / 'prepare.log').open('w') as log:
        process = subprocess.run(command, cwd=checkout, stdout=log, stderr=subprocess.STDOUT)
    after = identities(checkout)
    save(output / 'prepare.json', {'checkout': str(checkout), 'command': command,
                                  'exitCode': process.returncode, 'identities': before,
                                  'workingTreeStatus': git(checkout, 'status', '--short'),
                                  'sourceUnchanged': before == after})
    if process.returncode or before != after:
        raise RuntimeError(f'Preparation failed or source changed: {output / "prepare.log"}')
    launch = json.loads(manifest.read_text())
    launch['checkout'] = str(checkout)
    launch['identities'] = before
    launch['runtimeSha256'] = runtime_identities(launch)
    save(manifest, launch)
    return launch


def assert_unchanged(launch):
    if identities(pathlib.Path(launch['checkout'])) != launch['identities']:
        raise RuntimeError('Source or harness changed after preparation; discard this matrix and rerun')
    if runtime_identities(launch) != launch['runtimeSha256']:
        raise RuntimeError('Compiled runtime changed after preparation; discard this matrix and rerun')


def run_case(launch, folder, algorithm, length, heap, backend, args):
    folder.mkdir(parents=True, exist_ok=False)
    command = [launch['java'], f'-Xmx{heap}', f'-XX:ActiveProcessorCount={args.processors}',
               '--enable-native-access=ALL-UNNAMED', '-Dzeroj.allowInsecureTrustedSetup=true',
               '-cp', launch['classpath'], launch['main'], algorithm, str(length), str(args.samples),
               str(folder / 'artifacts'), backend]
    timed_command = command
    time_tool = pathlib.Path('/usr/bin/time')
    if time_tool.exists() and platform.system() in ('Darwin', 'Linux'):
        timed_command = [str(time_tool), '-l' if platform.system() == 'Darwin' else '-v', *command]
    start = time.monotonic()
    status = {'command': timed_command, 'algorithm': algorithm, 'messageBytes': length,
              'heap': heap, 'backend': backend, 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'initialLoadAverage': os.getloadavg() if hasattr(os, 'getloadavg') else None}
    with (folder / 'stdout.log').open('w') as out, (folder / 'stderr.log').open('w') as err:
        try:
            process = subprocess.Popen(timed_command, cwd=launch['checkout'], stdout=out, stderr=err,
                                       start_new_session=(os.name == 'posix'))
            try:
                status['exitCode'] = process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                # Kill the whole owned group, including the Java child of /usr/bin/time.
                # Killing only the timing wrapper would contaminate later profiles.
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
                status.update(exitCode=process.returncode, failure='process timeout')
        except OSError as failure:
            status.update(exitCode=None, failure=str(failure))
    status['wallSecondsIncludingStartupAndChecks'] = time.monotonic() - start
    stderr = (folder / 'stderr.log').read_text()
    if platform.system() == 'Darwin':
        match = re.search(r'^\s*(\d+)\s+maximum resident set size\s*$', stderr, re.M)
        status['peakRssBytes'] = int(match[1]) if match else None
    elif platform.system() == 'Linux':
        match = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', stderr)
        status['peakRssBytes'] = int(match[1]) * 1024 if match else None
    else:
        status['peakRssBytes'] = None
    result = folder / 'artifacts/result.json'
    status['passed'] = False
    if status.get('exitCode') == 0 and result.exists():
        try:
            measured = json.loads(result.read_text())
            expected_heap = int(heap[:-1]) * (1 << 30)
            status['effectiveControlsMatch'] = (measured['maxHeapBytes'] == expected_heap
                                                and measured['processors'] == args.processors)
            status['passed'] = measured['status'] == 'passed' and status['effectiveControlsMatch']
            if not status['effectiveControlsMatch']:
                status['failure'] = 'Effective JVM heap/processor controls differ from the requested values'
        except (ValueError, KeyError, TypeError) as failure:
            status['failure'] = 'Invalid benchmark result: ' + str(failure)
    status['artifactSha256'] = {str(p.relative_to(folder)): digest(p) for p in sorted((folder / 'artifacts').glob('*'))
                                if p.is_file()}
    save(folder / 'process.json', status)
    print(f'{folder.name}: {algorithm}/{length}/{heap}/{backend}: {"PASS" if status["passed"] else "FAIL"}', flush=True)
    return status['passed']


def run_matrix(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    launches = {label: prepare(path, output / ('prepare-' + label))
                for label, path in [('baseline', args.baseline), ('candidate', args.candidate)]}
    save(output / 'matrix.json', {'baseline': str(args.baseline.resolve()), 'candidate': str(args.candidate.resolve()),
                                 'heaps': args.heaps, 'algorithms': args.algorithms, 'lengths': args.lengths,
                                 'samples': args.samples, 'processors': args.processors, 'backends': args.backends,
                                 'order': 'Sequential fresh JVMs; baseline/candidate order alternates each profile',
                                 'platform': platform.platform()})
    passed = True
    count = 0
    for heap in args.heaps:
        for backend in args.backends:
            for algorithm in args.algorithms:
                for length in args.lengths:
                    labels = ['baseline', 'candidate'] if count % 2 == 0 else ['candidate', 'baseline']
                    name = f'{algorithm.lower().replace("-", "")}-{length}'
                    for label in labels:
                        assert_unchanged(launches[label])
                        passed = run_case(launches[label], output / heap / backend / name / label,
                                          algorithm, length, heap, backend, args) and passed
                        assert_unchanged(launches[label])
                    count += 1
    summarize(output)
    if not passed:
        raise RuntimeError('One or more benchmark processes failed; see process.json and stderr.log')


def summarize(output):
    comparisons = []
    for baseline in sorted(output.glob('*/*/*/baseline/process.json')):
        pair = baseline.parent.parent
        base_process = json.loads(baseline.read_text())
        candidate = pair / 'candidate/process.json'
        if not candidate.exists():
            comparisons.append({'profile': str(pair.relative_to(output)), 'status': 'incomplete'})
            continue
        candidate_process = json.loads(candidate.read_text())
        row = {'profile': str(pair.relative_to(output)), 'status': 'passed' if base_process['passed'] and candidate_process['passed'] else 'failed'}
        if row['status'] == 'passed':
            data = [json.loads((pair / label / 'artifacts/result.json').read_text()) for label in ['baseline', 'candidate']]
            def med(item, key):
                return statistics.median(s[key] for s in item['samples'] if not s['warmup'])
            metrics = ['constraints', 'wires', 'qapDomain', 'keyStoreBytes', 'compileMs', 'firstWitnessMs', 'setupMs', 'sampledHeapPeakBytes']
            row['metrics'] = {key: {'baseline': data[0][key], 'candidate': data[1][key]} for key in metrics}
            row['metrics']['terms'] = {'baseline': data[0]['terms']['total'], 'candidate': data[1]['terms']['total']}
            row['metrics']['peakRssBytes'] = {'baseline': base_process['peakRssBytes'], 'candidate': candidate_process['peakRssBytes']}
            for key in ['witnessMs', 'proveMs', 'verifyMs']:
                row['metrics']['median' + key[0].upper() + key[1:]] = {'baseline': med(data[0], key), 'candidate': med(data[1], key)}
            for values in row['metrics'].values():
                a, b = values['baseline'], values['candidate']
                values['reductionPercent'] = (1 - b / a) * 100 if a and b is not None else None
            row['r1csCanonicalSha256'] = {label: item['r1csCanonicalSha256'] for label, item in zip(['baseline', 'candidate'], data)}
        comparisons.append(row)
    save(output / 'summary.json', comparisons)
    lines = ['# SHA-2 optimization comparison', '', 'All timings are diagnostic measurements of this host; negative reductions mean regressions.',
             'Heap limits are JVM `-Xmx`, not total-process memory limits. RSS includes native/off-heap memory.', '',
             '| Profile | Constraints, before → after | Prove median ms, before → after | Prove change |', '|---|---:|---:|---:|']
    for row in comparisons:
        if row['status'] != 'passed':
            lines.append(f'| {row["profile"]} | {row["status"]} | — | — |')
            continue
        c = row['metrics']['constraints']
        p = row['metrics']['medianProveMs']
        lines.append(f'| {row["profile"]} | {c["baseline"]:,} → {c["candidate"]:,} | {p["baseline"]:.2f} → {p["candidate"]:.2f} | {p["reductionPercent"]:.2f}% reduction |')
    lines.extend(['', 'Complete compile/witness/setup/verification, term, domain, key and memory comparisons are in `summary.json`.',
                  'Independent snarkjs checks are separate; a successful benchmark does not imply that they ran.', ''])
    (output / 'summary.md').write_text('\n'.join(lines))


def verify(output, cli):
    cli = cli.resolve()
    command = ['node', str(cli)] if cli.suffix in ('.js', '.cjs', '.mjs') else [str(cli)]
    version = subprocess.run([*command, '--version'], capture_output=True, text=True)
    version_text = version.stdout + version.stderr
    if not re.search(r'snarkjs@0\.7\.6\b', version_text):
        raise RuntimeError('Pinned snarkjs 0.7.6 required')
    folder = output / 'independent-verification'
    folder.mkdir(exist_ok=False)
    checks = []
    for process_path in sorted(output.glob('*/*/*/*/process.json')):
        process = json.loads(process_path.read_text())
        if not process['passed']:
            raise RuntimeError('Cannot verify an incomplete/failed case: ' + str(process_path))
        for filename, expected in process['artifactSha256'].items():
            if digest(process_path.parent / filename) != expected:
                raise RuntimeError('Artifact identity changed: ' + filename)
        artifact = process_path.parent / 'artifacts'
        result = json.loads((artifact / 'result.json').read_text())
        proofs = sorted(artifact.glob('proof-[0-9]*.json'))
        changed = sorted(artifact.glob('public-wrong-*.json'))
        if len(proofs) != result['randomizedProofsVerified'] or len(changed) != result['publicInputs']:
            raise RuntimeError('Incomplete proof-vector set: ' + str(artifact))
        message = bytes.fromhex((artifact / 'message.hex').read_text().strip())
        expected_digest = hashlib.new(result['algorithm'].lower().replace('-', ''), message).digest()
        expected_public = [int.from_bytes(expected_digest[i:i + 16], 'big') for i in range(0, len(expected_digest), 16)]
        if len(message) != result['messageBytes'] or expected_digest.hex() != (artifact / 'digest.hex').read_text().strip():
            raise RuntimeError('Independent digest mismatch: ' + str(artifact))
        if [int(value) for value in json.loads((artifact / 'public.json').read_text())] != expected_public:
            raise RuntimeError('Full digest limb mismatch: ' + str(artifact))
        vectors = [(p, artifact / 'public.json', True) for p in proofs]
        vectors += [(artifact / 'proof.json', p, False) for p in changed]
        vectors += [(artifact / 'proof-negated-a.json', artifact / 'public.json', False)]
        for proof, public, valid in vectors:
            call = [*command, 'groth16', 'verify', str(artifact / 'verification_key.json'), str(public), str(proof)]
            p = subprocess.run(call, capture_output=True, text=True, timeout=120)
            text = p.stdout + p.stderr
            okay = (p.returncode == 0 and 'OK!' in text) if valid else (p.returncode != 0 and 'Invalid proof' in text)
            checks.append({'case': str(process_path.parent.relative_to(output)), 'proof': proof.name,
                           'public': public.name, 'expectedValid': valid, 'passed': okay, 'exitCode': p.returncode})
            (folder / f'{len(checks):04d}.log').write_text(text)
            save(folder / 'result.json', {'cliSha256': digest(cli), 'version': version_text.splitlines()[0], 'checks': checks})
            if not okay:
                raise RuntimeError(f'Independent verification failed: {call}; {text}')
    if not checks:
        raise RuntimeError('No successful cases found')
    print(f'{len(checks)} independent snarkjs checks passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare', help='compile the harness only; do not benchmark')
    prep.add_argument('--checkout', type=pathlib.Path, required=True)
    prep.add_argument('--output', type=pathlib.Path, required=True)
    run = sub.add_parser('run')
    run.add_argument('--baseline', type=pathlib.Path, required=True)
    run.add_argument('--candidate', type=pathlib.Path, required=True)
    run.add_argument('--output', type=pathlib.Path, required=True)
    run.add_argument('--heaps', nargs='+', choices=['6g', '8g'], default=['6g', '8g'])
    run.add_argument('--algorithms', nargs='+', choices=['SHA-256', 'SHA-512'], default=['SHA-256', 'SHA-512'])
    run.add_argument('--lengths', nargs='+', type=int, choices=[32, 128, 1024], default=[32, 128, 1024])
    run.add_argument('--backends', nargs='+', choices=['pure-java', 'blst'], default=['pure-java'])
    run.add_argument('--samples', type=int, default=3)
    run.add_argument('--processors', type=int, default=8)
    run.add_argument('--timeout', type=int, default=900, help='seconds per standalone process')
    summary = sub.add_parser('summarize')
    summary.add_argument('output', type=pathlib.Path)
    oracle = sub.add_parser('verify')
    oracle.add_argument('output', type=pathlib.Path)
    oracle.add_argument('--snarkjs', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.checkout, args.output.resolve())
    elif args.command == 'run':
        if not 3 <= args.samples <= 20 or args.processors < 1 or args.timeout < 1:
            parser.error('samples must be 3..20; processors and timeout must be positive')
        run_matrix(args)
    elif args.command == 'summarize':
        summarize(args.output.resolve())
    else:
        verify(args.output.resolve(), args.snarkjs)


if __name__ == '__main__':
    main()
