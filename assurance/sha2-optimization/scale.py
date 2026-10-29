#!/usr/bin/env python3
"""Measure fixed-length SHA-2 document sizes on one checkout, retaining resource failures."""
import argparse
import importlib.util
import json
import pathlib
import platform
import statistics

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('sha2_benchmark', HERE / 'run.py')
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def telemetry(case):
    for name in ('result.json', 'progress.json'):
        path = case / 'artifacts' / name
        if path.exists():
            try:
                data = json.loads(path.read_text())
                if isinstance(data, dict):
                    return data
            except (ValueError, OSError):
                pass
    return {}


def summarize(output):
    cases = []
    for path in sorted(output.glob('*/*/*/optimized/process.json')):
        process = json.loads(path.read_text())
        measured = telemetry(path.parent)
        row = {'case': str(path.parent.relative_to(output)), 'algorithm': process['algorithm'],
               'messageBytes': process['messageBytes'], 'heap': process['heap'],
               'backend': process['backend'], 'outcome': process['outcome'],
               'passed': process['passed'], 'effectiveControlsMatch': process.get('effectiveControlsMatch', False),
               'lastReportedStage': process.get('lastReportedStage'),
               'lastReportedPhaseState': process.get('lastReportedPhaseState'),
               'wallSeconds': process['wallSecondsIncludingStartupAndChecks'],
               'peakRssBytes': process.get('peakRssBytes'),
               'verifiedProofSamples': len(measured.get('samples', [])),
               'sampledHeapScope': 'whole completed run' if process['passed'] else 'last surviving checkpoint only'}
        for key in ('constraints', 'wires', 'terms', 'pressureModeEntered', 'r1csCanonicalSha256',
                    'qapDomain', 'keyStoreBytes', 'compileMs', 'fingerprintMs', 'firstWitnessMs',
                    'setupMs', 'sampledHeapPeakBytes', 'gcCollections', 'gcTimeMs', 'failure'):
            if key in measured:
                row[key] = measured[key]
        if process['passed']:
            samples = [s for s in measured['samples'] if not s['warmup']]
            for name in ('witnessMs', 'proveMs', 'verifyMs'):
                row['median' + name[0].upper() + name[1:]] = statistics.median(s[name] for s in samples)
        cases.append(row)
    manifest = json.loads((output / 'matrix.json').read_text())
    expected = len(manifest['heaps']) * len(manifest['algorithms']) * len(manifest['lengths']) * len(manifest['backends'])
    report = {'expectedCases': expected, 'completedProcesses': len(cases),
              'passedCases': sum(c['passed'] for c in cases),
              'allProcessesFinished': len(cases) == expected,
              'allCasesPassed': len(cases) == expected and all(c['passed'] for c in cases), 'cases': cases}
    bench.save(output / 'summary.json', report)
    lines = ['# SHA-2 document-size measurements', '',
             'Fixed byte lengths, complete digests, development setup. Heap caps are not RSS limits.',
             'A timeout is a time-budget result, not evidence of heap exhaustion. Failed pipelines',
             'do not get success-only proof medians. Partial verified samples are recorded separately.', '',
             '| Case | Result | Last stage | Constraints | Proof median seconds | Peak RSS GiB |',
             '|---|---|---|---:|---:|---:|']
    for case in cases:
        seconds = f"{case['medianProveMs'] / 1000:.3f}" if case['passed'] else '—'
        rss = f"{case['peakRssBytes'] / 2**30:.2f}" if case['peakRssBytes'] is not None else '—'
        constraints = f"{case['constraints']:,}" if 'constraints' in case else '—'
        lines.append(f"| {case['case']} | {case['outcome']} | {case['lastReportedStage']} | {constraints} | {seconds} | {rss} |")
    lines += ['', f"Completed processes: {len(cases)}/{expected}; full-pipeline passes: {report['passedCases']}.",
              'Independent proof verification is a separate step. See raw checkpoints, process status and GC logs.', '']
    (output / 'summary.md').write_text('\n'.join(lines))
    return report


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    launch = bench.prepare(args.checkout, output / 'prepare-optimized')
    bench.save(output / 'matrix.json', {
        'kind': 'optimized-document-scaling', 'checkout': str(args.checkout.resolve()),
        'heaps': args.heaps, 'algorithms': args.algorithms, 'lengths': args.lengths,
        'backends': args.backends, 'samples': args.samples, 'processors': args.processors,
        'timeoutSecondsPerCase': args.timeout, 'platform': platform.platform(),
        'order': 'Sequential fresh JVMs; ascending requested size, then heap, backend and hash',
        'fixture': 'Public ascending-byte pattern; measures SHA byte-length work, not document parsing',
        'telemetry': 'Atomic phase checkpoints, GC logging, fail-fast OOM; no GC tuning or security changes',
        'proverApi': 'Groth16Keys.prove(backend, BigInteger[], List<R1CSConstraint>)'})
    args.scale = True
    passed = True
    for length in args.lengths:
        for heap in args.heaps:
            for backend in args.backends:
                for algorithm in args.algorithms:
                    profile = algorithm.lower().replace('-', '') + '-' + str(length)
                    bench.assert_unchanged(launch)
                    okay = bench.run_case(launch, output / heap / backend / profile / 'optimized',
                                          algorithm, length, heap, backend, args)
                    passed = okay and passed
                    bench.assert_unchanged(launch)
                    summarize(output)
    if not passed:
        raise SystemExit('One or more profiles did not complete successfully; all requested profiles were attempted. See summary.json.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    task = commands.add_parser('run')
    task.add_argument('--checkout', type=pathlib.Path, default=pathlib.Path('.'))
    task.add_argument('--output', type=pathlib.Path, required=True)
    task.add_argument('--lengths', type=int, nargs='+', choices=[32, 128, 1024, 2048, 4096, 8192, 16384],
                      default=[2048, 4096, 8192, 16384])
    task.add_argument('--heaps', nargs='+', choices=['6g', '8g'], default=['6g', '8g'])
    task.add_argument('--algorithms', nargs='+', choices=['SHA-256', 'SHA-512'], default=['SHA-256', 'SHA-512'])
    task.add_argument('--backends', nargs='+', choices=['pure-java', 'blst'], default=['pure-java'])
    task.add_argument('--samples', type=int, default=3)
    task.add_argument('--processors', type=int, default=8)
    task.add_argument('--timeout', type=int, default=900)
    summary = commands.add_parser('summarize')
    summary.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    if args.command == 'summarize':
        summarize(args.output.resolve())
    else:
        if not 3 <= args.samples <= 20 or args.processors < 1 or args.timeout < 1:
            parser.error('samples must be 3..20; processors and timeout must be positive')
        if any(len(values) != len(set(values)) for values in [args.lengths, args.heaps, args.algorithms, args.backends]):
            parser.error('matrix dimensions must not contain duplicate values')
        run(args)


if __name__ == '__main__':
    main()
