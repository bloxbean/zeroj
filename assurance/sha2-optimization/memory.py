#!/usr/bin/env python3
"""Public-fixture setup OOM diagnostics and existing Groth16Pipeline feasibility tests."""
import argparse
import concurrent.futures
import importlib.util
import json
import pathlib
import re
import subprocess
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('sha2_benchmark', HERE / 'run.py')
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)
MEMORY_MAIN = 'org.zeroj.assurance.sha2.Sha2MemoryInvestigation'
SNAPSHOTS = ('graph-csr-boxed-witness', 'csr-boxed-witness', 'csr-only', 'released')


def parse_histogram(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r'\s*\d+:\s+(\d+)\s+(\d+)\s+(\S+)', line)
        if match:
            rows.append({'instances': int(match[1]), 'bytes': int(match[2]), 'class': match[3]})
    total = re.search(r'^Total\s+(\d+)\s+(\d+)\s*$', text, re.MULTILINE)
    if not rows or not total or sum(x['bytes'] for x in rows) != int(total[2]):
        raise ValueError('Incomplete/unrecognized live histogram; no trustworthy total')
    return {'instances': int(total[1]), 'liveBytes': int(total[2]), 'classes': rows}


def histogram_controller(folder, java, stop):
    """A full-GC live histogram is an explicit diagnostic, never part of pipeline timing."""
    handled = []
    status = {'status': 'running', 'capturedSnapshots': handled}
    try:
        _capture_histograms(folder, java, stop, handled)
        status['status'] = 'passed' if handled == list(SNAPSHOTS) else 'incomplete'
        return handled
    except Exception as failure:
        status['status'] = 'failed'
        status['error'] = type(failure).__name__ + ': ' + str(failure)
        raise
    finally:
        folder.mkdir(parents=True, exist_ok=True)
        bench.save(folder / 'controller.json', status)


def _capture_histograms(folder, java, stop, handled):
    results = {}
    while not stop.wait(0.1):
        progress = folder / 'artifacts/progress.json'
        if not progress.exists():
            continue
        state = json.loads(progress.read_text())  # Java atomically replaces this file.
        name = state.get('snapshot')
        if state.get('phaseState') != 'awaiting-histogram' or name in handled:
            continue
        if name not in SNAPSHOTS or name != SNAPSHOTS[len(handled)]:
            raise RuntimeError('Unexpected diagnostic snapshot ordering: ' + str(name))
        command = [str(pathlib.Path(java).with_name('jcmd')), str(state['pid']), 'GC.class_histogram']
        p = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (folder / ('histogram-' + name + '.txt')).write_text(p.stdout + p.stderr)
        if p.returncode:
            raise RuntimeError('jcmd live histogram failed: ' + p.stderr)
        results[name] = parse_histogram(p.stdout)
        results[name]['command'] = command
        bench.save(folder / 'artifacts/live-heap.json', results)
        handled.append(name)
        # Acknowledge only after a successful, parsed snapshot is durably recorded.
        (folder / 'artifacts' / ('continue-' + name)).write_text('captured\n')


def telemetry(case):
    for name in ('result.json', 'progress.json'):
        try:
            value = json.loads((case / 'artifacts' / name).read_text())
            if isinstance(value, dict):
                return value
        except (ValueError, OSError):
            pass
    return {}


def summarize(output):
    manifest = json.loads((output / 'matrix.json').read_text())
    rows = []
    for path in sorted(output.glob('*/*/*/*/process.json')):
        process = json.loads(path.read_text())
        artifact = path.parent / 'artifacts'
        report = telemetry(path.parent)
        row = {'case': str(path.parent.relative_to(output)), 'algorithm': process['algorithm'],
               'heap': process['heap'], 'messageBytes': process['messageBytes'],
               'outcome': process['outcome'], 'passed': process['passed'],
               'lastStage': process.get('lastReportedStage'), 'peakRssBytes': process.get('peakRssBytes'),
               'effectiveControlsMatch': process.get('effectiveControlsMatch', False),
               'samples': report.get('samples', [])}
        for key in ('constraints', 'wires', 'terms', 'r1csCanonicalSha256', 'fingerprint', 'csrPayloadBytes',
                    'dictionaryEntries', 'compileAndFingerprintMs', 'setupIncludingCacheMs',
                    'cacheWriteAndHashMs', 'cacheBytes', 'keyStoreBytes', 'qapDomain', 'sampledHeapPeakBytes',
                    'originalDocumentRelationMatches', 'measuredSamples', 'warmupSamples', 'timingScope'):
            if key in report:
                row[key] = report[key]
        row['sampledHeapScope'] = 'completed process' if process['passed'] else 'last surviving record; not necessarily whole-run peak'
        if (artifact / 'live-heap.json').exists():
            row['controlledLiveBytes'] = {k: v['liveBytes'] for k, v in json.loads((artifact / 'live-heap.json').read_text()).items()}
        if manifest['mode'] == 'live-set':
            controller = path.parent / 'controller.json'
            row['controller'] = json.loads(controller.read_text()) if controller.exists() else {'status': 'missing'}
            row['diagnosticPassed'] = bool(process['passed'] and row['controller']['status'] == 'passed')
        if manifest['mode'] == 'oom':
            error = (path.parent / 'stderr.log').read_text()
            row['setupAllocationLine'] = re.findall(r'Groth16SetupBLS381\.setupToStore\(Groth16SetupBLS381.java:(\d+)\)', error)[:1]
        rows.append(row)
    result = {'mode': manifest['mode'], 'expectedCases': len(manifest['profiles']),
              'completedProcesses': len(rows), 'passedPipelines': sum(r['passed'] for r in rows) if manifest['mode'] == 'pipeline' else 0,
              'cases': rows}
    bench.save(output / 'summary.json', result)
    return result


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    launch = bench.prepare(args.checkout, output / 'prepare')
    if args.mode != 'oom':
        launch['main'] = MEMORY_MAIN
    bench.save(output / 'selected-launch.json', launch)
    profiles = [(algorithm, heap) for heap in args.heaps for algorithm in args.algorithms
                if args.mode != 'oom' or (algorithm, heap) != ('SHA-256', '8g')]
    if not profiles:
        raise ValueError('No expected-failing profiles selected')
    bench.save(output / 'matrix.json', {'mode': args.mode, 'profiles': profiles, 'messageBytes': args.length,
                                     'samples': args.samples if args.mode == 'pipeline' else None,
                                     'processors': args.processors, 'timeoutSeconds': args.timeout,
                                     'controls': 'Fresh sequential JVMs; public fixture; pure Java; exact heap caps',
                                     'profiling': 'Live-set mode requests full GC via jcmd; never compare its time to pipeline runs'})
    args.scale = True
    args.capture_oom_stack = args.mode == 'oom'
    # The compatibility main requires >=3 samples; none is reached in the expected setup failures.
    if args.mode == 'oom':
        args.samples = 3
    okay = True
    for algorithm, heap in profiles:
        bench.assert_unchanged(launch)
        folder = output / heap / args.mode / (algorithm.lower().replace('-', '') + '-' + str(args.length)) / 'candidate'
        if args.mode == 'live-set':
            stop = threading.Event()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as workers:
                watcher = workers.submit(histogram_controller, folder, launch['java'], stop)
                try:
                    passed = bench.run_case(launch, folder, algorithm, args.length, heap, 'live-set', args)
                finally:
                    stop.set()
                try:
                    captured = watcher.result()
                    passed = passed and captured == list(SNAPSHOTS)
                except Exception as failure:
                    print('Live histogram controller failed: ' + str(failure), flush=True)
                    passed = False
        else:
            passed = bench.run_case(launch, folder, algorithm, args.length, heap,
                                    'pure-java' if args.mode == 'oom' else 'pipeline', args)
        bench.assert_unchanged(launch)
        if args.mode == 'oom':
            record = json.loads((folder / 'process.json').read_text())
            passed = (not passed and record['outcome'] == 'heap-oom'
                      and record.get('lastReportedStage') == 'development-setup'
                      and record.get('effectiveControlsMatch')
                      and 'Groth16SetupBLS381.setupToStore(' in (folder / 'stderr.log').read_text())
        okay = passed and okay
        summarize(output)
    if not okay:
        raise SystemExit('An experiment did not reach its expected outcome; see local records.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['oom', 'live-set', 'pipeline', 'summarize'])
    parser.add_argument('--checkout', type=pathlib.Path, default=pathlib.Path('.'))
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--length', type=int, choices=[32, 16384], default=16384)
    parser.add_argument('--heaps', nargs='+', choices=['6g', '8g'], default=['6g', '8g'])
    parser.add_argument('--algorithms', nargs='+', choices=['SHA-256', 'SHA-512'], default=['SHA-256', 'SHA-512'])
    parser.add_argument('--samples', type=int, choices=[1, 2, 3], default=1)
    parser.add_argument('--processors', type=int, default=8)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    if args.processors < 1 or args.timeout < 1:
        parser.error('processors and timeout must be positive')
    if len(args.heaps) != len(set(args.heaps)) or len(args.algorithms) != len(set(args.algorithms)):
        parser.error('matrix dimensions must not contain duplicates')
    if args.mode == 'oom' and args.length != 16384:
        parser.error('OOM reproduction is specifically the measured 16 KiB failures')
    if args.mode == 'summarize':
        summarize(args.output.resolve())
    else:
        run(args)


if __name__ == '__main__':
    main()
