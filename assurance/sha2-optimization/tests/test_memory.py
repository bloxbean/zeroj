"""Memory-investigation orchestration tests; no Java, Gradle, jcmd or prover runs.

Run with: python3 -B -m unittest discover -s assurance/sha2-optimization/tests -v
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


HARNESS = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sha2_memory_review', HARNESS / 'memory.py')
memory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(memory)
bench = memory.bench

HISTOGRAM = """424242:
 num     #instances         #bytes  class name (module)
-------------------------------------------------------
   1:             2             96  [J (java.base@25)
   2:             3             72  java.lang.String (java.base@25)
Total             5            168
"""


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sha2-memory-controller-test-')
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)


class HistogramParserTest(unittest.TestCase):
    def test_complete_histogram_preserves_counts_and_class_names(self):
        result = memory.parse_histogram(HISTOGRAM)
        self.assertEqual(result['liveBytes'], 168)
        self.assertEqual(result['instances'], 5)
        self.assertEqual(result['classes'], [
            {'instances': 2, 'bytes': 96, 'class': '[J'},
            {'instances': 3, 'bytes': 72, 'class': 'java.lang.String'},
        ])

    def test_truncated_or_unrecognized_output_is_not_a_measurement(self):
        for output in [
            '', 'AttachNotSupportedException: target is unavailable',
            HISTOGRAM.replace('Total             5            168\n', ''),
            HISTOGRAM.replace('168', '169'),
            'Total             0              0\n',
        ]:
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    memory.parse_histogram(output)


class HistogramControllerTest(TemporaryCase):
    def test_snapshots_are_ordered_and_acknowledged_only_after_persistence(self):
        folder = self.root / 'case'
        artifact = folder / 'artifacts'
        artifact.mkdir(parents=True)
        index = 0
        commands = []

        def wait(_interval):
            nonlocal index
            if index:
                previous = memory.SNAPSHOTS[index - 1]
                self.assertTrue((artifact / ('continue-' + previous)).is_file())
                saved = json.loads((artifact / 'live-heap.json').read_text())
                self.assertEqual(list(saved), list(memory.SNAPSHOTS[:index]))
            if index == len(memory.SNAPSHOTS):
                return True
            write_json(artifact / 'progress.json', {
                'snapshot': memory.SNAPSHOTS[index], 'phaseState': 'awaiting-histogram', 'pid': 424242,
            })
            index += 1
            return False

        def run(command, **kwargs):
            name = memory.SNAPSHOTS[index - 1]
            self.assertFalse((artifact / ('continue-' + name)).exists())
            self.assertEqual(command, ['/mock/java-home/bin/jcmd', '424242', 'GC.class_histogram'])
            self.assertEqual(kwargs, {'capture_output': True, 'text': True, 'timeout': 60})
            commands.append(command)
            return SimpleNamespace(returncode=0, stdout=HISTOGRAM, stderr='')

        real_save = bench.save

        def save(path, value):
            if path.name == 'live-heap.json':
                name = memory.SNAPSHOTS[index - 1]
                self.assertFalse((artifact / ('continue-' + name)).exists())
            real_save(path, value)

        with patch.object(memory.subprocess, 'run', side_effect=run), patch.object(bench, 'save', side_effect=save):
            captured = memory.histogram_controller(folder, '/mock/java-home/bin/java', SimpleNamespace(wait=wait))
        self.assertEqual(captured, list(memory.SNAPSHOTS))
        self.assertEqual(len(commands), 4)
        self.assertEqual(json.loads((folder / 'controller.json').read_text()),
                         {'status': 'passed', 'capturedSnapshots': list(memory.SNAPSHOTS)})

    def test_failed_or_malformed_histogram_never_acknowledges_snapshot(self):
        for label, result in [
            ('exit', SimpleNamespace(returncode=1, stdout='', stderr='Attach failed')),
            ('malformed', SimpleNamespace(returncode=0, stdout='truncated histogram', stderr='')),
        ]:
            with self.subTest(label=label):
                folder = self.root / label
                write_json(folder / 'artifacts/progress.json', {
                    'snapshot': memory.SNAPSHOTS[0], 'phaseState': 'awaiting-histogram', 'pid': 424242,
                })
                stop = SimpleNamespace(wait=Mock(side_effect=[False, True]))
                with patch.object(memory.subprocess, 'run', return_value=result):
                    with self.assertRaises((RuntimeError, ValueError)):
                        memory.histogram_controller(folder, '/mock/bin/java', stop)
                self.assertFalse((folder / 'artifacts' / ('continue-' + memory.SNAPSHOTS[0])).exists())
                self.assertFalse((folder / 'artifacts/live-heap.json').exists())
                self.assertTrue((folder / ('histogram-' + memory.SNAPSHOTS[0] + '.txt')).exists())
                status = json.loads((folder / 'controller.json').read_text())
                self.assertEqual(status['status'], 'failed')
                self.assertEqual(status['capturedSnapshots'], [])
                self.assertTrue(status['error'])

    def test_early_stop_persists_incomplete_snapshot_count(self):
        folder = self.root / 'incomplete'
        write_json(folder / 'artifacts/progress.json', {
            'snapshot': memory.SNAPSHOTS[0], 'phaseState': 'awaiting-histogram', 'pid': 424242,
        })
        stop = SimpleNamespace(wait=Mock(side_effect=[False, True]))
        with patch.object(memory.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=HISTOGRAM, stderr='')):
            captured = memory.histogram_controller(folder, '/mock/bin/java', stop)
        self.assertEqual(captured, [memory.SNAPSHOTS[0]])
        self.assertEqual(json.loads((folder / 'controller.json').read_text()),
                         {'status': 'incomplete', 'capturedSnapshots': captured})

    def test_unexpected_snapshot_order_does_not_attach_to_any_process(self):
        for name in ['unknown', memory.SNAPSHOTS[1]]:
            with self.subTest(name=name):
                folder = self.root / name
                write_json(folder / 'artifacts/progress.json', {
                    'snapshot': name, 'phaseState': 'awaiting-histogram', 'pid': 424242,
                })
                with patch.object(memory.subprocess, 'run') as command:
                    with self.assertRaisesRegex(RuntimeError, 'snapshot ordering'):
                        memory.histogram_controller(folder, '/mock/bin/java', SimpleNamespace(wait=Mock(return_value=False)))
                command.assert_not_called()


class StackCaptureControlsTest(TemporaryCase):
    def test_stack_capture_changes_exit_policy_without_changing_resource_controls(self):
        for heap in ['6g', '8g']:
            for capture in [False, True]:
                with self.subTest(heap=heap, capture=capture):
                    folder = self.root / (heap + '-' + str(capture))
                    args = SimpleNamespace(scale=True, capture_oom_stack=capture, processors=8, samples=3, timeout=1)
                    process = SimpleNamespace(pid=424242, wait=Mock(return_value=1), returncode=1)

                    def popen(command, **kwargs):
                        self.assertEqual('-XX:+ExitOnOutOfMemoryError' in command, not capture)
                        for option in [f'-Xmx{heap}', '-XX:ActiveProcessorCount=8',
                                       f'-Dsha2.benchmark.expectedHeapBytes={int(heap[0]) << 30}',
                                       '-Dsha2.benchmark.expectedProcessors=8', '-Dsha2.benchmark.checkpoints=true',
                                       '-Dzeroj.allowInsecureTrustedSetup=true']:
                            self.assertIn(option, command)
                        self.assertTrue(any(x.startswith('-Xlog:gc:') for x in command))
                        write_json(folder / 'artifacts/progress.json', {
                            'maxHeapBytes': int(heap[0]) << 30, 'processors': 8,
                            'currentStage': 'development-setup', 'phaseState': 'running',
                        })
                        kwargs['stderr'].write('java.lang.OutOfMemoryError: Java heap space\n')
                        kwargs['stderr'].flush()
                        return process

                    with patch.object(bench.subprocess, 'Popen', side_effect=popen), contextlib.redirect_stdout(io.StringIO()):
                        passed = bench.run_case({'java': 'mock-java', 'classpath': '', 'main': 'Mock',
                                                 'checkout': str(self.root)}, folder, 'SHA-256', 16384,
                                                heap, 'pure-java', args)
                    result = json.loads((folder / 'process.json').read_text())
                    self.assertFalse(passed)
                    self.assertEqual(result['outcome'], 'heap-oom')
                    self.assertTrue(result['effectiveControlsMatch'])


class MemorySummaryTest(TemporaryCase):
    def test_telemetry_falls_back_after_missing_malformed_or_nonobject_result(self):
        for label, content in [('missing', None), ('truncated', '{'), ('null', 'null'), ('list', '[]')]:
            with self.subTest(label=label):
                case = self.root / label
                progress = {'currentStage': 'packing-sample-0', 'sampledHeapPeakBytes': 123}
                write_json(case / 'artifacts/progress.json', progress)
                if content is not None:
                    (case / 'artifacts/result.json').write_text(content)
                self.assertEqual(memory.telemetry(case), progress)
        self.assertEqual(memory.telemetry(self.root / 'absent'), {})

    def test_valid_result_takes_precedence_over_older_checkpoint(self):
        case = self.root / 'case'
        write_json(case / 'artifacts/progress.json', {'stage': 'old'})
        write_json(case / 'artifacts/result.json', {'stage': 'new'})
        self.assertEqual(memory.telemetry(case), {'stage': 'new'})

    def case(self, mode, heap, passed, **extra):
        case = self.root / heap / mode / 'sha256-16384/candidate'
        write_json(case / 'process.json', {
            'algorithm': 'SHA-256', 'heap': heap, 'messageBytes': 16384,
            'outcome': 'passed' if passed else 'heap-oom', 'passed': passed,
            'effectiveControlsMatch': True, 'lastReportedStage': 'negative-proof-checks', **extra,
        })
        return case

    def test_failed_pipeline_keeps_partial_samples_without_becoming_a_success(self):
        write_json(self.root / 'matrix.json', {'mode': 'pipeline', 'profiles': [['SHA-256', '6g'], ['SHA-256', '8g']]})
        good = self.case('pipeline', '6g', True)
        bad = self.case('pipeline', '8g', False, lastReportedStage='prove-sample-1')
        write_json(good / 'artifacts/result.json', {
            'samples': [{'warmup': True, 'proveMs': 20}, {'warmup': False, 'proveMs': 10}],
            'measuredSamples': 1, 'warmupSamples': 1, 'originalDocumentRelationMatches': True,
        })
        write_json(bad / 'artifacts/progress.json', {'samples': [{'warmup': True, 'proveMs': 25}],
                                                     'sampledHeapPeakBytes': 500})
        (bad / 'artifacts/result.json').write_text('{')
        summary = memory.summarize(self.root)
        self.assertEqual(summary['completedProcesses'], 2)
        self.assertEqual(summary['passedPipelines'], 1)
        success, failure = summary['cases']
        self.assertEqual(success['measuredSamples'], 1)
        self.assertEqual(success['warmupSamples'], 1)
        self.assertFalse(failure['passed'])
        self.assertEqual(len(failure['samples']), 1)
        self.assertEqual(failure['sampledHeapPeakBytes'], 500)
        self.assertIn('not necessarily whole-run peak', failure['sampledHeapScope'])

    def test_live_process_success_requires_complete_controller_success(self):
        for label, controller in [
            ('missing', None),
            ('failed', {'status': 'failed', 'capturedSnapshots': [], 'error': 'Attach failed'}),
            ('incomplete', {'status': 'incomplete', 'capturedSnapshots': [memory.SNAPSHOTS[0]]}),
            ('passed', {'status': 'passed', 'capturedSnapshots': list(memory.SNAPSHOTS)}),
        ]:
            with self.subTest(status=label):
                output = self.root / label
                write_json(output / 'matrix.json', {'mode': 'live-set', 'profiles': [['SHA-256', '6g']]})
                case = output / '6g/live-set/sha256-16384/candidate'
                write_json(case / 'process.json', {
                    'algorithm': 'SHA-256', 'heap': '6g', 'messageBytes': 16384,
                    'passed': True, 'outcome': 'passed', 'effectiveControlsMatch': True,
                })
                if controller is not None:
                    write_json(case / 'controller.json', controller)
                summary = memory.summarize(output)
                self.assertEqual(summary['passedPipelines'], 0)
                self.assertTrue(summary['cases'][0]['passed'])
                self.assertEqual(summary['cases'][0]['diagnosticPassed'], label == 'passed')


class ExperimentOutcomeTest(TemporaryCase):
    def args(self, name, mode, algorithms=None):
        return SimpleNamespace(output=self.root / name, checkout=self.root, mode=mode, length=16384,
                               heaps=['6g'], algorithms=algorithms or ['SHA-256'], samples=1, processors=8, timeout=1)

    def fake_case(self, *, outcome='heap-oom', stage='development-setup', controls=True, setup_stack=True):
        def run_case(launch, folder, algorithm, length, heap, backend, args):
            passed = outcome == 'passed'
            write_json(folder / 'process.json', {
                'algorithm': algorithm, 'messageBytes': length, 'heap': heap, 'backend': backend,
                'passed': passed, 'outcome': outcome, 'effectiveControlsMatch': controls,
                'lastReportedStage': stage,
            })
            stack = 'at org.zeroj.crypto.setup.Groth16SetupBLS381.setupToStore(Groth16SetupBLS381.java:398)\n'
            (folder / 'stderr.log').write_text(stack if setup_stack else 'unrelated failure\n')
            return passed
        return run_case

    def execute(self, args, fake_case):
        with patch.object(bench, 'prepare', return_value={'java': '/mock/bin/java', 'main': 'Mock'}), \
                patch.object(bench, 'assert_unchanged'), patch.object(bench, 'run_case', side_effect=fake_case) as run_case, \
                contextlib.redirect_stdout(io.StringIO()):
            memory.run(args)
        return run_case

    def test_expected_setup_oom_is_diagnostic_success_never_a_passed_pipeline(self):
        args = self.args('expected', 'oom')
        self.execute(args, self.fake_case())
        summary = json.loads((args.output / 'summary.json').read_text())
        self.assertEqual(summary['passedPipelines'], 0)
        self.assertFalse(summary['cases'][0]['passed'])
        self.assertEqual(summary['cases'][0]['outcome'], 'heap-oom')
        self.assertEqual(summary['cases'][0]['setupAllocationLine'], ['398'])

    def test_wrong_oom_stage_controls_or_stack_does_not_satisfy_diagnostic(self):
        for label, kwargs in [
            ('timeout', {'outcome': 'timeout'}), ('prove', {'stage': 'prove-sample-0'}),
            ('controls', {'controls': False}), ('stack', {'setup_stack': False}),
            ('unexpected-success', {'outcome': 'passed'}),
        ]:
            with self.subTest(label=label):
                args = self.args(label, 'oom')
                with self.assertRaises(SystemExit):
                    self.execute(args, self.fake_case(**kwargs))
                self.assertTrue((args.output / 'summary.json').exists())

    def test_failed_pipeline_still_attempts_remaining_profiles(self):
        args = self.args('failed-pipelines', 'pipeline', ['SHA-256', 'SHA-512'])
        attempted = []
        fake_case = self.fake_case()

        def record(*a, **kw):
            attempted.append(a[2])
            return fake_case(*a, **kw)

        with self.assertRaises(SystemExit):
            self.execute(args, record)
        self.assertEqual(attempted, ['SHA-256', 'SHA-512'])
        summary = json.loads((args.output / 'summary.json').read_text())
        self.assertEqual(summary['completedProcesses'], 2)
        self.assertEqual(summary['passedPipelines'], 0)

    def test_controller_error_is_recorded_and_matrix_summary_survives(self):
        args = self.args('controller-failure', 'live-set')

        def broken_controller(folder, java, stop):
            # Wait for the mocked owned process record to exist, as the real controller waits for progress.
            stop.wait(1)
            write_json(folder / 'controller.json', {'status': 'failed', 'capturedSnapshots': [],
                                                   'error': 'RuntimeError: mocked attach failure'})
            raise RuntimeError('mocked attach failure')

        with patch.object(memory, 'histogram_controller', side_effect=broken_controller):
            with self.assertRaises(SystemExit):
                self.execute(args, self.fake_case(outcome='passed'))
        row = json.loads((args.output / 'summary.json').read_text())['cases'][0]
        self.assertTrue(row['passed'])
        self.assertFalse(row['diagnosticPassed'])
        self.assertIn('mocked attach failure', row['controller']['error'])


if __name__ == '__main__':
    unittest.main()
