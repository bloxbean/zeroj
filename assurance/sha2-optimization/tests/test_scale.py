"""Runner-control tests only: mocks never launch Java, Gradle or a cryptographic oracle.

Run with: python3 -B -m unittest discover -s assurance/sha2-optimization/tests -v
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


HARNESS = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sha2_scale_review', HARNESS / 'scale.py')
scale = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scale)
bench = scale.bench


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def controls(heap='6g'):
    return {'maxHeapBytes': int(heap[0]) << 30, 'processors': 8}


class ScaleRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sha2-scale-control-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.args = SimpleNamespace(scale=True, processors=8, samples=3, timeout=1)

    def run_fake(self, name, *, heap='6g', result=None, progress=None,
                 stdout='', stderr='', exit_code=0, timeout=False):
        folder = self.root / name
        outside = self.root / 'unrelated-key-marker'
        outside.write_text('keep')
        process = SimpleNamespace(pid=424242, returncode=exit_code)
        process.wait = unittest.mock.Mock(side_effect=[subprocess.TimeoutExpired('mock', 1), exit_code]
                                         if timeout else None, return_value=exit_code)

        def popen(command, **kwargs):
            self.assertIn('-XX:+ExitOnOutOfMemoryError', command)
            self.assertIn(f'-Xmx{heap}', command)
            self.assertIn(f'-Dsha2.benchmark.expectedHeapBytes={int(heap[0]) << 30}', command)
            self.assertIn('-Dsha2.benchmark.expectedProcessors=8', command)
            self.assertTrue((folder / 'process-start.json').exists())
            artifacts = folder / 'artifacts'
            artifacts.mkdir()
            for filename, data in [('result.json', result), ('progress.json', progress)]:
                if data is not None:
                    (artifacts / filename).write_text(data if isinstance(data, str) else json.dumps(data))
            keys = folder / 'temporary-keys'
            keys.mkdir()
            (keys / 'mock-key').write_text('development-only')
            kwargs['stdout'].write(stdout)
            kwargs['stdout'].flush()
            kwargs['stderr'].write(stderr)
            kwargs['stderr'].flush()
            return process

        with patch.object(bench.subprocess, 'Popen', side_effect=popen), \
                patch.object(bench.os, 'killpg') as kill, \
                contextlib.redirect_stdout(io.StringIO()):
            passed = bench.run_case({'java': 'mock-java', 'classpath': '', 'main': 'Mock',
                                     'checkout': str(self.root)}, folder, 'SHA-256', 2048,
                                    heap, 'pure-java', self.args)
        status = json.loads((folder / 'process.json').read_text())
        self.assertEqual(passed, status['passed'])
        self.assertTrue(status['temporaryKeysRemoved'])
        self.assertFalse((folder / 'temporary-keys').exists())
        self.assertEqual(outside.read_text(), 'keep')
        if timeout:
            kill.assert_called_once_with(process.pid, bench.signal.SIGKILL)
        else:
            kill.assert_not_called()
        return status

    def test_success_requires_each_actual_heap_cap(self):
        for heap in ['6g', '8g']:
            with self.subTest(heap=heap):
                status = self.run_fake(heap, heap=heap, result={'status': 'passed', **controls(heap)})
                self.assertTrue(status['passed'])
                self.assertEqual(status['outcome'], 'passed')
                self.assertTrue(status['effectiveControlsMatch'])

    def test_heap_and_processor_overrides_fail(self):
        for name, changed in [('heap', {'maxHeapBytes': 8 << 30}), ('processors', {'processors': 9})]:
            with self.subTest(control=name):
                status = self.run_fake(name, result={'status': 'passed', **controls(), **changed})
                self.assertFalse(status['passed'])
                self.assertEqual(status['outcome'], 'invalid-controls')

    def test_heap_oom_uses_atomic_checkpoint_and_cleans_owned_keys(self):
        status = self.run_fake('oom', exit_code=3,
                               stdout='Terminating due to java.lang.OutOfMemoryError: Java heap space\n',
                               progress={**controls(), 'currentStage': 'prove-sample-0', 'phaseState': 'running'})
        self.assertEqual(status['outcome'], 'heap-oom')
        self.assertEqual(status['lastReportedStage'], 'prove-sample-0')
        self.assertEqual(status['lastReportedPhaseState'], 'running')
        self.assertTrue(status['effectiveControlsMatch'])
        self.assertFalse(status['passed'])

    def test_gc_overhead_and_other_oom_are_distinguished(self):
        for name, message, outcome in [
            ('gc-overhead', 'java.lang.OutOfMemoryError: GC overhead limit exceeded', 'heap-oom'),
            ('native-memory', 'java.lang.OutOfMemoryError: Cannot reserve direct buffer memory', 'other-oom'),
        ]:
            with self.subTest(kind=name):
                status = self.run_fake(name, exit_code=3, stderr=message, progress=controls())
                self.assertEqual(status['outcome'], outcome)

    def test_timeout_is_not_reclassified_as_heap_exhaustion(self):
        status = self.run_fake('timeout', timeout=True, exit_code=-9,
                               stderr='java.lang.OutOfMemoryError: Java heap space', progress=controls())
        self.assertEqual(status['outcome'], 'timeout')
        self.assertFalse(status['passed'])

    def test_invalid_controls_are_not_an_authorized_heap_boundary(self):
        status = self.run_fake('invalid-oom', exit_code=3,
                               stdout='java.lang.OutOfMemoryError: Java heap space', progress=controls('8g'))
        self.assertEqual(status['outcome'], 'invalid-controls')
        self.assertFalse(status['effectiveControlsMatch'])

    def test_malformed_result_falls_back_to_checkpoint_without_passing(self):
        status = self.run_fake('malformed', result='{',
                               progress={**controls(), 'currentStage': 'development-setup', 'phaseState': 'completed'})
        self.assertEqual(status['outcome'], 'failed')
        self.assertEqual(status['lastReportedStage'], 'development-setup')
        self.assertFalse(status['passed'])

    def test_no_telemetry_does_not_imply_success(self):
        status = self.run_fake('no-telemetry')
        self.assertEqual(status['outcome'], 'failed')
        self.assertFalse(status['passed'])
        self.assertNotIn('effectiveControlsMatch', status)


class ScaleSummaryTest(unittest.TestCase):
    def test_partial_samples_do_not_get_success_medians(self):
        with tempfile.TemporaryDirectory(prefix='sha2-scale-summary-test-') as temporary:
            root = pathlib.Path(temporary)
            write_json(root / 'matrix.json', {'heaps': ['6g', '8g'], 'algorithms': ['SHA-256'],
                                              'lengths': [2048], 'backends': ['pure-java']})
            for heap, passed in [('6g', True), ('8g', False)]:
                case = root / heap / 'pure-java/sha256-2048/optimized'
                write_json(case / 'process.json', {
                    'algorithm': 'SHA-256', 'messageBytes': 2048, 'heap': heap, 'backend': 'pure-java',
                    'passed': passed, 'outcome': 'passed' if passed else 'heap-oom',
                    'effectiveControlsMatch': True, 'wallSecondsIncludingStartupAndChecks': 10,
                    'lastReportedStage': 'negative-proof-checks' if passed else 'prove-sample-2',
                    'lastReportedPhaseState': 'completed' if passed else 'running', 'peakRssBytes': 100,
                })
                samples = [{'warmup': i == 0, 'witnessMs': v, 'proveMs': v, 'verifyMs': v}
                           for i, v in enumerate([1000, 1, 2, 4] if passed else [1000, 1])]
                write_json(case / 'artifacts' / ('result.json' if passed else 'progress.json'),
                           {'samples': samples, 'sampledHeapPeakBytes': 50, 'constraints': 123})
                if passed:
                    interim = scale.summarize(root)
                    self.assertFalse(interim['allProcessesFinished'])
                    self.assertFalse(interim['allCasesPassed'])
            summary = scale.summarize(root)
            self.assertEqual(summary['passedCases'], 1)
            self.assertTrue(summary['allProcessesFinished'])
            self.assertFalse(summary['allCasesPassed'])
            success, failure = summary['cases']
            self.assertEqual(success['medianProveMs'], 2)
            self.assertEqual(failure['verifiedProofSamples'], 2)
            self.assertNotIn('medianProveMs', failure)
            self.assertEqual(failure['sampledHeapScope'], 'last surviving checkpoint only')


class FailedCaseOracleAccountingTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sha2-scale-oracle-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name) / 'matrix'
        self.root.mkdir()
        self.cli = pathlib.Path(self.temporary.name) / 'mock-cli.cjs'
        self.cli.write_text('// mocked CLI; never executed\n')
        write_json(self.root / '6g/pure-java/sha256-32/optimized/process.json',
                   {'passed': False, 'outcome': 'heap-oom'})

    def successful_case(self):
        case = self.root / '8g/pure-java/sha256-32/optimized'
        artifacts = case / 'artifacts'
        message = bytes(range(32))
        digest = hashlib.sha256(message).digest()
        public = [str(int.from_bytes(digest[i:i + 16], 'big')) for i in [0, 16]]
        write_json(artifacts / 'result.json', {'algorithm': 'SHA-256', 'messageBytes': 32,
                                              'randomizedProofsVerified': 4, 'publicInputs': 2})
        for i in range(4):
            write_json(artifacts / f'proof-{i}.json', {'fixture': i})
        for name in ['proof.json', 'proof-negated-a.json', 'verification_key.json']:
            write_json(artifacts / name, {'fixture': name})
        write_json(artifacts / 'public.json', public)
        for i in range(2):
            changed = list(public)
            changed[i] = str(int(changed[i]) ^ 1)
            write_json(artifacts / f'public-wrong-{i}.json', changed)
        (artifacts / 'message.hex').write_text(message.hex())
        (artifacts / 'digest.hex').write_text(digest.hex())
        write_json(case / 'process.json', {'passed': True, 'artifactSha256': {
            str(p.relative_to(case)): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir()}})

    @staticmethod
    def mock_oracle(command, **kwargs):
        if command[-1] == '--version':
            return SimpleNamespace(returncode=0, stdout='snarkjs@0.7.6\n', stderr='')
        valid = 'public-wrong-' not in command[-2] and 'negated-a' not in command[-1]
        return SimpleNamespace(returncode=0 if valid else 1, stdout='OK!' if valid else 'Invalid proof', stderr='')

    def test_explicit_allow_failed_verifies_success_and_records_skip(self):
        self.successful_case()
        with patch.object(bench.subprocess, 'run', side_effect=self.mock_oracle), \
                contextlib.redirect_stdout(io.StringIO()):
            bench.verify(self.root, self.cli, allow_failed=True)
        result = json.loads((self.root / 'independent-verification/result.json').read_text())
        self.assertEqual(len(result['checks']), 7)
        self.assertEqual(sum(c['expectedValid'] for c in result['checks']), 4)
        self.assertTrue(all(c['passed'] for c in result['checks']))
        self.assertEqual(len(result['skippedFailedCases']), 1)
        self.assertEqual(result['skippedFailedCases'][0]['outcome'], 'heap-oom')

    def test_default_mode_refuses_failed_case(self):
        self.successful_case()
        with patch.object(bench.subprocess, 'run', side_effect=self.mock_oracle):
            with self.assertRaisesRegex(RuntimeError, 'incomplete/failed case'):
                bench.verify(self.root, self.cli)

    def test_all_failed_never_reports_zero_check_success(self):
        with patch.object(bench.subprocess, 'run', side_effect=self.mock_oracle):
            with self.assertRaisesRegex(RuntimeError, 'No successful cases'):
                bench.verify(self.root, self.cli, allow_failed=True)
        result = json.loads((self.root / 'independent-verification/result.json').read_text())
        self.assertEqual(result['checks'], [])
        self.assertEqual(len(result['skippedFailedCases']), 1)

    def test_oracle_crash_does_not_count_as_negative_rejection(self):
        self.successful_case()

        def crashing_oracle(command, **kwargs):
            if 'public-wrong-' in command[-2]:
                return SimpleNamespace(returncode=1, stdout='', stderr='Unrelated runtime exception')
            return self.mock_oracle(command, **kwargs)

        with patch.object(bench.subprocess, 'run', side_effect=crashing_oracle):
            with self.assertRaisesRegex(RuntimeError, 'Independent verification failed'):
                bench.verify(self.root, self.cli, allow_failed=True)
        result = json.loads((self.root / 'independent-verification/result.json').read_text())
        self.assertFalse(result['checks'][-1]['passed'])
        self.assertFalse(result['checks'][-1]['expectedValid'])


if __name__ == '__main__':
    unittest.main()
