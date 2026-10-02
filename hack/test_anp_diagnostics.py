#!/usr/bin/env python3
"""Isolated regression tests for diagnostic evidence and verdict preservation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import anp_diagnostics as diagnostics

COMMAND = 'FAILED Command was [/agnhost connect --timeout=3s --protocol=tcp [fd00:10:16::12]:80]'
EXPECTED = 'Expected connection to fail from network-policy-conformance-gryffindor/harry-potter-0 to fd00:10:16::12, but instead it successfully connected.'


class OfflineRecorder(diagnostics.Recorder):
    def __init__(self, output):
        inventory = {'items': [{'metadata': {'name': name}, 'spec': {'nodeName': name, 'containers': [{'name': 'openvswitch'}]}} for name in ['node1', 'node2']]}
        with patch.object(diagnostics, 'command', return_value={'returncode': 0, 'stdout': json.dumps(inventory)}):
            super().__init__(output, interval=1, window=2)

    def snapshot(self, destination):
        destination.mkdir(parents=True, exist_ok=True)
        diagnostics.write_json(destination / 'snapshot.json', {'finished': diagnostics.timestamp(), 'failed_commands': []})
        self.snapshot_count += 1
        self.complete_snapshots += 1

    def audit(self):
        self.audit_count = 1
        self.audit_ready.set()
        self.stop.wait()

    def conntrack(self, probe, destination):
        pass


class DiagnosticTests(unittest.TestCase):
    def test_ipv6_probe_uses_original_client_container(self):
        probe = diagnostics.parse_probe(COMMAND, EXPECTED)
        self.assertEqual(probe['container'], 'harry-potter-client')
        self.assertEqual(probe['target'], 'fd00:10:16::12')
        self.assertFalse(probe['expected_connect'])
        self.assertEqual(probe['command'][-1], '[fd00:10:16::12]:80')

    def test_malformed_and_non_agnhost_commands_are_rejected(self):
        for args in ['sh -c evil', '/agnhost connect --timeout=3s --protocol=tcp example.org:80', '/agnhost connect --timeout=3s --protocol=tcp 1.2.3.4:99999', '/agnhost connect --timeout=3s --protocol=tcp "', '/agnhost connect --timeout=3s --protocol=tcp invalid']:
            self.assertIsNone(diagnostics.parse_probe('FAILED Command was [' + args + ']', EXPECTED))

    def test_exec_errors_are_not_denial_evidence(self):
        for code, stderr in [(-1, 'TIMEOUT'), (1, 'Error from server: TIMEOUT'), (1, 'container not found'), (137, 'TIMEOUT')]:
            self.assertEqual(diagnostics.probe_outcome({'returncode': code, 'stdout': '', 'stderr': stderr}), 'command_error_or_other_rejection')
        self.assertEqual(diagnostics.probe_outcome({'returncode': 1, 'stdout': '', 'stderr': 'TIMEOUT\ncommand terminated with exit code 1'}), 'dropped')

    def test_successful_additional_probes_preserve_original_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = OfflineRecorder(Path(temp))
            code = 'print(' + repr(COMMAND) + '); print(' + repr(EXPECTED) + '); raise SystemExit(7)'
            with patch.object(diagnostics, 'command', return_value={'returncode': 0, 'stdout': '', 'stderr': ''}), patch.object(diagnostics.time, 'sleep'):
                self.assertEqual(recorder.run([sys.executable, '-c', code]), 7)
            incident = Path(temp) / 'incidents/failure-001'
            self.assertTrue((incident / 'before/initial/snapshot.json').exists())
            self.assertTrue((incident / 'immediate/snapshot.json').exists())
            self.assertTrue((incident / 'after-probes/snapshot.json').exists())
            self.assertEqual(len(json.loads((incident / 'additional-probes.json').read_text())), 3)
            self.assertEqual(json.loads((Path(temp) / 'summary.json').read_text())['suite_returncode'], 7)

    def test_incomplete_collection_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = OfflineRecorder(Path(temp))
            self.assertEqual(recorder.run([sys.executable, '-c', 'print("no suite cases")']), 2)
            self.assertFalse(json.loads((Path(temp) / 'summary.json').read_text())['diagnostics_healthy'])

    def test_complete_suite_and_collection_can_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = OfflineRecorder(Path(temp))
            lines = ['--- PASS: TestAdminNetworkPolicyConformance/%s (0.00s)' % name for name in sorted(diagnostics.STANDARD_CASES)]
            lines += ['--- SKIP: TestAdminNetworkPolicyConformance/%s (0.00s)' % name for name in ['AdminNetworkPolicyEgressNamedPort', 'AdminNetworkPolicyEgressNodePeers', 'AdminNetworkPolicyIngressNamedPort', 'BaselineAdminNetworkPolicyEgressNamedPort', 'BaselineAdminNetworkPolicyEgressNodePeers', 'BaselineAdminNetworkPolicyIngressNamedPort']]
            code = 'print(' + repr('\n'.join(lines)) + ')'
            self.assertEqual(recorder.run([sys.executable, '-c', code]), 0)
            self.assertTrue(json.loads((Path(temp) / 'summary.json').read_text())['diagnostics_healthy'])

    def test_skipped_standard_case_cannot_pass_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = OfflineRecorder(Path(temp))
            names = sorted(diagnostics.STANDARD_CASES)
            lines = ['--- %s: TestAdminNetworkPolicyConformance/%s (0.00s)' % ('SKIP' if n == 0 else 'PASS', name) for n, name in enumerate(names)]
            self.assertEqual(recorder.run([sys.executable, '-c', 'print(' + repr('\n'.join(lines)) + ')']), 2)
            self.assertFalse(json.loads((Path(temp) / 'summary.json').read_text())['coverage_complete'])

    def test_failed_snapshot_commands_are_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = OfflineRecorder(Path(temp))
            recorder.complete_snapshots = 0
            with patch.object(diagnostics, 'command', return_value={'returncode': 1, 'stdout': '', 'stderr': 'unknown column'}):
                diagnostics.Recorder.snapshot(recorder, Path(temp) / 'broken')
            self.assertEqual(recorder.complete_snapshots, 0)
            self.assertIn('sb-logical-flows', json.loads((Path(temp) / 'broken/snapshot.json').read_text())['failed_commands'])
            recorder.workers.shutdown()

    def test_missing_suite_executable_still_writes_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = OfflineRecorder(Path(temp))
            self.assertEqual(recorder.run(['/does/not/exist']), 125)
            self.assertTrue(json.loads((Path(temp) / 'summary.json').read_text())['collector_errors'])

    def test_guard_rejects_non_ci(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false'}), patch.object(sys, 'argv', ['collector', '--output', '/tmp/unused', '--', 'true']):
            with self.assertRaises(SystemExit) as caught:
                diagnostics.main()
            self.assertEqual(caught.exception.code, 2)


class TraceTests(unittest.TestCase):
    def test_trace_preserves_output_and_stops_its_process(self):
        with tempfile.TemporaryDirectory() as temp:
            trace = diagnostics.Trace(Path(temp) / 'trace', [sys.executable, '-u', '-c', 'import time; print("flow update"); time.sleep(30)'])
            trace.start()
            self.assertTrue(trace.ready.wait(timeout=2))
            result = trace.close()
            self.assertTrue(result['healthy'])
            record = json.loads((Path(temp) / 'trace.jsonl').read_text())
            self.assertEqual(record['text'], 'flow update')
            self.assertIn('observed', record)
            self.assertIsNotNone(trace.proc.poll())

    def test_early_trace_exit_cannot_be_healthy(self):
        with tempfile.TemporaryDirectory() as temp:
            trace = diagnostics.Trace(Path(temp) / 'trace', [sys.executable, '-c', 'print("unsupported command"); raise SystemExit(7)'])
            trace.start()
            trace.thread.join(timeout=2)
            result = trace.close()
            self.assertFalse(result['healthy'])
            self.assertTrue(result['ended_early'])
            self.assertEqual(result['returncode'], 7)

    def test_output_limit_is_explicit_and_bounds_file_size(self):
        with tempfile.TemporaryDirectory() as temp:
            trace = diagnostics.Trace(Path(temp) / 'trace', [sys.executable, '-c', 'print("x" * 200)'], limit=50)
            trace.start()
            trace.thread.join(timeout=2)
            result = trace.close()
            self.assertGreater(result['bytes_observed'], result['byte_limit'])
            self.assertLessEqual((Path(temp) / 'trace.jsonl').stat().st_size, 50)
            self.assertFalse(result['healthy'])


if __name__ == '__main__':
    unittest.main()
