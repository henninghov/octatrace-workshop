import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
OPERATOR = '11111111-1111-4111-8111-111111111111'
spec = importlib.util.spec_from_file_location('firmware_test_adapter', ROOT / 'tools/firmware_test_adapter.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class FirmwareTestAdapterTest(unittest.TestCase):
    def setUp(self):
        (ROOT / 'build').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'firmware'
        (self.root / 'tools').mkdir(parents=True)
        (self.root / 'build').mkdir()
        (self.root / 'marker').write_text('original')
        host = '''import hashlib,json,pathlib\nROOT=pathlib.Path(__file__).resolve().parents[1]\ndef source_id(): return hashlib.sha256((ROOT/'marker').read_bytes()).hexdigest(),{}\nif __name__=='__main__':\n p=ROOT/'build/host/synthetic/results.json'; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps({'source_id':source_id()[0],'result':'pass'})); print(json.dumps({'host_report':str(p)}))\n'''
        catalog = '''import json,pathlib\nfrom test_host import source_id\nroot=pathlib.Path(__file__).resolve().parents[1]\ncases=['case.one'] if (root/'missing').exists() else ['case.one','case.two']\nprint(json.dumps({'source_id':source_id()[0],'python_case_ids':cases}))\n'''
        tooling = '''import json,pathlib,sys\nfrom test_host import source_id\nroot=pathlib.Path(__file__).resolve().parents[1]\n(root/'build/runner-started').write_text('yes')\nsource=source_id()[0]\nif (root/'fail').exists(): print('synthetic failure');sys.exit(7)\nif (root/'drift').exists(): (root/'marker').write_text('changed')\np=root/'build/tooling'/source/'results.json';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps({'source_id':source,'result':'pass','tests':2}));print('synthetic pass')\n'''
        for name, body in [('test_host.py', host), ('firmware_test_catalog.py', catalog), ('test_tooling.py', tooling)]:
            (self.root / 'tools' / name).write_text(body)
        pins = {f'tools/{name}': adapter.file_hash(self.root / 'tools' / name)
                for name in ['test_host.py', 'firmware_test_catalog.py', 'test_tooling.py']}
        self.definition = {'key': 'firmware-host-regression', 'revision': 1,
                           'runner_pins': pins, 'baseline_python_case_ids': ['case.one', 'case.two']}
        self.fonts = self.base / 'fonts'
        self.fonts.mkdir()
        self.counter = 0

    def run_attempt(self, suite='tooling'):
        self.counter += 1
        attempt = self.base / ('00000000-0000-4000-8000-' + str(self.counter).zfill(12))
        digest = adapter.hashlib.sha256((json.dumps(self.definition, indent=2) + '\n').encode()).hexdigest()
        result = adapter.execute(self.root, Path(sys.executable), self.fonts, suite,
                                 self.definition, digest, attempt, OPERATOR, 'c' * 64)
        self.assertTrue((attempt / 'started.json').is_file())
        self.assertEqual(json.loads((attempt / 'completed.json').read_text()), result)
        self.assertEqual((attempt.stat().st_mode & 0o777), 0o700)
        return result, attempt

    def test_both_fixed_suites_run_and_keep_source_bound_reports(self):
        for suite in ['tooling', 'host']:
            result, attempt = self.run_attempt(suite)
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(result['id'], attempt.name)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['discovered_python_cases'], 2)
            self.assertEqual(result['log_sha256'], adapter.file_hash(attempt / 'output.log'))
            self.assertIn('no device', result['scope'])

    def test_tooling_receives_the_selected_font_directory(self):
        runner = self.root / 'tools/test_tooling.py'
        runner.write_text('import os,pathlib\n' +
                          '(pathlib.Path(__file__).resolve().parents[1]/"font-path").write_text(os.environ.get("OCTATRACE_FIRMWARE_FONTS", ""))\n' +
                          runner.read_text())
        self.definition['runner_pins']['tools/test_tooling.py'] = adapter.file_hash(runner)
        result, _ = self.run_attempt()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual((self.root / 'font-path').read_text(), str(self.fonts.resolve()))

    def test_inherited_python_and_compiler_overrides_cannot_disable_checks(self):
        runner = self.root / 'tools/test_tooling.py'
        runner.write_text('import os,sys,pathlib\n' +
                          '(pathlib.Path(__file__).resolve().parents[1]/"environment").write_text(str(sys.flags.optimize)+":"+str(os.environ.get("GCC_EXEC_PREFIX")))\n' +
                          runner.read_text())
        self.definition['runner_pins']['tools/test_tooling.py'] = adapter.file_hash(runner)
        with mock.patch.dict(os.environ, {'PYTHONOPTIMIZE': '1', 'GCC_EXEC_PREFIX': '/untrusted'}):
            result, _ = self.run_attempt()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual((self.root / 'environment').read_text(), '0:None')

    def test_contract_qualification_saves_source_bound_evidence(self):
        host = self.root / 'tools/test_host.py'
        host.write_text('import hashlib,json,pathlib\nROOT=pathlib.Path(__file__).resolve().parents[1]\n'
                        'def source_id():\n d={"marker":hashlib.sha256((ROOT/"marker").read_bytes()).hexdigest()}\n return hashlib.sha256(json.dumps(d,sort_keys=True).encode()).hexdigest(),d\n')
        self.definition['runner_pins']['tools/test_host.py'] = adapter.file_hash(host)
        runner = self.root / 'tools/check_claim_qr.py'
        runner.write_text('import hashlib,json,pathlib\nfrom test_host import ROOT,source_id\n'
                          'source,files=source_id()\nidentity=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()\n'
                          'p=ROOT/"build/claim-qr"/identity/"results.json"\np.parent.mkdir(parents=True,exist_ok=True)\n'
                          'p.write_text(json.dumps({"result":"pass","contract_input_id":identity,"source_files":files}))\n'
                          'print(json.dumps({"result":"pass","report":str(p)}))\n')
        self.definition['runner_pins']['tools/check_claim_qr.py'] = adapter.file_hash(runner)
        self.definition['revision'] = 2
        result, attempt = self.run_attempt('claimQr')
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(adapter.file_hash(attempt / 'source-inputs.json'), result['firmware_source_id'])
        self.assertEqual(json.loads((attempt / 'runner-report.json').read_text())['result'], 'pass')

    def test_qualification_report_must_match_inputs_and_reviewed_location(self):
        files = {'marker': adapter.file_hash(self.root / 'marker')}
        digest = adapter.hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        report = self.root / 'build/claim-qr' / digest / 'results.json'
        report.parent.mkdir(parents=True)
        report.write_text(json.dumps({'result': 'pass', 'source_files': files, 'contract_input_id': digest}))
        log = self.base / 'output.log'
        log.write_text(json.dumps({'result': 'pass', 'report': str(report)}))
        self.assertEqual(adapter.check_owner_report(self.root, self.base, 'claimQr', log, digest, files), report)
        with self.assertRaisesRegex(ValueError, 'inputs differ'):
            adapter.check_owner_report(self.root, self.base, 'claimQr', log, digest, {'marker': 'changed'})
        report.write_text(json.dumps({'result': 'pass', 'source_files': files, 'contract_input_id': 'changed'}))
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            adapter.check_owner_report(self.root, self.base, 'claimQr', log, digest, files)
        log.write_text(json.dumps({'result': 'pass', 'report': str(self.base / 'other/results.json')}))
        with self.assertRaisesRegex(ValueError, 'outside'):
            adapter.check_owner_report(self.root, self.base, 'claimQr', log, digest, files)

    def test_reopening_and_export_reject_symlinked_evidence(self):
        result, attempt = self.run_attempt()
        output = attempt / 'output.log'
        saved = self.base / 'saved-output'
        saved.write_bytes(output.read_bytes())
        output.unlink()
        output.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            adapter.inspect_attempt(attempt, result['definition_sha256'], OPERATOR)
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            adapter.export_attempt(attempt, self.base / 'export.json', result['definition_sha256'], OPERATOR)

    def test_session_qualification_requires_all_cases_controls_and_coverage(self):
        output = self.base / 'qualification'
        output.mkdir()
        for case in adapter.SESSION_CASES:
            (output / (case + '.log')).write_text('PASS session ' + case)
        for number in range(9):
            folder = output / ('negative-' + str(number) + '-case')
            folder.mkdir()
            (folder / 'result.log').write_text('runtime_error')
        coverage = {str(i): {'lines': {'percent': 100}, 'branches': {'count': 2, 'percent': 100}} for i in range(15)}
        (output / 'coverage-summary.json').write_text(json.dumps(coverage))
        result = {'wire': 'passed', 'journal': 'passed', 'participant': 'passed', 'coordinator': 'passed',
                  'negative_controls': 9, 'runtime_integration': 'not run', 'physical': 'not run', 'coverage': coverage}
        log = self.base / 'output.log'
        lines = ['PASS session ' + name for name in adapter.SESSION_CASES]
        log.write_text('\n'.join(lines + [json.dumps(result)]))
        report = adapter.check_owner_report(self.root, self.base, 'sessionControl', log, 'a' * 64, {})
        self.assertEqual(json.loads(report.read_text())['negative_controls'], 9)
        self.assertTrue((self.base / 'qualification-evidence.json').is_file())
        (output / 'negative-0-case/result.log').unlink()
        with self.assertRaisesRegex(ValueError, 'negative-control evidence'):
            adapter.check_owner_report(self.root, self.base, 'sessionControl', log, 'a' * 64, {})
        coverage['0']['lines']['percent'] = 90
        log.write_text('\n'.join(lines + [json.dumps(result)]))
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            adapter.check_owner_report(self.root, self.base, 'sessionControl', log, 'a' * 64, {})

    def test_field_prerequisites_reject_unbound_or_redirected_reports(self):
        source = 'a' * 64
        for name in ('field-authentication', 'field-transport', 'handshake-crypto-host'):
            folder = self.root / 'build' / name / 'run'
            folder.mkdir(parents=True)
            report = {'source_id': source, 'result': 'pass'}
            if name == 'field-authentication':
                upstream = folder / 'libedhoc-2.3.3'
                upstream.mkdir()
                sources = {}
                for i in range(62):
                    file = upstream / (str(i) + '.c')
                    file.write_text('source')
                    sources[file.name] = adapter.file_hash(file)
                archive = folder / 'core.a'
                archive.write_text('archive')
                objects = {}
                for name in ('context_view.o', 'context_view_test.o'):
                    path = folder / name
                    path.write_text('object')
                    objects[name] = adapter.file_hash(path)
                report.update({'compiled_vendor_sources': sources, 'core_archive_sha256': adapter.file_hash(archive), 'host_objects_sha256': objects})
            (folder / 'results.json').write_text(json.dumps(report))
            (folder.parent / 'latest.json').write_text(json.dumps({'path': str(folder)}))
        adapter.field_prerequisites(self.root, source)
        latest = self.root / 'build/field-transport/latest.json'
        latest.write_text(json.dumps({'path': str(self.base)}))
        with self.assertRaisesRegex(ValueError, 'outside'):
            adapter.field_prerequisites(self.root, source)
        latest.write_text(json.dumps({'path': str(latest.parent / 'run')}))
        with self.assertRaisesRegex(ValueError, 'different source'):
            adapter.field_prerequisites(self.root, 'b' * 64)
        object_file = self.root / 'build/field-authentication/run/context_view.o'
        object_file.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'object differs'):
            adapter.field_prerequisites(self.root, source)
        object_file.write_text('object')
        (self.root / 'build/field-authentication/run/libedhoc-2.3.3/0.c').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'vendor source differs'):
            adapter.field_prerequisites(self.root, source)

    def test_changed_runner_and_missing_baseline_block_before_tests(self):
        (self.root / 'tools/test_tooling.py').write_text('changed')
        result, _ = self.run_attempt()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('reviewed definition', result['reason'])
        self.assertFalse((self.root / 'build/runner-started').exists())
        self.definition['runner_pins']['tools/test_tooling.py'] = adapter.file_hash(self.root / 'tools/test_tooling.py')
        (self.root / 'missing').touch()
        result, _ = self.run_attempt()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('baseline cases are missing', result['reason'])
        self.assertFalse((self.root / 'build/runner-started').exists())

    def test_failure_and_source_drift_are_not_passes(self):
        (self.root / 'fail').touch()
        result, attempt = self.run_attempt()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['exit_code'], 7)
        self.assertIn('synthetic failure', (attempt / 'output.log').read_text())
        (self.root / 'fail').unlink()
        (self.root / 'drift').touch()
        result, _ = self.run_attempt()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('source changed', result['reason'])

    def test_lock_existing_attempt_and_missing_parent_stop_work(self):
        lock = (self.root / 'build/.workshop-host-test.lock').open('a')
        self.addCleanup(lock.close)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result, attempt = self.run_attempt()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('already running', result['reason'])
        self.assertFalse((self.root / 'build/runner-started').exists())
        digest = adapter.hashlib.sha256((json.dumps(self.definition, indent=2) + '\n').encode()).hexdigest()
        with self.assertRaises(FileExistsError):
            adapter.execute(self.root, Path(sys.executable), self.fonts, 'tooling', self.definition, digest, attempt, OPERATOR, 'c' * 64)
        with self.assertRaises(FileNotFoundError):
            adapter.execute(self.root, Path(sys.executable), self.fonts, 'tooling', self.definition, digest, self.base / 'absent' / 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', OPERATOR, 'c' * 64)
        with self.assertRaises(ValueError):
            adapter.execute(self.root, Path(sys.executable), self.fonts, 'unknown', self.definition, 'digest', self.base / 'unused', OPERATOR, 'c' * 64)
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            adapter.execute(self.root, Path(sys.executable), self.fonts, 'tooling', self.definition, digest, self.base / 'unused', OPERATOR, 'invalid')
        with self.assertRaisesRegex(ValueError, 'Attempt UUID'):
            adapter.execute(self.root, Path(sys.executable), self.fonts, 'tooling', self.definition, digest, self.base / 'invalid-attempt', OPERATOR, 'c' * 64)

    def test_failed_local_save_and_missing_fonts_do_not_start_tests(self):
        digest = adapter.hashlib.sha256((json.dumps(self.definition, indent=2) + '\n').encode()).hexdigest()
        with mock.patch.object(adapter, 'publish', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                adapter.execute(self.root, Path(sys.executable), self.fonts, 'tooling', self.definition, digest, self.base / 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', OPERATOR, 'c' * 64)
        self.assertFalse((self.root / 'build/runner-started').exists())
        result = adapter.execute(self.root, Path(sys.executable), None, 'host', self.definition, digest, self.base / 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', OPERATOR, 'c' * 64)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('font directory', result['reason'])

    def test_cancel_terminates_the_test_process_and_retains_outcome(self):
        tooling = self.root / 'tools/test_tooling.py'
        tooling.write_text('import pathlib,time\np=pathlib.Path(__file__).resolve().parents[1]/"build/runner-started"\np.write_text("running")\ntime.sleep(60)\n')
        self.definition['runner_pins']['tools/test_tooling.py'] = adapter.file_hash(tooling)
        definition = self.base / 'definition.json'
        definition.write_text(json.dumps(self.definition))
        attempt = self.base / 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
        code = ('import importlib.util,json,pathlib,sys; '
                's=importlib.util.spec_from_file_location("adapter",sys.argv[1]); '
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m); '
                'd=json.loads(pathlib.Path(sys.argv[4]).read_text()); '
                'h=m.hashlib.sha256((json.dumps(d,indent=2)+"\\n").encode()).hexdigest(); '
                'm.execute(pathlib.Path(sys.argv[2]),pathlib.Path(sys.executable),None,"tooling",d,h,pathlib.Path(sys.argv[3]),"11111111-1111-4111-8111-111111111111","c"*64)')
        child = subprocess.Popen([sys.executable, '-B', '-c', code,
                                  str(ROOT / 'tools/firmware_test_adapter.py'),
                                  str(self.root), str(attempt), str(definition)])
        try:
            marker = self.root / 'build/runner-started'
            deadline = time.monotonic() + 10
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists(), 'Synthetic test did not start')
            child.send_signal(signal.SIGTERM)
            self.assertEqual(child.wait(timeout=10), 0)
            result = json.loads((attempt / 'completed.json').read_text())
            self.assertEqual(result['status'], 'cancelled')
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_reopen_export_detects_changed_evidence_and_keeps_attempt(self):
        result, attempt = self.run_attempt()
        digest = result['definition_sha256']
        self.assertEqual(adapter.inspect_attempt(attempt, digest)['status'], 'passed')
        with self.assertRaisesRegex(ValueError, 'Invalid saved firmware attempt'):
            adapter.inspect_attempt(attempt, digest, '22222222-2222-4222-8222-222222222222')
        export = self.base / 'report.json'
        saved = adapter.export_attempt(attempt, export, digest)
        self.assertEqual(saved['sha256'], adapter.file_hash(export))
        self.assertEqual(json.loads(export.read_text())['report']['id'], result['id'])
        self.assertEqual(json.loads(export.read_text())['report']['operator'], OPERATOR)
        self.assertEqual(json.loads(export.read_text())['report']['workshop_fingerprint'], 'c' * 64)
        with self.assertRaisesRegex(ValueError, 'Invalid saved firmware attempt'):
            adapter.export_attempt(attempt, self.base / 'other.json', digest,
                                   '22222222-2222-4222-8222-222222222222')
        with self.assertRaises(FileExistsError):
            adapter.export_attempt(attempt, export, digest)
        (attempt / 'output.log').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'evidence differs'):
            adapter.inspect_attempt(attempt, digest)
        self.assertTrue((attempt / 'completed.json').exists())

    def test_unfinished_attempt_reopens_as_interrupted(self):
        result, attempt = self.run_attempt()
        (attempt / 'completed.json').unlink()
        self.assertEqual(adapter.inspect_attempt(attempt, result['definition_sha256'])['status'], 'incomplete')

    def test_child_holds_lock_if_supervisor_is_killed(self):
        tooling = self.root / 'tools/test_tooling.py'
        tooling.write_text('import os,pathlib,time\np=pathlib.Path(__file__).resolve().parents[1]/"build/runner-started"\np.write_text(str(os.getpid()))\ntime.sleep(60)\n')
        self.definition['runner_pins']['tools/test_tooling.py'] = adapter.file_hash(tooling)
        definition = self.base / 'orphan-definition.json'
        definition.write_text(json.dumps(self.definition))
        attempt = self.base / 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
        code = ('import importlib.util,json,pathlib,sys; '
                's=importlib.util.spec_from_file_location("adapter",sys.argv[1]); '
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m); '
                'd=json.loads(pathlib.Path(sys.argv[4]).read_text()); '
                'h=m.hashlib.sha256((json.dumps(d,indent=2)+"\\n").encode()).hexdigest(); '
                'm.execute(pathlib.Path(sys.argv[2]),pathlib.Path(sys.executable),None,"tooling",d,h,pathlib.Path(sys.argv[3]),"11111111-1111-4111-8111-111111111111","c"*64)')
        child = subprocess.Popen([sys.executable, '-B', '-c', code,
                                  str(ROOT / 'tools/firmware_test_adapter.py'),
                                  str(self.root), str(attempt), str(definition)])
        runner_pid = None
        try:
            marker = self.root / 'build/runner-started'
            deadline = time.monotonic() + 10
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists(), 'Synthetic test did not start')
            while time.monotonic() < deadline:
                value = marker.read_text().strip()
                if value:
                    runner_pid = int(value)
                    break
                time.sleep(0.01)
            self.assertIsNotNone(runner_pid)
            child.kill()
            child.wait(timeout=5)
            result, _ = self.run_attempt()
            self.assertEqual(result['status'], 'failed')
            self.assertIn('already running', result['reason'])
            digest = adapter.hashlib.sha256((json.dumps(self.definition, indent=2) + '\n').encode()).hexdigest()
            self.assertEqual(adapter.inspect_attempt(attempt, digest)['status'], 'incomplete')
        finally:
            if runner_pid:
                try: os.killpg(runner_pid, signal.SIGKILL)
                except ProcessLookupError: pass
            if child.poll() is None:
                child.kill()
                child.wait()


if __name__ == '__main__':
    unittest.main()
