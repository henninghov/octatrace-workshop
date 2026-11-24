#!/usr/bin/env python3
"""Supervise reviewed firmware host suites and retain local attempts."""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

LEGACY_DEFINITION_SHA256 = 'f0ed16d12fb93f643732c4523b0ecd89d389d2d7c92dcbe9a32fc2a32976e476'
SECOND_DEFINITION_SHA256 = '4f97b9a13af2497c88e09697d14b8cbbbe4ff5a0c9d255910f9252380c3a5ad5'
THIRD_DEFINITION_SHA256 = '8c4ee9eec754cb991320c85dc788a31ec35686d226cb8cd85c3085927f2a649e'
FOURTH_DEFINITION_SHA256 = '9b7a6672f76c8063ecfd4508eaf14d654ed0368243191a2be1bd833381ff2144'
FIFTH_DEFINITION_SHA256 = '3a683438374cdde4251e1e6fb7fa588f450b8aa8a9ef6674b06d77dffe615369'
SIXTH_DEFINITION_SHA256 = 'dccff7e6b0ff50cef98efde688ac6d28e79e8680e187b5c70491f49371f54d78'
DEFINITION_SHA256 = '1a13e143fd5639247726a4197625cc241f316e2eb4c00655b427c223777713b8'
CHECKS = {
    'authorityStorage': ('check_authority_storage.py', 'authority-storage'),
    'claimQr': ('check_claim_qr.py', 'claim-qr'),
    'deviceAuthority': ('check_device_authority.py', 'device-authority'),
    'deviceCredential': ('check_device_credential.py', 'device-credential'),
    'fieldHandshake': ('check_field_handshake.py', 'field-handshake'),
    'proofContext': ('check_proof_context.py', 'proof-context'),
    'setupTransfer': ('check_setup_transfer.py', None),
    'sessionControl': ('test_session_control.py', None),
    'authorityResources': ('check_authority_resources.py', 'authority-resources'),
    'fieldResources': ('check_field_resources.py', 'field-resources'),
    'authorityLayout': ('check_authority_layout.py', None),
}
SESSION_CASES = ('wire', 'journal', 'participant', 'coordinator', 'attempt', 'flash',
                 'core_radio', 'link_radio', 'bluetooth', 'phone_channel', 'phone_handler')


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def publish_bytes(path, data):
    staged = path.parent / ('.staged-' + uuid.uuid4().hex)
    try:
        with staged.open('xb') as output:
            os.chmod(staged, 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def publish(path, value):
    publish_bytes(path, json.dumps(value, indent=2).encode() + b'\n')


def load_source(root, pins):
    for relative, expected in pins.items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or file_hash(path) != expected:
            raise ValueError('Firmware runner differs from the reviewed definition: ' + relative)
    spec = importlib.util.spec_from_file_location('reviewed_firmware_test_host', root / 'tools/test_host.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_id()


def load_source_id(root, pins):
    return load_source(root, pins)[0]


def field_prerequisites(root, source):
    """Use only source-matched reports within the selected firmware checkout."""
    folders = {}
    for name in ('field-authentication', 'field-transport', 'handshake-crypto-host'):
        base = (root / 'build' / name).resolve()
        latest = root / 'build' / name / 'latest.json'
        if not base.is_relative_to(root) or latest.is_symlink() or not latest.is_file():
            raise ValueError('Run the firmware native host suite for this source before field resources')
        candidate = Path(json.loads(latest.read_text())['path'])
        if (not candidate.is_absolute() or candidate.is_symlink() or
                not candidate.resolve().is_relative_to(base)):
            raise ValueError('Field prerequisite report is outside the firmware checkout')
        folder = candidate.resolve()
        report = folder / 'results.json'
        if report.is_symlink() or not report.is_file():
            raise ValueError('Field prerequisite report is missing or redirected')
        data = json.loads(report.read_text())
        if data.get('result') != 'pass' or data.get('source_id') != source:
            raise ValueError('Field prerequisite report belongs to a different source')
        folders[name] = (folder, data)
    auth, report = folders['field-authentication']
    upstream = auth / 'libedhoc-2.3.3'
    if upstream.is_symlink() or not upstream.is_dir() or not upstream.resolve().is_relative_to(auth):
        raise ValueError('Field prerequisite source directory is missing or redirected')
    archive = auth / 'core.a'
    if archive.is_symlink() or not archive.is_file() or file_hash(archive) != report.get('core_archive_sha256'):
        raise ValueError('Field prerequisite archive differs')
    objects = report.get('host_objects_sha256')
    if not isinstance(objects, dict) or set(objects) != {'context_view.o', 'context_view_test.o'}:
        raise ValueError('Field prerequisite object inventory differs')
    for name, digest in objects.items():
        path = auth / name
        if path.is_symlink() or not path.is_file() or file_hash(path) != digest:
            raise ValueError('Field prerequisite object differs')
    sources = report.get('compiled_vendor_sources')
    if not isinstance(sources, dict) or len(sources) != 62:
        raise ValueError('Field prerequisite vendor source inventory differs')
    for name, digest in sources.items():
        path = upstream / name
        if (Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or
                not path.is_file() or not path.resolve().is_relative_to(upstream) or file_hash(path) != digest):
            raise ValueError('Field prerequisite vendor source differs')


def check_owner_report(root, attempt, suite, log, source, inputs):
    """Accept only the selected runner's report, bound to this source inventory."""
    if suite == 'sessionControl':
        lines = log.read_text(errors='strict').splitlines()
        result = json.loads(lines[-1])
        passed = [line for line in lines if line.startswith('PASS session ')]
        if (len(passed) != len(SESSION_CASES) or len(set(passed)) != len(SESSION_CASES) or
                result.get('negative_controls') != 9 or
                result.get('runtime_integration') != 'not run' or result.get('physical') != 'not run' or
                any(result.get(name) != 'passed' for name in ('wire', 'journal', 'participant', 'coordinator'))):
            raise ValueError('Session qualification did not complete all required checks')
        coverage = result.get('coverage')
        if (not isinstance(coverage, dict) or len(coverage) != 15 or
                any(row['lines']['percent'] != 100 or
                    (row['branches']['count'] and row['branches']['percent'] < 95)
                    for row in coverage.values())):
            raise ValueError('Session qualification coverage differs')
        output = attempt / 'qualification'
        paths = [output / (case + '.log') for case in SESSION_CASES]
        negatives = sorted(output.glob('negative-*/result.log'))
        if len(negatives) != 9:
            raise ValueError('Session negative-control evidence is incomplete')
        paths += negatives + [output / 'coverage-summary.json']
        artifacts = {str(path.relative_to(output)): path.read_text() for path in paths
                     if path.is_file() and not path.is_symlink()}
        if len(artifacts) != len(paths):
            raise ValueError('Session evidence is missing or redirected')
        if (any(not artifacts[case + '.log'].startswith('PASS session ') for case in SESSION_CASES) or
                any('runtime_error' not in artifacts[str(path.relative_to(output))] for path in negatives) or
                json.loads(artifacts['coverage-summary.json']) != coverage):
            raise ValueError('Session evidence does not match the owner result')
        content = json.dumps(artifacts, sort_keys=True).encode()
        publish_bytes(attempt / 'qualification-evidence.json', content)
        report = output / 'results.json'
        publish(report, {'result': 'pass', 'source_id': source, 'case_pass_lines': passed,
                         'coverage': coverage, 'negative_controls': 9,
                         'runtime_integration': 'not run', 'physical': 'not run',
                         'qualification_evidence_sha256': hashlib.sha256(content).hexdigest()})
        return report
    item = json.loads(log.read_text(errors='strict').splitlines()[-1])
    report = Path(item['report']).resolve()
    output = attempt / 'qualification' if suite in {'setupTransfer', 'authorityLayout'} else root / 'build' / CHECKS[suite][1]
    output = output.resolve()
    if not report.is_relative_to(output) or report.name != 'results.json':
        raise ValueError('Qualification report is outside its reviewed output')
    evidence = json.loads(report.read_text())
    if item.get('result') != 'pass' or evidence.get('result') != 'pass':
        raise ValueError('Firmware qualification did not pass')
    files = evidence.get('source_files_sha256' if suite == 'setupTransfer' else 'source_files')
    if not isinstance(files, dict) or not files or any(inputs.get(k) != v for k, v in files.items()):
        raise ValueError('Qualification inputs differ from the firmware source')
    if suite in {'fieldHandshake', 'fieldResources', 'authorityResources', 'authorityLayout'}:
        if evidence.get('source_id') != source:
            raise ValueError('Qualification source differs')
    elif suite != 'setupTransfer':
        digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        if evidence.get('contract_input_id') != digest or report.parent.name != digest:
            raise ValueError('Qualification contract identity differs')
    return report


def execute(root, python, fonts, suite, definition, definition_hash, attempt, operator, workshop_fingerprint):
    """Execute only a fixed suite, with an independently saved start/result."""
    if suite not in {'tooling', 'host', *CHECKS}:
        raise ValueError('Unknown firmware test suite')
    if not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', operator):
        raise ValueError('Operator UUID required')
    if not re.fullmatch(r'[0-9a-f]{64}', workshop_fingerprint):
        raise ValueError('Workshop bundle fingerprint required')
    if (definition.get('key') != 'firmware-host-regression' or
            definition.get('revision') not in {1, 2, 3, 4, 5, 6, 7} or
            (suite in CHECKS and definition.get('revision') < 2) or
            (suite == 'sessionControl' and definition.get('revision') < 3) or
            (suite in {'authorityResources', 'fieldResources'} and definition.get('revision') < 4) or
            (suite == 'authorityLayout' and definition.get('revision') < 6)):
        raise ValueError('Unexpected firmware test definition')
    definition_bytes = json.dumps(definition, indent=2).encode() + b'\n'
    if hashlib.sha256(definition_bytes).hexdigest() != definition_hash:
        raise ValueError('Firmware test definition digest mismatch')
    root, python, attempt = root.resolve(), python.absolute(), attempt.absolute()
    if not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', attempt.name):
        raise ValueError('Attempt UUID required')
    if attempt.exists():
        raise FileExistsError('Attempt already exists')
    attempt.mkdir(mode=0o700, parents=False)
    run_id = attempt.name
    started = {'format': 1, 'id': run_id, 'operator': operator, 'suite': suite, 'status': 'running',
               'workshop_fingerprint': workshop_fingerprint,
               'definition_sha256': definition_hash, 'started_unix': time.time(),
               'scope': 'Host checks only; no device or physical result'}
    publish(attempt / 'started.json', started)
    result = dict(started)
    process = None
    cancelled = False
    prior_handler = signal.getsignal(signal.SIGTERM)

    def cancel(_signum, _frame):
        nonlocal cancelled
        cancelled = True
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def run_logged(command, log, run_environment=None):
        nonlocal process
        with log.open('xb') as output:
            os.chmod(log, 0o600)
            process = subprocess.Popen(command, cwd=root, env=run_environment or environment, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       pass_fds=(lock.fileno(),))
            deadline = time.monotonic() + 1800
            while process.poll() is None:
                if cancelled:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                    break
                if time.monotonic() >= deadline:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise RuntimeError('Firmware test timed out')
                time.sleep(0.1)
            code = process.wait()
            output.flush()
            os.fsync(output.fileno())
        if cancelled:
            raise InterruptedError('Test cancelled')
        return code

    signal.signal(signal.SIGTERM, cancel)
    lock = None
    try:
        publish_bytes(attempt / 'definition.json', definition_bytes)
        adapter_bytes = Path(__file__).read_bytes()
        result['adapter_sha256'] = hashlib.sha256(adapter_bytes).hexdigest()
        publish_bytes(attempt / 'adapter.py', adapter_bytes)
        pins = definition['runner_pins']
        before, inputs = load_source(root, pins)
        result['firmware_source_id'] = before
        if definition['revision'] >= 2:
            source_bytes = json.dumps(inputs, sort_keys=True).encode()
            if hashlib.sha256(source_bytes).hexdigest() != before:
                raise RuntimeError('Firmware source inventory differs')
            publish_bytes(attempt / 'source-inputs.json', source_bytes)
        (root / 'build').mkdir(exist_ok=True)
        lock = (root / 'build/.workshop-host-test.lock').open('a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another firmware host test is already running') from error
        environment = dict(os.environ)
        for key in list(environment):
            if (key in {'PYTHONOPTIMIZE', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONINSPECT',
                        'PYTHONSAFEPATH', 'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH',
                        'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
                        'COVERAGE_FILE', 'COVERAGE_RCFILE', 'COVERAGE_PROCESS_START'} or
                    key.startswith(('DYLD_', 'LD_'))):
                environment.pop(key, None)
        environment['PYTHONNOUSERSITE'] = '1'
        environment['PATH'] = str(python.parent) + os.pathsep + environment.get('PATH', '')
        environment.pop('OCTATRACE_FIRMWARE_FONTS', None)
        if fonts is not None:
            if not fonts.is_dir():
                raise ValueError('A valid licensed font directory is required')
            environment['OCTATRACE_FIRMWARE_FONTS'] = str(fonts.resolve())
        process = subprocess.Popen([str(python), '-B', str(root / 'tools/firmware_test_catalog.py')],
                                   cwd=root, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True,
                                   pass_fds=(lock.fileno(),))
        try:
            catalog_stdout, catalog_stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise RuntimeError('Firmware catalog timed out') from error
        if cancelled:
            raise InterruptedError('Test cancelled')
        if process.returncode:
            raise RuntimeError('Firmware catalog unavailable: ' + catalog_stderr[-4096:])
        inventory = json.loads(catalog_stdout)
        cases = inventory['python_case_ids']
        if inventory['source_id'] != before or set(definition['baseline_python_case_ids']) - set(cases):
            raise RuntimeError('Firmware source changed or baseline cases are missing')
        result['discovered_python_cases'] = len(cases)
        result['catalog_sha256'] = hashlib.sha256(catalog_stdout.encode()).hexdigest()
        publish_bytes(attempt / 'catalog.json', catalog_stdout.encode())
        if cancelled:
            raise InterruptedError('Test cancelled')
        if suite in {'host', 'fieldResources', 'authorityLayout'} and (fonts is None or not fonts.is_dir()):
            raise ValueError('A licensed font directory is required for host tests')
        if suite == 'fieldResources':
            guard_spec = importlib.util.spec_from_file_location('reviewed_compiler_guard', root / 'tools/compile_commands_guard.py')
            guard = importlib.util.module_from_spec(guard_spec)
            guard_spec.loader.exec_module(guard)
            for role in ('link', 'core'):
                guard.reviewed_command(root, before, role)
            prior_log = attempt / 'prerequisite-host.log'
            if run_logged([str(python), '-B', str(root / 'tools/test_host.py'), '--font-dir', str(fonts.resolve())], prior_log):
                raise RuntimeError('Prerequisite host tests failed; see the retained log')
            result['prerequisite_log_sha256'] = file_hash(prior_log)
            last = json.loads(prior_log.read_text().splitlines()[-1])
            prior_report = Path(last['host_report']).resolve()
            if not prior_report.is_relative_to((root / 'build/host').resolve()):
                raise ValueError('Prerequisite host report is outside the firmware checkout')
            prior = json.loads(prior_report.read_text())
            if prior.get('result') != 'pass' or prior.get('source_id') != before or prior.get('cpp_cases_per_role') != 128:
                raise ValueError('Prerequisite host report differs from this source')
            prior_bytes = prior_report.read_bytes()
            result['prerequisite_report_sha256'] = hashlib.sha256(prior_bytes).hexdigest()
            publish_bytes(attempt / 'prerequisite-host-report.json', prior_bytes)
            if load_source_id(root, pins) != before:
                raise RuntimeError('Firmware source changed during prerequisite tests')
            field_prerequisites(root, before)
        if suite == 'authorityLayout':
            guard_spec = importlib.util.spec_from_file_location('reviewed_compiler_guard', root / 'tools/compile_commands_guard.py')
            guard = importlib.util.module_from_spec(guard_spec)
            guard_spec.loader.exec_module(guard)
            for role in ('link', 'core'):
                guard.reviewed_command(root, before, role)
            coverage_path = attempt / 'layout-coverage.data'
            coverage_environment = dict(environment, COVERAGE_FILE=str(coverage_path))
            include = ','.join(str(root / name) for name in ('tools/build_firmware.py', 'tools/provision_platform.py',
                              'tools/provision_preparation.py', 'tools/control_storage_manifest.py'))
            tests_log = attempt / 'layout-tests.log'
            tests_command = [str(python), '-B', '-m', 'coverage', 'run', '--branch', '--include=' + include,
                             '-m', 'unittest', 'discover', '-s', str(root / 'tests'), '-p', 'test_*.py', '-v']
            if run_logged(tests_command, tests_log, coverage_environment):
                raise RuntimeError('Layout prerequisite tests failed; see the retained log')
            summaries = re.findall(r'Ran (\d+) tests', tests_log.read_text(errors='replace'))
            if not summaries or int(summaries[-1]) != len(cases) or 'skipped=' in tests_log.read_text(errors='replace'):
                raise RuntimeError('Layout prerequisite tests are incomplete')
            build_environment = dict(coverage_environment, PYTHONPATH=str(root / 'tools'))
            build_log = attempt / 'layout-build.log'
            build_command = [str(python), '-B', '-m', 'coverage', 'run', '--append', '--branch', '--include=' + include,
                             str(root / 'tools/build_firmware.py'), '--role', 'Link', '--font-dir', str(fonts.resolve()),
                             '--output-root', str(attempt / 'layout-build')]
            if run_logged(build_command, build_log, build_environment):
                raise RuntimeError('Layout prerequisite build failed; see the retained log')
            coverage_log = attempt / 'layout-coverage.log'
            coverage_json = attempt / 'layout-coverage.json'
            if run_logged([str(python), '-B', '-m', 'coverage', 'json', '--include=' + include, '-o', str(coverage_json)],
                          coverage_log, coverage_environment):
                raise RuntimeError('Layout coverage report failed; see the retained log')
            if load_source_id(root, pins) != before:
                raise RuntimeError('Firmware source changed during layout prerequisites')
            coverage_bytes = coverage_path.read_bytes()
            result['layout_coverage_sha256'] = hashlib.sha256(coverage_bytes).hexdigest()
            publish_bytes(attempt / 'layout-coverage.b64', base64.b64encode(coverage_bytes))
            result['layout_tests_log_sha256'] = file_hash(tests_log)
            result['layout_build_log_sha256'] = file_hash(build_log)
            result['layout_coverage_json_sha256'] = file_hash(coverage_json)
        runner = ('test_tooling.py' if suite == 'tooling' else
                  'test_host.py' if suite == 'host' else CHECKS[suite][0])
        command = [str(python), '-B', str(root / 'tools' / runner)]
        if suite == 'host':
            command += ['--font-dir', str(fonts.resolve())]
        if suite == 'setupTransfer':
            command += ['--output', str(attempt / 'qualification/results.json')]
        if suite == 'sessionControl':
            command += ['--negative-control', '--output', str(attempt / 'qualification')]
        if suite == 'authorityResources':
            command += ['--arm-commands', str(root / 'build/firmware/link' / before / 'compile_commands.json')]
        if suite == 'authorityLayout':
            command += ['--baseline', str(root / 'tests/baselines/c433-authority-layout.v1.json'),
                        '--coverage', str(attempt / 'layout-coverage.data'), '--output', str(attempt / 'qualification')]
        log = attempt / 'output.log'
        code = run_logged(command, log)
        result['log_sha256'] = file_hash(log)
        result['exit_code'] = code
        if cancelled:
            raise InterruptedError('Test cancelled')
        if code:
            raise RuntimeError('Firmware test runner failed; see the retained log')
        if load_source_id(root, pins) != before:
            raise RuntimeError('Firmware source changed during the test')
        if suite == 'tooling':
            report = root / 'build/tooling' / before / 'results.json'
        elif suite == 'host':
            lines = log.read_text(errors='replace').splitlines()
            last = json.loads(lines[-1])
            report = Path(last['host_report']).resolve()
            if not report.is_relative_to((root / 'build/host').resolve()):
                raise ValueError('Host report is outside the firmware host output')
        else:
            report = check_owner_report(root, attempt, suite, log, before, inputs)
        evidence = json.loads(report.read_text())
        if suite == 'sessionControl':
            result['qualification_evidence_sha256'] = evidence['qualification_evidence_sha256']
        if (suite in {'tooling', 'host'} and evidence.get('source_id') != before) or evidence.get('result') != 'pass':
            raise RuntimeError('Firmware result is missing, failed or belongs to another source')
        if suite == 'tooling' and evidence.get('tests') != len(cases):
            raise RuntimeError('Executed test count differs from the catalog')
        result['runner_report_sha256'] = file_hash(report)
        report_bytes = report.read_bytes()
        if hashlib.sha256(report_bytes).hexdigest() != result['runner_report_sha256']:
            raise RuntimeError('Firmware runner report changed during save')
        publish_bytes(attempt / 'runner-report.json', report_bytes)
        result['status'] = 'passed'
    except Exception as error:
        result['status'] = 'cancelled' if cancelled or isinstance(error, InterruptedError) else 'failed'
        result['reason'] = str(error)
    finally:
        if lock:
            lock.close()
        signal.signal(signal.SIGTERM, prior_handler)
    log = attempt / 'output.log'
    if log.is_file() and 'log_sha256' not in result:
        result['log_sha256'] = file_hash(log)
    prior_log = attempt / 'prerequisite-host.log'
    if prior_log.is_file() and 'prerequisite_log_sha256' not in result:
        result['prerequisite_log_sha256'] = file_hash(prior_log)
    for name, key in [('layout-tests.log', 'layout_tests_log_sha256'),
                      ('layout-build.log', 'layout_build_log_sha256'),
                      ('layout-coverage.json', 'layout_coverage_json_sha256')]:
        path = attempt / name
        if path.is_file() and key not in result:
            result[key] = file_hash(path)
    result['finished_unix'] = time.time()
    publish(attempt / 'completed.json', result)
    return result


def inspect_attempt(attempt, expected_definition=None, operator=None):
    """Reopen saved evidence without treating an incomplete attempt as passed."""
    if (attempt.is_symlink() or (attempt / 'started.json').is_symlink() or
            (attempt / 'completed.json').is_symlink()):
        raise ValueError('Saved firmware attempt cannot be a symbolic link')
    started = json.loads((attempt / 'started.json').read_text())
    if expected_definition is None:
        expected_definition = started.get('definition_sha256')
        if expected_definition not in {LEGACY_DEFINITION_SHA256, SECOND_DEFINITION_SHA256, THIRD_DEFINITION_SHA256, FOURTH_DEFINITION_SHA256, FIFTH_DEFINITION_SHA256, SIXTH_DEFINITION_SHA256, DEFINITION_SHA256}:
            raise ValueError('Unknown firmware test definition')
    if (started.get('definition_sha256') != expected_definition or started.get('status') != 'running' or
            started.get('id') != attempt.name or
            not isinstance(started.get('operator'), str) or
            not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', started['operator']) or
            not isinstance(started.get('workshop_fingerprint'), str) or
            not re.fullmatch(r'[0-9a-f]{64}', started['workshop_fingerprint']) or
            (operator is not None and started['operator'] != operator)):
        raise ValueError('Invalid saved firmware attempt')
    completed_file = attempt / 'completed.json'
    if not completed_file.is_file():
        return {**started, 'status': 'incomplete',
                'reason': 'No final result is saved; the run may still be active or was interrupted.'}
    result = json.loads(completed_file.read_text())
    if (result.get('id') != started.get('id') or result.get('suite') != started.get('suite') or
            result.get('operator') != started.get('operator') or
            result.get('workshop_fingerprint') != started.get('workshop_fingerprint') or
            result.get('definition_sha256') != expected_definition or
            result.get('status') not in {'passed', 'failed', 'cancelled'}):
        raise ValueError('Saved firmware attempt binding differs')
    if result['status'] == 'passed':
        required = ['adapter_sha256', 'catalog_sha256', 'log_sha256', 'runner_report_sha256']
        if (any(not isinstance(result.get(key), str) for key in required) or
                result.get('exit_code') != 0 or
                not re.fullmatch(r'[0-9a-f]{64}', result.get('firmware_source_id', ''))):
            raise ValueError('Passed firmware attempt is missing required evidence')
    files = [('definition.json', 'definition_sha256'), ('adapter.py', 'adapter_sha256'),
             ('catalog.json', 'catalog_sha256'), ('output.log', 'log_sha256'),
             ('runner-report.json', 'runner_report_sha256'),
             ('qualification-evidence.json', 'qualification_evidence_sha256'),
             ('prerequisite-host.log', 'prerequisite_log_sha256'),
             ('prerequisite-host-report.json', 'prerequisite_report_sha256'),
             ('layout-tests.log', 'layout_tests_log_sha256'), ('layout-build.log', 'layout_build_log_sha256'),
             ('layout-coverage.json', 'layout_coverage_json_sha256')]
    for name, key in files:
        if (attempt / name).is_symlink():
            raise ValueError('Saved firmware evidence cannot be a symbolic link: ' + name)
        if key in result and (not (attempt / name).is_file() or file_hash(attempt / name) != result[key]):
            if result['status'] != 'passed' and not (attempt / name).exists():
                continue
            raise ValueError('Saved firmware evidence differs: ' + name)
    if (result['status'] == 'passed' and expected_definition in {SECOND_DEFINITION_SHA256, THIRD_DEFINITION_SHA256, FOURTH_DEFINITION_SHA256, FIFTH_DEFINITION_SHA256, SIXTH_DEFINITION_SHA256, DEFINITION_SHA256} and
            ((attempt / 'source-inputs.json').is_symlink() or
             not (attempt / 'source-inputs.json').is_file() or
             file_hash(attempt / 'source-inputs.json') != result['firmware_source_id'])):
        raise ValueError('Saved firmware source inventory differs')
    if result['status'] == 'passed' and result.get('suite') == 'authorityLayout':
        encoded = attempt / 'layout-coverage.b64'
        if (encoded.is_symlink() or not encoded.is_file() or
                hashlib.sha256(base64.b64decode(encoded.read_bytes(), validate=True)).hexdigest() != result.get('layout_coverage_sha256')):
            raise ValueError('Saved layout coverage differs')
    return result


def export_attempt(attempt, destination, expected_definition=None, operator=None):
    result = inspect_attempt(attempt, expected_definition, operator)
    bundle = {'format': 1, 'report': result, 'evidence': {}}
    for name in ['started.json', 'definition.json', 'adapter.py', 'catalog.json', 'source-inputs.json', 'output.log', 'runner-report.json', 'qualification-evidence.json', 'prerequisite-host.log', 'prerequisite-host-report.json', 'layout-tests.log', 'layout-build.log', 'layout-coverage.json', 'layout-coverage.b64']:
        path = attempt / name
        if path.is_file():
            bundle['evidence'][name] = path.read_text(errors='strict')
    payload = json.dumps(bundle, indent=2).encode() + b'\n'
    publish_bytes(destination, payload)
    return {'path': str(destination), 'sha256': hashlib.sha256(payload).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation', choices=['run', 'inspect', 'export'], default='run')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--fonts', type=Path)
    parser.add_argument('--definition', type=Path)
    parser.add_argument('--definition-sha256')
    parser.add_argument('--attempt', required=True, type=Path)
    parser.add_argument('--operator', required=True)
    parser.add_argument('--workshop-fingerprint')
    parser.add_argument('--suite', choices=['tooling', 'host', *CHECKS])
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.operation == 'inspect':
        print(json.dumps(inspect_attempt(args.attempt, operator=args.operator)))
        return 0
    if args.operation == 'export':
        if args.destination is None:
            parser.error('export requires --destination')
        print(json.dumps(export_attempt(args.attempt, args.destination, operator=args.operator)))
        return 0
    if not all([args.root, args.python, args.definition, args.definition_sha256, args.suite, args.workshop_fingerprint]):
        parser.error('run requires root, python, definition, definition-sha256, suite and workshop-fingerprint')
    if args.definition_sha256 != DEFINITION_SHA256 or file_hash(args.definition) != DEFINITION_SHA256:
        raise ValueError('Firmware test definition digest mismatch')
    definition = json.loads(args.definition.read_text())
    result = execute(args.root, args.python, args.fonts, args.suite, definition,
                     args.definition_sha256, args.attempt, args.operator, args.workshop_fingerprint)
    print(json.dumps(result))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
