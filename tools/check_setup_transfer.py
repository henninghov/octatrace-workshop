#!/usr/bin/env python3
"""Qualify the candidate setup carrier with real tests and omission controls.

No runtime/device/readiness result. All outputs go to the explicitly selected
report folder, so cross-repository checks need no device or source-tree writes.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import unittest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    root = args.root.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.unlink(missing_ok=True)
    pin = json.loads((root / 'setup-transfer.lock.json').read_text())
    folder = root / pin['path']
    tests = root / ('tests' if pin['path'].startswith('contracts/') else 'tools/tests') / 'test_setup_transfer.py'
    shared_test = tests.parent / 'shared_contract_suites' / tests.name
    paths = [root / 'setup-transfer.lock.json', *folder.iterdir(), root / 'tools/verify_setup_transfer.py',
             root / 'tools/check_setup_transfer.py', tests, shared_test, root / 'shared-contract-tests.lock.json']
    for family in ('device-credential', 'device-authority', 'proof-context', 'field-handshake'):
        lock = root / (family + '.lock.json'); paths.append(lock)
        dep = json.loads(lock.read_text()); paths.extend(root / dep['path'] / p for p in dep['files'])
    def hashes():
        return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    before = hashes()
    coverage_file = args.output.parent / '.coverage'
    env = dict(os.environ, COVERAGE_FILE=str(coverage_file))
    include = ','.join(str(p) for p in [folder / 'codec.py', root / 'tools/verify_setup_transfer.py'])
    command = [sys.executable, '-B', '-m', 'coverage', 'run', '--branch', '--include=' + include,
               '-m', 'unittest', 'discover', '-s', str(tests.parent), '-p', tests.name, '-v']
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
    (args.output.parent / 'tests.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    count = re.search(r'Ran (\d+) tests', result.stderr)
    if not count or int(count[1]) < 12 or 'skipped=' in result.stderr:
        raise ValueError('Incomplete setup transfer qualification')
    cov = args.output.parent / 'coverage.json'
    subprocess.run([sys.executable, '-B', '-m', 'coverage', 'json', '-o', str(cov)],
                   cwd=root, env=env, capture_output=True, check=True)
    measured = json.loads(cov.read_text())
    if len(measured['files']) != 2 or any(r['missing_lines'] or r['missing_branches'] or r['excluded_lines'] for r in measured['files'].values()):
        raise ValueError('Setup transfer critical coverage below 100%')
    spec = importlib.util.spec_from_file_location('candidate_setup_tests', tests)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    source = (folder / 'codec.py').read_text()
    controls = []
    replacements = [
        ('body_digest', 'if encode(record.kind, record.device_uuid, record.correlation_uuid, record.body) != data:', 'if False:'),
        ('connection_generation', 'if self._closed or type(generation) is not int or generation != self._generation:', 'if self._closed or type(generation) is not int:')]
    for name, old, new in replacements:
        if source.count(old) != 1:
            raise ValueError('Fault control no longer matches source')
        with tempfile.TemporaryDirectory() as temp:
            mutant = Path(temp) / 'codec.py'; mutant.write_text(source.replace(old, new))
            module.C = runpy.run_path(str(mutant))
            stream = io.StringIO()
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.CodecTest)
            broken = unittest.TextTestRunner(stream=stream).run(suite)
        (args.output.parent / (name + '-omission.log')).write_text(stream.getvalue())
        if broken.wasSuccessful() or not broken.failures or broken.errors:
            raise ValueError('Setup transfer omission control ineffective')
        controls.append({'name':name, 'detected':True, 'failing_tests':[t.id() for t, _ in broken.failures]})
    subprocess.run(['node', '--check', str(folder / 'reference.mjs')], check=True, capture_output=True)
    if hashes() != before:
        raise ValueError('Setup transfer source changed during qualification')
    report = {'checkpoint':'C8.1 setup-transfer candidate foundation', 'result':'pass',
              'scope':'Python/independent Node record and BLE framing only; no live BLE/crypto/storage/key adoption',
              'source_files_sha256':before, 'tests':int(count[1]), 'coverage':measured['totals'],
              'negative_controls':controls, 'physical_validation':'Not run',
              'remaining':'Native bounded adapter/resources, original measured deadline/admission/ACK owner, LINK-CORE field profile and LoRa validation; C8.1 freeze remains open'}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result':'pass', 'tests':report['tests'], 'report':str(args.output), 'runtime_readiness':False}))


if __name__ == '__main__':
    main()
