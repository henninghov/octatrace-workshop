"""Check local shared-suite pins without accessing another checkout."""
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'shared-contract-tests.lock.json').is_file())
TESTS = Path(__file__).parent
SUITES = TESTS / 'shared_contract_suites'


class SharedContractPinsTest(unittest.TestCase):
    def test_every_wrapper_and_suite_matches_local_pins(self):
        lock = json.loads((ROOT / 'shared-contract-tests.lock.json').read_text())
        self.assertIs(type(lock['format']), int)
        self.assertEqual(lock['format'], 1)
        self.assertEqual(lock['source_repository'], 'octatrace-firmware')
        self.assertFalse(SUITES.is_symlink())
        self.assertEqual(set(lock['files']), {p.name for p in SUITES.iterdir()})
        for name, digest in lock['files'].items():
            with self.subTest(name=name):
                suite = SUITES / name
                self.assertFalse(suite.is_symlink())
                self.assertEqual(hashlib.sha256(suite.read_bytes()).hexdigest(), digest)
                self.assertIn("_expected = '" + digest + "'", (TESTS / name).read_text())

    def test_wrapper_rejects_changed_source_lock_and_symlinks_before_execution(self):
        name = 'test_credential_layout_policy.py'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tests = root / 'tests'
            tests.mkdir()
            shutil.copy2(TESTS / name, tests / name)
            shutil.copytree(SUITES, tests / 'shared_contract_suites')
            lock = root / 'shared-contract-tests.lock.json'
            shutil.copy2(ROOT / lock.name, lock)
            suite = tests / 'shared_contract_suites' / name
            original = suite.read_bytes()
            suite.write_bytes(original + b'\n# tampered\n')
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                runpy.run_path(str(tests / name))
            suite.write_bytes(original)
            data = json.loads(lock.read_text())
            data['files'][name] = '0' * 64
            lock.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                runpy.run_path(str(tests / name))
            shutil.copy2(ROOT / lock.name, lock)
            data = json.loads(lock.read_text())
            data['format'] = True
            lock.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                runpy.run_path(str(tests / name))
            shutil.copy2(ROOT / lock.name, lock)
            suite.unlink()
            suite.symlink_to(SUITES / name)
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                runpy.run_path(str(tests / name))


if __name__ == '__main__':
    unittest.main()
