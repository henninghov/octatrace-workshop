"""Verify the local consumer test snapshots without an owner checkout."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

TESTS = Path(__file__).parent
ROOT = next(p for p in TESTS.resolve().parents if (p / 'consumer-contract-tests.lock.json').is_file())
SUITES = TESTS / 'consumer_contract_suites'


class ConsumerContractPinsTest(unittest.TestCase):
    def test_local_snapshots_and_delivery_entry_point_are_pinned(self):
        lock = json.loads((ROOT / 'consumer-contract-tests.lock.json').read_text())
        self.assertIs(type(lock['format']), int)
        self.assertEqual(lock['format'], 1)
        self.assertEqual(lock['source_repository'], 'octatrace-firmware')
        self.assertFalse(SUITES.is_symlink())
        self.assertEqual(set(lock['files']), {p.name for p in SUITES.iterdir()})
        for name, digest in lock['files'].items():
            with self.subTest(name=name):
                path = SUITES / name
                self.assertFalse(path.is_symlink())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        delivery = (TESTS / 'test_credential_delivery_contract.py').read_text()
        self.assertIn("_load_consumer_suite('delivery_common.py', globals())", delivery)
        self.assertIn('test_signed_vector_and_schema = _delivery_signed_vector_and_schema', delivery)

    def test_changed_snapshot_or_lock_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tests = root / 'tools/tests'
            tests.mkdir(parents=True)
            shutil.copy2(TESTS / 'consumer_contract_test_loader.py', tests)
            shutil.copytree(SUITES, tests / 'consumer_contract_suites')
            lock = root / 'consumer-contract-tests.lock.json'
            shutil.copy2(ROOT / lock.name, lock)
            spec = importlib.util.spec_from_file_location('isolated_consumer_loader', tests / 'consumer_contract_test_loader.py')
            loader = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(loader)
            suite = tests / 'consumer_contract_suites/delivery_common.py'
            original = suite.read_bytes()
            suite.write_bytes(original + b'\n# changed\n')
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                loader.load('delivery_common.py', {})
            suite.write_bytes(original)
            pin = json.loads(lock.read_text())
            pin['files']['delivery_common.py'] = '0' * 64
            lock.write_text(json.dumps(pin))
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                loader.load('delivery_common.py', {})
            shutil.copy2(ROOT / lock.name, lock)
            suite.unlink()
            suite.symlink_to(SUITES / 'delivery_common.py')
            with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
                loader.load('delivery_common.py', {})


if __name__ == '__main__':
    unittest.main()
