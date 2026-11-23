"""Fault checks for the Workshop's read-only update proof adapter."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / 'assets/bench/claimed_update_proof.py'
spec = importlib.util.spec_from_file_location('claimed_update_proof', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Client:
    def __init__(self):
        self.before = {'state': 'ready', 'busy': False, 'failed': False, 'boot': 'a' * 32}
        self.proof = {'boot': 'a' * 32, 'challenge': 'c' * 64}
        self.proves = []

    def __enter__(self): return self
    def __exit__(self, *_): pass
    def info(self): return self.before
    def prove(self, challenge):
        self.proves.append(challenge)
        return self.proof


class UpdateProofTest(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.selection = {'role': 'Core', 'hardware': '1' * 16, 'source': '2' * 64}
        self.calls = []

    def connect(self, hardware, source, role):
        self.calls.append((hardware, source, role))
        return self.client

    def verify(self, proof, attempt):
        if proof['challenge'] != attempt['challenge']:
            raise ValueError('challenge mismatch')
        self.assertEqual(attempt['source'], self.selection['source'])

    def run_proof(self):
        return module.read_proof(self.selection, self.connect, self.verify, lambda n: 'c' * (n * 2))

    def test_fresh_proof_bound_to_connected_source_and_boot(self):
        result = self.run_proof()
        self.assertEqual(result, self.client.proof)
        self.assertEqual(self.calls, [('1' * 16, '2' * 64, 'Core')])
        self.assertEqual(self.client.proves, ['c' * 64])

    def test_busy_or_faulted_device_never_issues_proof(self):
        for changes in ({'state': 'fault'}, {'busy': True}, {'failed': True}):
            with self.subTest(changes=changes):
                self.setUp()
                self.client.before.update(changes)
                with self.assertRaises(ValueError): self.run_proof()
                self.assertEqual(self.client.proves, [])

    def test_changed_boot_and_bad_proof_are_rejected(self):
        self.client.proof['boot'] = 'b' * 32
        with self.assertRaises(ValueError): self.run_proof()
        self.setUp()
        self.client.proof['challenge'] = 'd' * 64
        with self.assertRaises(ValueError): self.run_proof()


if __name__ == '__main__': unittest.main()
