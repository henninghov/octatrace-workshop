import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import verify_crypto_probe
import verify_crypto_reentry
import verify_crypto_keys


class CryptoProbeContractTest(unittest.TestCase):
    def test_key_snapshot_and_guide_pins(self):
        self.assertEqual(verify_crypto_keys.verify(ROOT)['invalid'], 22)
        lock = json.loads((ROOT / 'crypto-keys.lock.json').read_text())
        guide = json.loads((ROOT / 'assets/bench/c83-crypto-keys.v1.json').read_text())
        for name, digest in lock['files'].items():
            self.assertEqual(hashlib.sha256((ROOT / 'vendor/crypto-keys' / name).read_bytes()).hexdigest(), digest)
            self.assertEqual(guide['runner']['additional_files']['contracts/crypto-keys/' + name], digest)
        self.assertEqual(guide['runner']['id'], 'p1.crypto-keys')
        self.assertEqual([build['role'] for build in guide['builds']], ['Link', 'Core'])
        self.assertEqual(len({build['source'] for build in guide['builds']}), 1)
        self.assertEqual(len({build['artifact'] for build in guide['builds']}), 2)

    def test_reentry_snapshot_and_guide_pins(self):
        self.assertEqual(verify_crypto_reentry.verify(ROOT)['invalid'], 16)
        lock = json.loads((ROOT / 'crypto-reentry.lock.json').read_text())
        guide = json.loads((ROOT / 'assets/bench/c83-crypto-reentry.v1.json').read_text())
        for name, digest in lock['files'].items():
            self.assertEqual(hashlib.sha256((ROOT / 'vendor/crypto-reentry' / name).read_bytes()).hexdigest(), digest)
            self.assertEqual(guide['runner']['additional_files']['contracts/crypto-reentry/' + name], digest)
        self.assertEqual(guide['runner']['id'], 'p1.crypto-reentry')
        self.assertEqual([build['role'] for build in guide['builds']], ['Link', 'Core'])

    def test_snapshot_and_guide_pin_same_crypto_contract(self):
        self.assertEqual(verify_crypto_probe.verify(ROOT)['invalid'], 16)
        lock = json.loads((ROOT / 'crypto-probe.lock.json').read_text())
        guide = json.loads((ROOT / 'assets/bench/c83-crypto-probe.v1.json').read_text())
        for name, digest in lock['files'].items():
            self.assertEqual(hashlib.sha256((ROOT / 'vendor/crypto-probe' / name).read_bytes()).hexdigest(), digest)
            self.assertEqual(guide['runner']['additional_files']['contracts/crypto-probe/' + name], digest)
        self.assertEqual(guide['runner']['id'], 'p1.crypto-probe')
        self.assertEqual([build['role'] for build in guide['builds']], ['Link', 'Core'])
        self.assertEqual(len({build['source'] for build in guide['builds']}), 1)
        self.assertEqual(len({build['artifact'] for build in guide['builds']}), 2)


if __name__ == '__main__':
    unittest.main()
