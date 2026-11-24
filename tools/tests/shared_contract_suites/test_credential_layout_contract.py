import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = next(p for p in Path(__file__).resolve().parents if (p / 'credential-layout.lock.json').is_file())
sys.path.insert(0, str(BASE / 'tools'))
import verify_credential_layout as verifier


class CredentialLayoutVerifierTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'owner'
        self.root.mkdir()
        for name in ('credential-layout', 'authority-layout', 'authority-storage', 'device-authority', 'device-credential'):
            lock = BASE / (name + '.lock.json')
            path = json.loads(lock.read_text())['path']
            shutil.copytree(BASE / path, self.root / path)
            shutil.copy2(lock, self.root)
        self.pin_path = self.root / 'credential-layout.lock.json'
        self.pin = json.loads(self.pin_path.read_text())
        self.folder = self.root / self.pin['path']

    def write_pin(self, pin):
        self.pin_path.write_text(json.dumps(pin))

    def verify_mocked(self):
        with patch.object(verifier.verify_authority_layout, 'verify'), patch.object(verifier.verify_device_credential, 'verify'):
            return verifier.verify(self.root)

    def test_real_dependencies_and_candidate(self):
        value = verifier.verify(self.root)
        self.assertEqual((value['start'], value['end_exclusive'], value['runtime_credential']), ('0xdf000', '0xe1000', False))

    def test_cli_entrypoint_runs_real_dependencies(self):
        script = BASE / 'tools/verify_credential_layout.py'
        code = compile(script.read_text(), str(script), 'exec')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(code, {'__name__': '__main__', '__file__': str(self.root / 'tools/verify_credential_layout.py')})
        self.assertEqual(json.loads(output.getvalue())['start'], '0xdf000')

    def test_pin_and_dependencies_fail_closed(self):
        for key, value in [('profile', 'wrong'), ('version', True), ('version', 2),
                           ('source_repository', 'wrong'), ('path', '../outside'), ('files', {})]:
            pin = copy.deepcopy(self.pin); pin[key] = value; self.write_pin(pin)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.verify_mocked()
        for key in ('requires_authority_layout_files_sha256', 'requires_device_credential_files_sha256'):
            pin = copy.deepcopy(self.pin); pin[key] = {}; self.write_pin(pin)
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify_mocked()

    def test_inventory_and_file_tampering_are_rejected(self):
        extra = self.folder / 'extra'; extra.write_text('x')
        with self.assertRaises(ValueError): self.verify_mocked()
        extra.unlink()
        for name in verifier.FILES:
            file = self.folder / name; original = file.read_bytes(); file.write_bytes(original + b' ')
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify_mocked()
            file.write_bytes(original)
        file = self.folder / 'policy.py'; file.unlink(); file.symlink_to(BASE / json.loads((BASE / 'credential-layout.lock.json').read_text())['path'] / 'policy.py')
        with self.assertRaises(ValueError): self.verify_mocked()

    def test_independently_pinned_semantics_and_negative_guard(self):
        file = self.folder / 'contract.json'; data = json.loads(file.read_text()); data['credential_start'] -= 4096
        file.write_text(json.dumps(data)); pin = copy.deepcopy(self.pin)
        pin['files']['contract.json'] = hashlib.sha256(file.read_bytes()).hexdigest(); self.write_pin(pin)
        with patch.object(verifier, 'FILES', pin['files']), self.assertRaisesRegex(ValueError, 'contract mismatch'):
            self.verify_mocked()
        shutil.copy2(BASE / json.loads((BASE / 'credential-layout.lock.json').read_text())['path'] / 'contract.json', file); self.write_pin(self.pin)
        policy = self.folder / 'policy.py'; text = policy.read_text().replace('return type(image_end) is int and 0x26000 <= image_end <= START', 'return True')
        policy.write_text(text); pin = copy.deepcopy(self.pin)
        pin['files']['policy.py'] = hashlib.sha256(policy.read_bytes()).hexdigest(); self.write_pin(pin)
        with patch.object(verifier, 'FILES', pin['files']), self.assertRaisesRegex(ValueError, 'overlap accepted'):
            self.verify_mocked()
        text = (BASE / json.loads((BASE / 'credential-layout.lock.json').read_text())['path'] / 'policy.py').read_text().replace('return type(image_end) is int and 0x26000 <= image_end <= START', 'return False')
        policy.write_text(text); pin = copy.deepcopy(self.pin)
        pin['files']['policy.py'] = hashlib.sha256(policy.read_bytes()).hexdigest(); self.write_pin(pin)
        with patch.object(verifier, 'FILES', pin['files']), self.assertRaisesRegex(ValueError, 'positive manifest rejected'):
            self.verify_mocked()


if __name__ == '__main__':
    unittest.main()
