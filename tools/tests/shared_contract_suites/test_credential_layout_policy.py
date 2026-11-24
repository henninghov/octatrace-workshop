import copy
import json
from pathlib import Path
import runpy
import unittest
import jsonschema

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'credential-layout.lock.json').is_file())
CONTRACT = ROOT / json.loads((ROOT / 'credential-layout.lock.json').read_text())['path']
POLICY = runpy.run_path(str(CONTRACT / 'policy.py'))


class CredentialLayoutPolicyTest(unittest.TestCase):
    def setUp(self):
        self.expected = POLICY['capability']('a' * 64, 'b' * 64)
        self.manifest = {'credential_storage_reservation': self.expected,
                         'credential_storage_symbols': dict(POLICY['SYMBOLS']),
                         'phone_storage_reservation': {'__octatrace_image_end': POLICY['START']}}

    def test_accepts_exact_layout_and_bounds(self):
        self.assertTrue(POLICY['compatible'](self.manifest, self.expected))
        self.manifest['phone_storage_reservation']['__octatrace_image_end'] = 0x26000
        self.assertTrue(POLICY['compatible'](self.manifest, self.expected))

    def test_hashes_require_exact_lowercase_strings(self):
        for value in (None, False, 1, '', 'a' * 63, 'g' * 64, 'A' * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                POLICY['capability'](value, 'b' * 64)
            with self.subTest(value=value), self.assertRaises(ValueError):
                POLICY['capability']('a' * 64, value)

    def test_fails_closed_for_metadata_or_container_changes(self):
        self.assertFalse(POLICY['compatible'](None, self.expected))
        self.assertFalse(POLICY['compatible'](self.manifest, None))
        for field in self.manifest:
            for value in (None, [], 'wrong'):
                candidate = copy.deepcopy(self.manifest); candidate[field] = value
                self.assertFalse(POLICY['compatible'](candidate, self.expected), (field, value))
        for key in self.expected:
            candidate = copy.deepcopy(self.manifest); candidate['credential_storage_reservation'][key] = None
            self.assertFalse(POLICY['compatible'](candidate, self.expected), key)
        candidate = copy.deepcopy(self.manifest); candidate['credential_storage_reservation']['version'] = True
        self.assertFalse(POLICY['compatible'](candidate, self.expected))
        candidate = copy.deepcopy(self.manifest); candidate['credential_storage_reservation']['extra'] = 1
        self.assertFalse(POLICY['compatible'](candidate, self.expected))

    def test_exact_symbols_and_image_ceiling(self):
        for key in POLICY['SYMBOLS']:
            for value in (None, True, POLICY['SYMBOLS'][key] + 1):
                candidate = copy.deepcopy(self.manifest); candidate['credential_storage_symbols'][key] = value
                self.assertFalse(POLICY['compatible'](candidate, self.expected), (key, value))
            candidate = copy.deepcopy(self.manifest); del candidate['credential_storage_symbols'][key]
            self.assertFalse(POLICY['compatible'](candidate, self.expected), key)
        candidate = copy.deepcopy(self.manifest); candidate['credential_storage_symbols']['extra'] = 0
        self.assertFalse(POLICY['compatible'](candidate, self.expected))
        for value in (None, True, 0x25fff, POLICY['START'] + 1):
            candidate = copy.deepcopy(self.manifest); candidate['phone_storage_reservation']['__octatrace_image_end'] = value
            self.assertFalse(POLICY['compatible'](candidate, self.expected), value)

    def test_schema_matches_policy(self):
        schema = json.loads((CONTRACT / 'manifest.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(self.expected)
        for change in ({'version': True}, {'runtime_credential': 0}, {'maintenance_version': 1},
                       {'start': '0xe0000'}, {'pages': 3}, {'extra': 0}):
            with self.subTest(change=change):
                self.assertTrue(list(validator.iter_errors({**self.expected, **change})))


if __name__ == '__main__':
    unittest.main()
