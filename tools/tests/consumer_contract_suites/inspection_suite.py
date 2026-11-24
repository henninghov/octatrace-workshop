"""Consumer compatibility for the read-only credential-inspection contract."""
import copy
import json
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import verify_credential_inspection


class InspectionConsumerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'vendor', self.root / 'vendor')
        for file in ROOT.glob('*.lock.json'):
            shutil.copy2(file, self.root / file.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_actual_snapshot_vectors_and_schema(self):
        self.assertEqual(verify_credential_inspection.verify(self.root)['scope'], 'read-only')
        folder = self.root / 'vendor/credential-inspection'
        validate = runpy.run_path(str(folder / 'policy.py'))['validate']
        schema = Draft202012Validator(json.loads((folder / 'response.schema.json').read_text()))
        vectors = json.loads((folder / 'vectors.json').read_text())
        for row in vectors['valid']:
            with self.subTest(row=row):
                self.assertEqual(list(schema.iter_errors(row)), [])
                self.assertEqual(validate(row, vectors['request_id']), row)
        for row in vectors['invalid']:
            with self.subTest(row=row):
                self.assertTrue(list(schema.iter_errors(row)))
                with self.assertRaises(ValueError):
                    validate(row, vectors['request_id'])
        with self.assertRaises(ValueError):
            validate(copy.deepcopy(vectors['valid'][0]), 8)

    def test_mutation_repinned_content_and_extra_file_fail_closed(self):
        folder = self.root / 'vendor/credential-inspection'
        path = folder / 'policy.py'
        original = path.read_text()
        path.write_text(original + '\n# changed\n')
        with self.assertRaises(ValueError):
            verify_credential_inspection.verify(self.root)
        lock = self.root / 'credential-inspection.lock.json'
        value = json.loads(lock.read_text())
        value['files']['policy.py'] = '0' * 64
        lock.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            verify_credential_inspection.verify(self.root)
        shutil.copy2(ROOT / 'credential-inspection.lock.json', lock)
        path.write_text(original)
        (folder / 'unexpected').write_text('x')
        with self.assertRaises(ValueError):
            verify_credential_inspection.verify(self.root)


if __name__ == '__main__':
    unittest.main()
