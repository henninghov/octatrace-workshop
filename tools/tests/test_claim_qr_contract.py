"""Contract-level tests only: no registry access, code issuance, scanner or device."""
import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'claim-qr.lock.json').is_file())
sys.path.insert(0, str(ROOT / 'tools'))
import verify_claim_qr as checker

LOCK = json.loads((ROOT / 'claim-qr.lock.json').read_text())
FOLDER = ROOT / LOCK['path']
CODEC = runpy.run_path(str(FOLDER / 'codec.py'))
VECTORS = json.loads((FOLDER / 'vectors.json').read_text())


class ClaimQrCodecTest(unittest.TestCase):
    def test_all_positive_bytes_round_trip_and_environment_role_combinations(self):
        combinations = set()
        for row in VECTORS['valid']:
            with self.subTest(row=row['name']):
                encoded = CODEC['encode'](row['fields'])
                self.assertEqual(encoded, row['text'])
                self.assertEqual(len(encoded), 145)
                self.assertEqual(base64.urlsafe_b64decode(encoded[18:] + '=').hex(), row['cbor_hex'])
                self.assertEqual(CODEC['decode'](encoded, row['fields']['environment']).to_fields(), row['fields'])
                combinations.add((row['fields']['environment'], row['fields']['role']))
        self.assertEqual(combinations, {(e, r) for e in ('development', 'production') for r in ('Link', 'Core')})

    def test_all_pinned_invalid_text_is_denied_without_disclosure(self):
        for row in VECTORS['invalid_text']:
            with self.subTest(row=row['name']), self.assertRaisesRegex(ValueError, '^Invalid claim QR$'):
                CODEC['decode'](row['text'], row['environment'])

    def test_all_pinned_invalid_fields_are_denied_without_disclosure(self):
        for row in VECTORS['invalid_fields']:
            with self.subTest(row=row['name']), self.assertRaisesRegex(ValueError, '^Invalid claim QR$'):
                CODEC['encode'](row['fields'])

    def test_every_truncation_and_large_input_stops_before_base64_decoding(self):
        value = VECTORS['valid'][0]['text']
        with patch('base64.urlsafe_b64decode', side_effect=AssertionError('must not decode')):
            for text in [value[:i] for i in range(len(value))] + [value + 'x' * 1000000]:
                with self.assertRaisesRegex(ValueError, '^Invalid claim QR$'):
                    CODEC['decode'](text, 'development')

    def test_generic_base64_decoder_would_accept_the_noncanonical_pad_bits(self):
        valid = VECTORS['valid'][0]['text']
        bad = next(v['text'] for v in VECTORS['invalid_text'] if v['name'] == 'nonzero_base64_pad_bits')
        self.assertEqual(base64.urlsafe_b64decode(valid[18:] + '='), base64.urlsafe_b64decode(bad[18:] + '='))
        with self.assertRaisesRegex(ValueError, '^Invalid claim QR$'):
            CODEC['decode'](bad, 'development')

    def test_well_formed_changed_identity_or_secret_stays_untrusted(self):
        # Syntax cannot detect an unknown registered key/code or assign an owner.
        for field in ('device_uuid', 'public_key_sha256', 'claim_secret'):
            fields = dict(VECTORS['valid'][0]['fields'])
            fields[field] = ('22222222-2222-4222-8222-222222222222' if field == 'device_uuid' else 'ab' * 32)
            result = CODEC['decode'](CODEC['encode'](fields), 'development')
            self.assertEqual(result.to_fields(), fields)
            self.assertEqual(type(result).__name__, 'UntrustedClaim')
            self.assertNotIn(fields['claim_secret'], repr(result))
            with self.assertRaises(AttributeError):
                result.role = 'Core'

    def test_explicit_private_export_is_separate_from_safe_repr(self):
        fields = VECTORS['valid'][0]['fields']
        result = CODEC['decode'](VECTORS['valid'][0]['text'], 'development')
        self.assertNotIn(fields['claim_secret'], str(result))
        self.assertIn(fields['claim_secret'], json.dumps(result.to_fields()))
        exported = result.to_fields()
        exported['claim_secret'] = 'ff' * 32
        self.assertEqual(result.claim_secret, fields['claim_secret'])

    def test_json_integer_one_normalises_but_boolean_one_is_denied(self):
        fields = dict(VECTORS['valid'][0]['fields'], v=1.0)
        result = CODEC['validate_fields'](fields)
        self.assertIs(type(result.v), int)
        self.assertEqual(CODEC['encode'](fields), VECTORS['valid'][0]['text'])
        with self.assertRaises(ValueError):
            CODEC['encode'](dict(fields, v=True))


class ClaimQrPinTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.folder = self.root / LOCK['path']
        shutil.copytree(FOLDER, self.folder)
        (self.root / 'claim-qr.lock.json').write_text(json.dumps(LOCK))

    def repin(self):
        lock = copy.deepcopy(LOCK)
        lock['files'] = {name: hashlib.sha256((self.folder / name).read_bytes()).hexdigest() for name in LOCK['files']}
        (self.root / 'claim-qr.lock.json').write_text(json.dumps(lock))

    def change_json(self, name, operation):
        path = self.folder / name
        value = json.loads(path.read_text())
        operation(value)
        path.write_text(json.dumps(value))
        self.repin()

    def test_actual_owner_or_consumer_snapshot_and_cli(self):
        expected = {name: len(VECTORS[name]) for name in ('valid', 'invalid_text', 'invalid_fields')}
        self.assertEqual(checker.verify(ROOT), expected)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            runpy.run_path(str(ROOT / 'tools/verify_claim_qr.py'), run_name='__main__')
        self.assertEqual(json.loads(stream.getvalue()), expected)
        self.assertEqual(checker.verify(self.root), expected)

    def test_lock_profile_version_owner_path_and_inventory(self):
        for field, value in [('profile', 'other'), ('version', 2), ('source_repository', 'other'),
                             ('path', '../outside'), ('files', {})]:
            lock = copy.deepcopy(LOCK)
            lock[field] = value
            (self.root / 'claim-qr.lock.json').write_text(json.dumps(lock))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Unsupported claim QR pin'):
                checker.verify(self.root)

    def test_missing_and_extra_file_are_denied(self):
        path = self.folder / 'extra.txt'
        path.write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)
        path.unlink()
        (self.folder / 'codec.py').unlink()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)

    def test_unpinned_changes_invalid_digest_and_symlink_are_denied(self):
        path = self.folder / 'codec.py'
        original = path.read_bytes()
        path.write_bytes(original + b'\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        path.write_bytes(original)
        lock = copy.deepcopy(LOCK)
        lock['files']['codec.py'] = 'invalid'
        (self.root / 'claim-qr.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        (self.root / 'claim-qr.lock.json').write_text(json.dumps(LOCK))
        path.unlink()
        path.symlink_to(FOLDER / 'codec.py')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)

    def test_folder_symlink_cannot_escape_checkout(self):
        shutil.rmtree(self.folder)
        self.folder.symlink_to(FOLDER, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)

    def test_repinned_profile_schema_and_incomplete_vectors_are_denied(self):
        for name, change, message in [
            ('profile.json', lambda x: x['text'].update(characters=146), 'profile'),
            ('profile.json', lambda x: x['cbor']['fields'][0].update(key=7), 'profile'),
            ('claim.schema.json', lambda x: x.update(additionalProperties=True), 'schema'),
            ('vectors.json', lambda x: x.update(valid=[]), 'vectors')]:
            original = (self.folder / name).read_bytes()
            self.change_json(name, change)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                checker.verify(self.root)
            (self.folder / name).write_bytes(original)
            self.repin()

    def test_repinned_positive_text_fields_and_bytes_are_denied(self):
        original = (self.folder / 'vectors.json').read_bytes()
        for field in ('text', 'fields', 'cbor_hex'):
            def mutate(value):
                row = value['valid'][0]
                if field == 'fields':
                    row['fields']['role'] = 'Core'
                else:
                    row[field] += '0'
            self.change_json('vectors.json', mutate)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'positive vector'):
                checker.verify(self.root)
            (self.folder / 'vectors.json').write_bytes(original)
            self.repin()

    def test_repinned_negative_vector_cannot_become_valid(self):
        for kind in ('invalid_text', 'invalid_fields'):
            original = (self.folder / 'vectors.json').read_bytes()
            def mutate(value):
                if kind == 'invalid_text':
                    value[kind][0] = {'name': 'invalid_now_valid', 'text': value['valid'][0]['text'], 'environment': 'development'}
                else:
                    value[kind][0] = {'name': 'invalid_now_valid', 'fields': value['valid'][0]['fields']}
            self.change_json('vectors.json', mutate)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'negative vector accepted'):
                checker.verify(self.root)
            (self.folder / 'vectors.json').write_bytes(original)
            self.repin()

    def test_codec_diagnostics_cannot_disclose_input(self):
        path = self.folder / 'codec.py'
        path.write_text(path.read_text().replace("ERROR = 'Invalid claim QR'", "ERROR = 'sensitive payload'"))
        self.repin()
        with self.assertRaisesRegex(ValueError, 'may disclose'):
            checker.verify(self.root)

    def test_independent_reference_failure_and_incorrect_summary_are_denied(self):
        for result in [subprocess.CompletedProcess([], 1, '', ''),
                       subprocess.CompletedProcess([], 0, '{}', '')]:
            with patch.object(checker.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'Independent claim QR'):
                    checker.verify(self.root)

    def test_negative_control_removing_pad_bit_check_is_detected(self):
        path = self.folder / 'codec.py'
        text = path.read_text()
        before = "if base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=') != body:"
        self.assertEqual(text.count(before), 1)
        path.write_text(text.replace(before, 'if False:'))
        self.repin()
        with self.assertRaisesRegex(ValueError, 'negative vector accepted'):
            checker.verify(self.root)

    def test_negative_control_wrong_uuid_byte_order_is_detected(self):
        path = self.folder / 'codec.py'
        text = path.read_text()
        before = 'uuid.UUID(claim.device_uuid).bytes +'
        self.assertEqual(text.count(before), 1)
        path.write_text(text.replace(before, 'uuid.UUID(claim.device_uuid).bytes_le +'))
        self.repin()
        with self.assertRaisesRegex(ValueError, 'positive vector'):
            checker.verify(self.root)


if __name__ == '__main__':
    unittest.main()
