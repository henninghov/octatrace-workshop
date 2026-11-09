"""Factory credential contract only. OpenSSL uses public synthetic fixture material."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'device-credential.lock.json').is_file())
sys.path.insert(0, str(ROOT / 'tools'))
import verify_device_credential as checker
LOCK = json.loads((ROOT / 'device-credential.lock.json').read_text())
FOLDER = ROOT / LOCK['path']
CODEC = runpy.run_path(str(FOLDER / 'codec.py'))
VECTORS = json.loads((FOLDER / 'vectors.json').read_text())


class PublicOpenSSL:
    """Independent test adapter: LibreSSL imports P-256 SPKI and verifies SHA256/DER."""
    def __init__(self):
        self.cache = {}

    @staticmethod
    def spki(point):
        return bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + point

    def valid_public_key(self, point):
        if point not in self.cache:
            result = subprocess.run(['openssl', 'ec', '-pubin', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                                    input=self.spki(point), capture_output=True)
            self.cache[point] = result.returncode == 0 and result.stdout == self.spki(point)
        return self.cache[point]

    def verify(self, point, message, signature):
        def integer(value):
            value = value.lstrip(b'\0') or b'\0'
            if value[0] & 128:
                value = b'\0' + value
            return b'\x02' + bytes([len(value)]) + value
        parts = integer(signature[:32]) + integer(signature[32:])
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name, value in [('key.der', self.spki(point)), ('message', message),
                                ('sig.der', b'\x30' + bytes([len(parts)]) + parts)]:
                (folder / name).write_bytes(value)
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(folder / 'key.der'),
                                     '-keyform', 'DER', '-signature', str(folder / 'sig.der'),
                                     str(folder / 'message')], capture_output=True)
        return result.returncode == 0


CRYPTO = PublicOpenSSL()
BASE = VECTORS['valid'][0]


def verify(row=BASE, codec=CODEC, **options):
    args = dict(environment=row.get('environment', row.get('fields', {}).get('environment')),
                issuers=row.get('issuers', VECTORS['issuers']), crypto=CRYPTO, expected=row['expected'])
    args.update(options)
    return codec['verify'](bytes.fromhex(row['hex']), **args)


class DeviceCredentialTest(unittest.TestCase):
    def denied(self, operation):
        with self.assertRaisesRegex(ValueError, '^Invalid device credential$'):
            operation()

    def test_signed_vectors_both_roles_realms_and_maximum_sizes(self):
        combinations = set()
        for row in VECTORS['valid']:
            with self.subTest(name=row['name']):
                self.assertEqual(CODEC['signing_bytes'](row['fields']).hex(), row['signing_hex'])
                self.assertEqual(CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex'])).hex(), row['hex'])
                result = verify(row)
                self.assertEqual(result.to_fields(), row['fields'])
                self.assertEqual(result.content_id.hex(), hashlib.sha256(bytes.fromhex(row['signing_hex'])).hexdigest())
                combinations.add((row['fields']['environment'], row['fields']['role']))
        self.assertEqual(combinations, {(e, r) for e in ('development', 'production') for r in ('Link', 'Core')})
        self.assertEqual(max(len(bytes.fromhex(r['hex'])) for r in VECTORS['valid']), 271)
        self.assertEqual(max(len(bytes.fromhex(r['signing_hex'])) for r in VECTORS['valid']), 245)
        self.assertLessEqual(245, 512)

    def test_caller_buffer_limits_include_entire_signed_structure(self):
        row = VECTORS['valid'][4]
        self.assertEqual(len(CODEC['signing_bytes'](row['fields'], 245)), 245)
        self.denied(lambda: CODEC['signing_bytes'](row['fields'], 244))
        self.assertEqual(len(CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex']), 271)), 271)
        self.denied(lambda: CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex']), 270))
        for limit in [None, True, 0, -1, 513]:
            self.denied(lambda: CODEC['signing_bytes'](row['fields'], limit))
            self.denied(lambda: CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex']), limit))
        self.denied(lambda: CODEC['compare_revision'](None, 0, None))

    def test_all_invalid_objects_and_metadata_denied(self):
        for row in VECTORS['invalid_objects']:
            with self.subTest(name=row['name']):
                self.denied(lambda: verify(row))
        for row in VECTORS['invalid_fields']:
            with self.subTest(name=row['name']):
                self.denied(lambda: CODEC['fields'](row['fields']))

    def test_every_truncation_and_large_input_bound(self):
        raw = bytes.fromhex(BASE['hex'])
        for i in range(len(raw)):
            self.denied(lambda: CODEC['verify'](raw[:i], 'development', VECTORS['issuers'], CRYPTO, BASE['expected']))
        for value in [None, [], 'secret', bytearray(raw), b'x' * 1000000]:
            with patch.dict(CODEC['verify'].__globals__, uncbor=lambda _: self.fail('Parsed oversized or wrong-type data')):
                self.denied(lambda: CODEC['verify'](value, 'development', [], CRYPTO, {}))

    def test_missing_wrong_expected_identity_and_crypto_adapters_fail_closed(self):
        for realm in [None, 'staging', [], 1]:
            self.denied(lambda: verify(environment=realm))
        for expected in [None, [], {}, {**BASE['expected'], 'owner': 'anything'},
                         {**BASE['expected'], 'role': 'Unknown'},
                         {**BASE['expected'], 'device_uuid': 'invalid'},
                         {**BASE['expected'], 'public_key_sha256': '0' * 64}]:
            self.denied(lambda: verify(expected=expected))
        for field in ('valid_public_key', 'verify'):
            for result in [False, 1, None]:
                with patch.object(CRYPTO, field, return_value=result):
                    self.denied(lambda: verify())
            with patch.object(CRYPTO, field, side_effect=RuntimeError('do not disclose payload')):
                self.denied(lambda: verify())
        with patch.object(CRYPTO, 'valid_public_key', side_effect=[True, False]):
            self.denied(lambda: verify())
        self.denied(lambda: verify(crypto=None))

    def test_keyring_validation_and_separate_issuer_purposes(self):
        for issuers in [None, {}, [], VECTORS['issuers'] * 3, [None], [{}],
                        [{**VECTORS['issuers'][0], 'environment': 'staging'}],
                        [{**VECTORS['issuers'][0], 'purpose': 'anything'}],
                        [{**VECTORS['issuers'][0], 'kid': '00' * 8}],
                        [{**VECTORS['issuers'][0], 'public_key': '02' + '11' * 64}],
                        [VECTORS['issuers'][0], {**VECTORS['issuers'][0], 'purpose': 'ownership_control'}]]:
            self.denied(lambda: verify(issuers=issuers))
        self.assertEqual(verify(issuers=tuple(VECTORS['issuers'])).to_fields(), BASE['fields'])

    def test_revision_rollback_conflict_retry_and_signature_malleability(self):
        first, newer, maximum, alternate = (verify(VECTORS['valid'][i]) for i in [0, 5, 4, 6])
        compare = CODEC['compare_revision']
        self.assertEqual(compare(first, 0, None), 'newer')
        self.assertEqual(compare(first, 1, first.content_id), 'retry')
        self.assertEqual(first.content_id, alternate.content_id)
        self.assertNotEqual(BASE['signature_hex'], VECTORS['valid'][6]['signature_hex'])
        self.assertEqual(compare(alternate, 1, first.content_id), 'retry')
        self.assertEqual(compare(newer, 1, first.content_id), 'newer')
        self.assertEqual(compare(maximum, 2, newer.content_id), 'newer')
        self.assertEqual(compare(maximum, 4294967295, maximum.content_id), 'retry')
        for revision, content in [(0, first.content_id), (1, None), (1, b'x'), (1, 'x' * 32),
                                  (1, b'x' * 32), (2, newer.content_id), (-1, None),
                                  (4294967296, first.content_id), (True, None), (float('nan'), None),
                                  (float('inf'), None), (1.5, first.content_id)]:
            self.denied(lambda: compare(first, revision, content))
        # Canonical whole-number JSON values remain compatible with JSON Schema.
        numeric = {**BASE['fields'], 'v': 1.0, 'credential_revision': 1.0}
        self.assertEqual(CODEC['signing_bytes'](numeric).hex(), BASE['signing_hex'])
        # Return value does not mutate registry/storage or expose a field-command capability.
        with self.assertRaises(TypeError):
            first.metadata['role'] = 'Core'
        exported = first.to_fields(); exported['role'] = 'Core'
        self.assertEqual(first.to_fields()['role'], 'Link')
        self.assertNotIn('public_key', repr(first))

    def test_bounded_cbor_canonicality_all_widths_and_parser_failures(self):
        encode, decode = CODEC['cbor'], CODEC['uncbor']
        for value in [0, -1, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296,
                      18446744073709551615, -18446744073709551616, b'abc', 'æ', [], (), {}, {2: [], 1: b''}]:
            self.assertEqual(encode(decode(encode(value))), encode(value))
        for value in [None, True, 1.2, 18446744073709551616, -18446744073709551617,
                      b'x' * 513, 'x' * 513, [0] * 33, dict.fromkeys(range(33), 0), {'key': 1}, [[[[[0]]]]]]:
            self.denied(lambda: encode(value))
        bad = [b'', b'\x18', b'\x1c', b'\x1f', b'\x18\x00', b'\x61\xff', b'\x42x',
               b'\x00\x00', b'\xf6', b'\xc0\x00', b'\x98\x21', b'\xb8\x21',
               b'\xa2\x01\x00\x01\x00', b'\xa1\x40\x00', b'\xa2\x02\x00\x01\x00',
               b'\x81' * 6 + b'\x00', b'\xff', b'x' * 513, None, bytearray(b'\x00')]
        for value in bad:
            self.denied(lambda: decode(value))
        # Deterministic malformed corpus: parser may return canonical values only.
        rng = random.Random(4201)
        for _ in range(700):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 80)))
            try:
                decoded = decode(data)
            except ValueError as error:
                self.assertEqual(str(error), 'Invalid device credential')
            else:
                self.assertEqual(encode(decoded), data)

    def test_payload_and_envelope_types_and_missing_unknown_labels(self):
        encode = CODEC['cbor']
        env = CODEC['uncbor'](bytes.fromhex(BASE['hex'])[1:])
        def reject(envelope):
            data = b'\xd2' + encode(envelope)
            self.denied(lambda: CODEC['verify'](data, 'development', VECTORS['issuers'], CRYPTO, BASE['expected']))
        for value in [{}, [0] * 3, [0, {}, env[2], env[3]], [env[0], [], env[2], env[3]],
                      [env[0], {}, 0, env[3]], [env[0], {}, env[2], 0]]:
            reject(value)
        for header in [0, {}, {1: -7, 4: 1}, {1: -7, 4: b'x'}]:
            reject([encode(header), {}, env[2], env[3]])
        reject([env[0], {}, encode([]), env[3]])
        payload = CODEC['uncbor'](env[2])
        for label, value in [(1, b'\x01'), (2, b'\x01'), (4, 'invalid'), (4, b'x'),
                             (9, 'invalid'), (13, 1), (10, 1)]:
            body = {**payload, label: value}
            reject([env[0], {}, encode(body), env[3]])
        for signature in [None, 'x' * 64, b'x' * 63]:
            self.denied(lambda: CODEC['assemble'](BASE['fields'], signature))
        for value in [None, [], {**BASE['fields'], 'extra': 1}]:
            self.denied(lambda: CODEC['fields'](value))

    def test_negative_controls_signature_bypass_and_wrong_uuid_order(self):
        source = (FOLDER / 'codec.py').read_text()
        before = 'crypto.verify(key, message, envelope[3]) is True'
        self.assertEqual(source.count(before), 1)
        altered = {}; exec(compile(source.replace(before, 'True'), '<signature-bypass>', 'exec'), altered)
        bad = next(r for r in VECTORS['invalid_objects'] if r['name'] == 'tampered-signature')
        # A normal rejection assertion fails for this deliberately broken implementation.
        with self.assertRaises(AssertionError):
            self.denied(lambda: verify(bad, codec=altered))
        before = 'uuid.UUID(value).bytes'
        self.assertEqual(source.count(before), 1)
        altered = {}; exec(compile(source.replace(before, 'uuid.UUID(value).bytes_le'), '<wrong-uuid-order>', 'exec'), altered)
        with self.assertRaises(AssertionError):
            self.assertEqual(altered['signing_bytes'](BASE['fields']).hex(), BASE['signing_hex'])


class DeviceCredentialPinTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.folder = self.root / LOCK['path']
        shutil.copytree(FOLDER, self.folder)
        (self.root / 'device-credential.lock.json').write_text(json.dumps(LOCK))

    def repin(self):
        lock = copy.deepcopy(LOCK)
        lock['files'] = {name: hashlib.sha256((self.folder / name).read_bytes()).hexdigest() for name in LOCK['files']}
        (self.root / 'device-credential.lock.json').write_text(json.dumps(lock))

    def test_actual_pin_and_cli(self):
        expected = {name: len(VECTORS[name]) for name in ('valid', 'invalid_objects', 'invalid_fields')}
        self.assertEqual(checker.verify(ROOT), expected)
        self.assertEqual(checker.verify(self.root), expected)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runpy.run_path(str(ROOT / 'tools/verify_device_credential.py'), run_name='__main__')
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_pin_metadata_inventory_hashes_and_symlinks(self):
        for field, value in [('profile', 'other'), ('version', 2), ('source_repository', 'other'),
                             ('path', '../outside'), ('files', {})]:
            lock = {**LOCK, field: value}
            (self.root / 'device-credential.lock.json').write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError, 'Unsupported device credential pin'):
                checker.verify(self.root)
        (self.root / 'device-credential.lock.json').write_text(json.dumps(LOCK))
        extra = self.folder / 'extra'; extra.write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)
        extra.unlink()
        path = self.folder / 'codec.py'; original = path.read_bytes(); path.write_bytes(original + b'\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        path.write_bytes(original)
        lock = copy.deepcopy(LOCK); lock['files']['codec.py'] = 'invalid'
        (self.root / 'device-credential.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        (self.root / 'device-credential.lock.json').write_text(json.dumps(LOCK))
        path.unlink(); path.symlink_to(FOLDER / 'codec.py')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        shutil.rmtree(self.folder); self.folder.symlink_to(FOLDER, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)

    def test_repinned_profile_schema_and_vector_corruption(self):
        cases = [('profile.json', lambda x: x.update(version=2), 'profile'),
                 ('credential.schema.json', lambda x: x.update(additionalProperties=True), 'schema'),
                 ('vectors.json', lambda x: x.update(synthetic=False), 'vectors'),
                 ('vectors.json', lambda x: x.update(valid=[]), 'vectors'),
                 ('vectors.json', lambda x: x['valid'][0].update(signing_hex='00'), 'positive vector'),
                 ('vectors.json', lambda x: x['valid'][0].update(hex='00'), 'positive vector'),
                 ('vectors.json', lambda x: x['invalid_fields'][0].update(fields=BASE['fields']), 'invalid fields accepted')]
        for name, change, message in cases:
            path = self.folder / name; original = path.read_bytes(); value = json.loads(path.read_text())
            change(value); path.write_text(json.dumps(value)); self.repin()
            with self.subTest(name=name, message=message), self.assertRaisesRegex(ValueError, message):
                checker.verify(self.root)
            path.write_bytes(original); self.repin()
        path = self.folder / 'codec.py'; path.write_text(path.read_text().replace("ERROR = 'Invalid device credential'", "ERROR = 'sensitive payload'")); self.repin()
        with self.assertRaisesRegex(ValueError, 'may disclose'):
            checker.verify(self.root)

    def test_reference_failures_and_invalid_objects_cannot_become_valid(self):
        for result in [subprocess.CompletedProcess([], 1, '', ''), subprocess.CompletedProcess([], 0, '{}', '')]:
            with patch.object(checker.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'Independent device credential'):
                    checker.verify(self.root)
        path = self.folder / 'vectors.json'; value = json.loads(path.read_text())
        value['invalid_objects'][0] = {**value['invalid_objects'][0], 'hex': BASE['hex']}
        path.write_text(json.dumps(value)); self.repin()
        with self.assertRaisesRegex(ValueError, 'Independent device credential'):
            checker.verify(self.root)


if __name__ == '__main__':
    unittest.main()
