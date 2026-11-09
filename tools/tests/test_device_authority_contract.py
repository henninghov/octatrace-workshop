"""Ownership/control contract tests. Public fixtures only; no command or cloud IO."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'device-authority.lock.json').is_file())
sys.path.insert(0, str(ROOT / 'tools'))
import verify_device_authority as checker
LOCK = json.loads((ROOT / 'device-authority.lock.json').read_text())
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
ROWS = {r['name']: r for r in VECTORS['valid']}
BASE = ROWS['dev-phone1']


def verify(row=BASE, codec=CODEC, **options):
    args = dict(environment=row.get('environment', row.get('fields', {}).get('environment')),
                issuers=row.get('issuers', VECTORS['issuers']), crypto=CRYPTO, expected=row['expected'])
    args.update(options)
    return codec['verify'](bytes.fromhex(row['hex']), **args)


def verified(name, codec=CODEC):
    return verify(ROWS[name], codec=codec)


class AuthorityContractTest(unittest.TestCase):
    def denied(self, operation):
        with self.assertRaisesRegex(ValueError, '^Invalid device authority$'):
            operation()

    def test_independent_signed_bytes_all_purposes_roles_environments_and_bounds(self):
        combinations = set()
        for row in VECTORS['valid']:
            with self.subTest(name=row['name']):
                self.assertEqual(CODEC['signing_bytes'](row['fields']).hex(), row['signing_hex'])
                self.assertEqual(CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex'])).hex(), row['hex'])
                value = verify(row)
                self.assertEqual(value.to_fields(), row['fields'])
                self.assertEqual(value.content_id.hex(), hashlib.sha256(bytes.fromhex(row['signing_hex'])).hexdigest())
                combinations.add((row['fields']['purpose'], row['fields']['environment']))
        self.assertEqual(combinations, {(p, e) for p in CODEC['PURPOSES'] for e in ('development', 'production')})
        self.assertEqual(max(len(bytes.fromhex(r['hex'])) for r in VECTORS['valid']), 270)
        self.assertEqual(max(len(bytes.fromhex(r['signing_hex'])) for r in VECTORS['valid']), 243)
        self.assertLessEqual(243, 512)

    def test_invalid_signed_objects_and_metadata_are_denied_without_disclosure(self):
        for row in VECTORS['invalid_objects']:
            with self.subTest(name=row['name']):
                self.denied(lambda: verify(row))
        for row in VECTORS['invalid_fields']:
            with self.subTest(name=row['name']):
                self.denied(lambda: CODEC['fields'](row['fields']))

    def test_revision_replacement_removal_and_owner_epoch_vectors(self):
        for row in VECTORS['revisions']:
            with self.subTest(name=row['name']):
                current = verified(row['current'])
                previous = verified(row['previous']) if row['previous'] else None
                operation = lambda: CODEC['compare_revision'](current, previous)
                if row['result'] == 'deny':
                    self.denied(operation)
                else:
                    self.assertEqual(operation(), row['result'])
        first, alternate = verified('dev-phone1'), verified('dev-phone1-alternate-signature')
        self.assertNotEqual(ROWS['dev-phone1']['signature_hex'], ROWS['dev-phone1-alternate-signature']['signature_hex'])
        self.assertEqual(first.content_id, alternate.content_id)
        self.denied(lambda: CODEC['compare_revision'](None))
        self.denied(lambda: CODEC['compare_revision'](first, {}))

    def test_current_owner_binding_both_core_and_link_and_stable_context_vectors(self):
        for row in VECTORS['contexts']:
            with self.subTest(name=row['name']):
                args = (verified(row['policy']), verified(row['owner']), verified(row['link_owner']) if row.get('link_owner') else None)
                operation = lambda: CODEC['authority_context'](*args)
                if row['result'] == 'deny':
                    self.denied(operation)
                else:
                    self.assertEqual(operation().hex(), row['result'])
        self.assertNotEqual(CODEC['authority_context'](verified('dev-phone1'), verified('dev-link-owner')),
                            CODEC['authority_context'](verified('dev-phone2'), verified('dev-link-owner')))
        # A tombstone is valid to install but cannot establish control context.
        CODEC['check_owners'](verified('dev-phone-removed'), verified('dev-link-owner'))
        CODEC['check_owners'](verified('dev-coreA-removed'), verified('dev-coreA-owner'))
        self.denied(lambda: CODEC['check_owners'](verified('dev-coreA-peer1'), verified('dev-coreA-owner'), verified('dev-coreA-owner')))
        self.denied(lambda: CODEC['check_owners'](verified('dev-coreA-removed'), verified('dev-coreA-owner'), verified('dev-link-owner')))
        self.denied(lambda: CODEC['check_owners'](None, verified('dev-link-owner')))

    def test_subject_key_vectors_include_old_phone_and_peer_replacement(self):
        for row in VECTORS['subjects']:
            with self.subTest(name=row['name']):
                operation = lambda: CODEC['check_subject_key'](verified(row['policy']), row['role'], row['uuid'], bytes.fromhex(row['public_key']), CRYPTO)
                if row['result'] == 'deny':
                    self.denied(operation)
                else:
                    self.assertIsNone(operation())
        row = VECTORS['subjects'][0]; policy = verified(row['policy']); point = bytes.fromhex(row['public_key'])
        for wrong in [None, '04', b'x' * 65, b'\x04' * 64, bytearray(point)]:
            self.denied(lambda: CODEC['check_subject_key'](policy, row['role'], row['uuid'], wrong, CRYPTO))
        for result in [False, 1, None]:
            with patch.object(CRYPTO, 'valid_public_key', return_value=result):
                self.denied(lambda: CODEC['check_subject_key'](policy, row['role'], row['uuid'], point, CRYPTO))
        with patch.object(CRYPTO, 'valid_public_key', side_effect=RuntimeError('secret')):
            self.denied(lambda: CODEC['check_subject_key'](policy, row['role'], row['uuid'], point, CRYPTO))
        # This returns no permission: a copied public point can match; fresh key proof is still required.
        self.assertIsNone(CODEC['check_subject_key'](policy, row['role'], row['uuid'], point, CRYPTO))

    def test_explicit_capabilities_do_not_add_team_owner_reader_or_movement_access(self):
        for op in CODEC['CAPABILITIES']:
            self.assertTrue(CODEC['has_capability'](verified('dev-phone1'), op))
            self.assertFalse(CODEC['has_capability'](verified('dev-phone-removed'), op))
            self.assertEqual(CODEC['has_capability'](verified('dev-read-only'), op), op == 'read_state')
        for op in ['admin', 'movement', 'transfer_owner', 'claim', 'team_start', None, ['start']]:
            self.denied(lambda: CODEC['has_capability'](verified('dev-phone1'), op))
        self.denied(lambda: CODEC['has_capability'](verified('dev-link-owner'), 'start'))

    def test_offline_evaluation_has_no_clock_expiry_network_or_periodic_renewal(self):
        policy, owner = verified('dev-phone1'), verified('dev-link-owner')
        before = CODEC['authority_context'](policy, owner)
        with patch.object(socket, 'create_connection', side_effect=AssertionError('Unexpected network')), \
             patch.object(time, 'time', side_effect=AssertionError('Unexpected wall clock')):
            self.assertEqual(CODEC['authority_context'](policy, owner), before)
            self.assertTrue(CODEC['has_capability'](policy, 'start'))
            self.assertEqual(CODEC['compare_revision'](policy, policy), 'retry')
        self.assertNotIn('expires_at', policy.to_fields())
        self.assertNotIn('fresh_proof', policy.to_fields())
        # Stable context survives reading the same bytes; it makes no fresh-handshake/reboot claim.
        self.assertEqual(CODEC['authority_context'](verify(), owner), before)

    def test_returned_metadata_is_deeply_immutable_and_public_repr_is_redacted(self):
        result = verify()
        with self.assertRaises(TypeError):
            result.metadata['owner_ref'] = 'other'
        with self.assertRaises(TypeError):
            result.metadata['capabilities'][0] = 'other'
        exported = result.to_fields(); exported['capabilities'].append('movement')
        self.assertEqual(result.to_fields(), BASE['fields'])
        self.assertNotIn('owner_ref', repr(result))

    def test_exact_purpose_and_state_vocabulary_in_converter(self):
        for label, number in [('ownership_receipt', 1), ('phone_controller', 2), ('core_link', 3)]:
            self.assertEqual(CODEC['to_wire'](label, 'purpose'), number)
        for label, number in [('grant', 1), ('removed', 2)]:
            self.assertEqual(CODEC['to_wire'](label, 'state'), number)
        for kind in ['purpose', 'state']:
            for value in [None, 1, [], 'admin', 'factory_identity']:
                self.denied(lambda: CODEC['to_wire'](value, kind))

    def test_caller_capacity_and_invalid_construction_limits(self):
        row = ROWS['dev-coreA-peer1-maximum']
        self.assertEqual(len(CODEC['signing_bytes'](row['fields'], 243)), 243)
        self.denied(lambda: CODEC['signing_bytes'](row['fields'], 242))
        self.assertEqual(len(CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex']), 270)), 270)
        self.denied(lambda: CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex']), 269))
        for limit in [None, True, 0, -1, 513]:
            self.denied(lambda: CODEC['signing_bytes'](row['fields'], limit))
            self.denied(lambda: CODEC['assemble'](row['fields'], bytes.fromhex(row['signature_hex']), limit))
        for signature in [None, 'x' * 64, b'x' * 63]:
            self.denied(lambda: CODEC['assemble'](BASE['fields'], signature))
        numeric = {**BASE['fields'], 'v': 1.0, 'revision': 1.0}
        self.assertEqual(CODEC['signing_bytes'](numeric).hex(), BASE['signing_hex'])

    def test_every_truncation_large_input_and_seeded_malformed_wire(self):
        for row in [ROWS['dev-link-owner'], BASE, ROWS['dev-coreA-peer1']]:
            raw = bytes.fromhex(row['hex'])
            for n in range(len(raw)):
                self.denied(lambda: CODEC['verify'](raw[:n], row['fields']['environment'], VECTORS['issuers'], CRYPTO, row['expected']))
        for value in [None, 'secret', [], bytearray(bytes.fromhex(BASE['hex'])), b'x' * 1000000]:
            with patch.dict(CODEC['BASE'], uncbor=lambda _: self.fail('Parsed unbounded input')):
                self.denied(lambda: CODEC['verify'](value, 'development', [], CRYPTO, {}))
        rng = random.Random(4202)
        for _ in range(500):
            raw = b'\xd2' + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 100)))
            self.denied(lambda: CODEC['verify'](raw, 'development', VECTORS['issuers'], CRYPTO, BASE['expected']))

    def test_wrong_expected_bindings_and_issuer_adapters_fail_closed(self):
        for env in [None, 'staging', [], 1]:
            self.denied(lambda: verify(environment=env))
        for expected in [None, [], {}, {**BASE['expected'], 'owner': 'x'},
                         {**BASE['expected'], 'resource_uuid': 'invalid'},
                         {**BASE['expected'], 'resource_role': 'Phone'},
                         {**BASE['expected'], 'resource_key_revision': True},
                         {**BASE['expected'], 'resource_key_sha256': '0' * 64}]:
            self.denied(lambda: verify(expected=expected))
        for method in ['valid_public_key', 'verify']:
            for result in [False, 1, None]:
                with patch.object(CRYPTO, method, return_value=result):
                    self.denied(lambda: verify())
            with patch.object(CRYPTO, method, side_effect=RuntimeError('secret data')):
                self.denied(lambda: verify())
        self.denied(lambda: verify(crypto=None))
        for issuers in [None, {}, [], VECTORS['issuers'] * 3, [None], [{}],
                        [{**VECTORS['issuers'][2], 'environment': 'staging'}],
                        [{**VECTORS['issuers'][2], 'purpose': 'anything'}],
                        [{**VECTORS['issuers'][2], 'kid': '00' * 8}],
                        [{**VECTORS['issuers'][2], 'public_key': '02' + '11' * 64}],
                        [VECTORS['issuers'][2], {**VECTORS['issuers'][2], 'purpose': 'factory_identity'}]]:
            self.denied(lambda: verify(issuers=issuers))
        self.assertEqual(verify(issuers=tuple(VECTORS['issuers'])).to_fields(), BASE['fields'])

    def test_envelope_payload_scalar_and_field_type_failures(self):
        enc, dec = CODEC['BASE']['cbor'], CODEC['BASE']['uncbor']
        env = dec(bytes.fromhex(BASE['hex'])[1:]);body = dec(env[2])
        def reject(envelope):
            raw = b'\xd2' + enc(envelope)
            self.denied(lambda: CODEC['verify'](raw, 'development', VECTORS['issuers'], CRYPTO, BASE['expected']))
        for item in [{}, [0] * 3, [0, {}, env[2], env[3]], [env[0], [], env[2], env[3]],
                     [env[0], {}, 0, env[3]], [env[0], {}, env[2], 0]]:
            reject(item)
        for header in [0, {}, {1: -7, 4: 1}, {1: -7, 4: b'x'}]:
            reject([enc(header), {}, env[2], env[3]])
        for payload in [[], {}, {1: 1}]:
            reject([env[0], {}, enc(payload), env[3]])
        for label, value in [(1, b'\x01'), (2, b'\x01'), (4, 'invalid'), (4, b'x'),
                             (8, 'invalid'), (13, b'\x01'), (13, -1)]:
            reject([env[0], {}, enc({**body, label: value}), env[3]])
        for value in [None, [], {}, {'purpose': []}, {**BASE['fields'], 'purpose': 'wrong'},
                      {**BASE['fields'], 'capabilities': ['read_state', True]},
                      {**BASE['fields'], 'state': []}]:
            self.denied(lambda: CODEC['fields'](value))
        # Nested/canonical CBOR rules are reused from the exact independently pinned b1 parser.
        for raw in [b'\xd2\x18\x00', b'\xd2\x61\xff', b'\xd2' + b'\x81' * 6 + b'\x00']:
            self.denied(lambda: CODEC['verify'](raw, 'development', VECTORS['issuers'], CRYPTO, BASE['expected']))

    def test_negative_controls_signature_bypass_revision_rollback_and_owner_check(self):
        source = (FOLDER / 'codec.py').read_text()
        def altered(before, after):
            self.assertEqual(source.count(before), 1)
            scope = {'__file__': str(FOLDER / 'codec.py')}
            exec(compile(source.replace(before, after), '<authority-negative-control>', 'exec'), scope)
            return scope
        bad = next(r for r in VECTORS['invalid_objects'] if r['name'] == 'dev-phone1-signature')
        variant = altered('crypto.verify(key, message, envelope[3]) is True', 'True')
        with self.assertRaises(AssertionError):
            self.denied(lambda: verify(bad, codec=variant))
        variant = altered(" or new['revision'] < old['revision']", '')
        with self.assertRaises(AssertionError):
            self.denied(lambda: variant['compare_revision'](verified('dev-phone1', variant), verified('dev-phone-removed', variant)))
        variant = altered("link['owner_ref'] != value['owner_ref']", 'False')
        with self.assertRaises(AssertionError):
            self.denied(lambda: variant['authority_context'](verified('dev-new-owner-core-old-link', variant), verified('dev-core-transfer', variant), verified('dev-link-owner', variant)))


class AuthorityPinTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.folder = self.root / LOCK['path']
        shutil.copytree(FOLDER, self.folder)
        dep = json.loads((ROOT / 'device-credential.lock.json').read_text())
        shutil.copytree(ROOT / dep['path'], self.root / dep['path'])
        (self.root / 'device-credential.lock.json').write_text(json.dumps(dep))
        (self.root / 'device-authority.lock.json').write_text(json.dumps(LOCK))

    def repin(self):
        lock = copy.deepcopy(LOCK)
        lock['files'] = {name: hashlib.sha256((self.folder / name).read_bytes()).hexdigest() for name in LOCK['files']}
        (self.root / 'device-authority.lock.json').write_text(json.dumps(lock))

    def test_actual_pin_and_cli_and_dependency(self):
        expected = {k: len(VECTORS[k]) for k in checker.COUNTS}
        self.assertEqual(checker.verify(ROOT), expected)
        self.assertEqual(checker.verify(self.root), expected)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            runpy.run_path(str(ROOT / 'tools/verify_device_authority.py'), run_name='__main__')
        self.assertEqual(json.loads(out.getvalue()), expected)
        lock = copy.deepcopy(LOCK); lock['requires_device_credential_files_sha256'] = {}
        (self.root / 'device-authority.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, 'dependency mismatch'):
            checker.verify(self.root)

    def test_lock_inventory_hashes_and_symlinks(self):
        for name, value in [('profile', 'other'), ('version', 2), ('source_repository', 'other'),
                            ('path', '../outside'), ('files', {})]:
            lock = {**LOCK, name: value}
            (self.root / 'device-authority.lock.json').write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError, 'Unsupported device authority pin'):
                checker.verify(self.root)
        (self.root / 'device-authority.lock.json').write_text(json.dumps(LOCK))
        extra = self.folder / 'extra'; extra.write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)
        extra.unlink()
        path = self.folder / 'codec.py'; original = path.read_bytes(); path.write_bytes(original + b'\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        path.write_bytes(original)
        lock = copy.deepcopy(LOCK); lock['files']['codec.py'] = 'invalid'
        (self.root / 'device-authority.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        (self.root / 'device-authority.lock.json').write_text(json.dumps(LOCK))
        path.unlink(); path.symlink_to(FOLDER / 'codec.py')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            checker.verify(self.root)
        shutil.rmtree(self.folder); self.folder.symlink_to(FOLDER, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            checker.verify(self.root)

    def test_repinned_schema_profile_vectors_and_disclosing_diagnostics_fail(self):
        for name, change, message in [
            ('profile.json', lambda x: x.update(version=2), 'profile'),
            ('authority.schema.json', lambda x: x.update(oneOf=[]), 'schema'),
            ('vectors.json', lambda x: x.update(synthetic=False), 'vectors'),
            ('vectors.json', lambda x: x.update(valid=[]), 'vectors'),
            ('vectors.json', lambda x: x['valid'][0].update(signing_hex='00'), 'positive vector'),
            ('vectors.json', lambda x: x['valid'][0].update(hex='00'), 'positive vector'),
            ('vectors.json', lambda x: x['invalid_fields'][0].update(fields=BASE['fields']), 'invalid fields accepted')]:
            path = self.folder / name; original = path.read_bytes(); value = json.loads(path.read_text())
            change(value); path.write_text(json.dumps(value)); self.repin()
            with self.subTest(name=name, message=message), self.assertRaisesRegex(ValueError, message):
                checker.verify(self.root)
            path.write_bytes(original); self.repin()
        path = self.folder / 'codec.py'; path.write_text(path.read_text().replace("ERROR = 'Invalid device authority'", "ERROR = 'sensitive input'")); self.repin()
        with self.assertRaisesRegex(ValueError, 'may disclose'):
            checker.verify(self.root)

    def test_independent_reference_failure_and_corrupted_rejection_vectors(self):
        # Preserve real dependency checks when simulating only the authority subprocess result.
        actual = checker.subprocess.run
        for result in [subprocess.CompletedProcess([], 1, '', ''), subprocess.CompletedProcess([], 0, '{}', '')]:
            def run(args, **kwargs):
                return result if 'device-authority/reference.mjs' in args[1] else actual(args, **kwargs)
            with patch.object(checker.subprocess, 'run', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'Independent device authority'):
                    checker.verify(self.root)
        path = self.folder / 'vectors.json'; value = json.loads(path.read_text())
        value['invalid_objects'][0].update(hex=ROWS['dev-link-owner']['hex'])
        path.write_text(json.dumps(value)); self.repin()
        with self.assertRaisesRegex(ValueError, 'Independent device authority'):
            checker.verify(self.root)


if __name__ == '__main__':
    unittest.main()
