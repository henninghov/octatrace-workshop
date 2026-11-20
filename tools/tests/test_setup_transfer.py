"""Candidate transport boundaries; no signature/admission/storage success fake."""
import copy
import contextlib
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
from pathlib import Path
import random
import runpy
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'setup-transfer.lock.json').exists())
sys.path.insert(0, str(ROOT / 'tools'))
import verify_setup_transfer as checker
PIN = json.loads((ROOT / 'setup-transfer.lock.json').read_text())
FOLDER = ROOT / PIN['path']
C = runpy.run_path(str(FOLDER / 'codec.py'))
V = json.loads((FOLDER / 'vectors.json').read_text())
DEVICE = '01020304-0506-4708-890a-0b0c0d0e0f10'
CORRELATION = '11121314-1516-4718-991a-1b1c1d1e1f20'


def record(body=b'\xa5' * 426, kind='setup_challenge'):
    return C['encode'](kind, DEVICE, CORRELATION, body)


def receiver(**values):
    return C['Reassembly'](values.get('generation', 17), values.get('transfer', 3),
                           values.get('device', DEVICE), values.get('correlation', CORRELATION))


class CodecTest(unittest.TestCase):
    def test_readable_schema_has_exact_shapes_and_matches_public_vectors(self):
        from jsonschema import Draft202012Validator
        schema = json.loads((FOLDER / 'record.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for row in V['valid']:
            self.assertTrue(validator.is_valid(row['fields']))
        base = V['valid'][0]['fields']
        for bad in (None, {}, {**base, 'extra':True}, {**base, 'kind':True},
                    {**base, 'device_uuid':'bad'}, {**base, 'body_hex':'aa' * 272},
                    {**base, 'body_hex':''}, {**base, 'body_hex':'AA'},
                    {**base, 'kind':'phone_custody', 'body_hex':'00' * 32}):
            self.assertFalse(validator.is_valid(bad))

    def test_actual_signed_and_maximum_records_roundtrip_without_authority(self):
        for row in V['valid']:
            f = row['fields']; wire = bytes.fromhex(row['hex']); value = C['decode'](wire)
            self.assertEqual(C['encode'](f['kind'], f['device_uuid'], f['correlation_uuid'], bytes.fromhex(f['body_hex'])), wire)
            self.assertEqual((value.kind, value.device_uuid, value.correlation_uuid, value.body.hex()),
                             (f['kind'], f['device_uuid'], f['correlation_uuid'], f['body_hex']))
            self.assertTrue(type(value).__name__.startswith('Untrusted'))
            self.assertFalse(hasattr(value, 'installed'))
            with self.assertRaises(FrozenInstanceError):
                value.kind = 'grant'
        self.assertEqual(len(record()), 494)
        self.assertEqual(len(C['frames'](record(), 65535)), 42)

    def test_kind_lengths_uuid_and_custody_bounds(self):
        for kind, (_, maximum) in C['KINDS'].items():
            body = b'\xa5' * maximum
            self.assertEqual(len(C['encode'](kind, DEVICE, CORRELATION, body)), 68 + maximum)
            for bad in (b'', body + b'0', None, True, bytearray(body), 'secret'):
                with self.assertRaisesRegex(ValueError, '^Invalid setup transfer$'):
                    C['encode'](kind, DEVICE, CORRELATION, bad)
        for bad in (None, True, [], 'unknown'):
            with self.assertRaises(ValueError):
                C['encode'](bad, DEVICE, CORRELATION, b'a')
        for bad in (None, 1, DEVICE.upper(), 'bad', '00000000-0000-0000-0000-000000000000'):
            with self.assertRaises(ValueError): C['encode']('core_link', bad, CORRELATION, b'a')
            with self.assertRaises(ValueError): C['encode']('core_link', DEVICE, bad, b'a')
        for bad in (b'\0' * 32, b'a' * 31):
            with self.assertRaises(ValueError): C['encode']('phone_custody', DEVICE, CORRELATION, bad)

    def test_preparse_size_version_digest_length_unknown_kind_and_truncations(self):
        good = record()
        for bad in (None, True, '', bytearray(good), b'x' * 1000000, *[good[:n] for n in range(len(good))]):
            with self.assertRaises(ValueError): C['decode'](bad)
        for row in V['invalid_records']:
            with self.assertRaises(ValueError): C['decode'](bytes.fromhex(row['hex']))
        for offset in (0, 1, 8, 23, 34, 36, 100, len(good) - 1):
            changed = bytearray(good); changed[offset] ^= 0x80
            # UUID payload changes may still be canonical; enforce expected context at reassembly.
            if offset in (8, 23): continue
            with self.assertRaises(ValueError): C['decode'](bytes(changed))

    def test_exact_frames_and_reassembly_reorder_duplicates_deliver_once(self):
        for row in V['valid']:
            data = bytes.fromhex(row['hex']); f = row['fields']
            packets = C['frames'](data, row['transfer'])
            self.assertEqual([p.hex() for p in packets], row['frames'])
            rx = receiver(transfer=row['transfer'], device=f['device_uuid'], correlation=f['correlation_uuid'])
            outputs = []
            order = list(range(len(packets))); random.Random(7).shuffle(order)
            for i in order:
                value = rx.accept(17, packets[i])
                if value is not None: outputs.append(value)
                self.assertIsNone(rx.accept(17, packets[i]))
            self.assertEqual(len(outputs), 1)
            self.assertEqual(outputs[0].body.hex(), f['body_hex'])
            rx.close(); self.assertFalse(any(rx._buffer))
            with self.assertRaises(ValueError): rx.accept(17, packets[0])

    def test_bad_frames_cannot_resize_or_replace_admitted_context(self):
        packets = C['frames'](record(), 3)
        for bad in (None, True, '', bytearray(packets[0]), packets[0][:-1], packets[0] + b'\0'):
            with self.assertRaises(ValueError): C['parse_frame'](bad)
        for index, value in ((0, 0), (2, 0), (2, 2), (3, 0), (5, 0), (7, 255)):
            f = bytearray(packets[0]); f[index] = value
            if index == 3: f[4] = 0
            if index == 5: f[6] = 0
            with self.assertRaises(ValueError): C['parse_frame'](bytes(f))
        f = bytearray(packets[-1]); f[-1] = 1
        with self.assertRaises(ValueError): C['parse_frame'](bytes(f))
        rx = receiver(); rx.accept(17, packets[0]); before = bytes(rx._buffer)
        for generation in (None, True, 16, 18):
            with self.assertRaises(ValueError): rx.accept(generation, packets[1])
        with self.assertRaises(ValueError): rx.accept(17, C['frames'](record(), 4)[1])
        self.assertEqual(bytes(rx._buffer), before)

    def test_conflicts_hash_failure_and_wrong_subject_close_and_wipe(self):
        packets = C['frames'](record(), 3)
        rx = receiver(); rx.accept(17, packets[0]); bad = bytearray(packets[0]); bad[8] ^= 1
        with self.assertRaises(ValueError): rx.accept(17, bytes(bad))
        self.assertTrue(rx._closed); self.assertFalse(any(rx._buffer))
        rx = receiver(); rx.accept(17, packets[0]); different = C['frames'](record(b'a' * 425), 3)
        with self.assertRaises(ValueError): rx.accept(17, different[1])
        self.assertFalse(any(rx._buffer))
        for values in ({'device':CORRELATION}, {'correlation':DEVICE}, {}):
            rx = receiver(**values)
            changed = list(packets)
            if not values:
                f = bytearray(changed[-1]); f[8] ^= 1; changed[-1] = bytes(f)
            with self.assertRaises(ValueError):
                for f in changed: rx.accept(17, f)
            self.assertTrue(rx._closed); self.assertFalse(any(rx._buffer))

    def test_generation_and_transfer_ids_deny_bool_zero_overflow_and_wrong_types(self):
        for bad in (None, False, True, 0, -1, 65536, 1.0):
            with self.assertRaises(ValueError): C['frames'](record(), bad)
            with self.assertRaises(ValueError): receiver(transfer=bad)
        for bad in (None, True, 0, -1, 0x10000000000000000, 1.0):
            with self.assertRaises(ValueError): receiver(generation=bad)
        with self.assertRaises(ValueError): receiver(device='bad')
        with self.assertRaises(ValueError): receiver(correlation='bad')


class PinTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.root = Path(temp.name)
        self.folder = self.root / PIN['path']; shutil.copytree(FOLDER, self.folder)
        (self.root / 'setup-transfer.lock.json').write_text(json.dumps(PIN))
        for family in ('device-credential', 'device-authority', 'proof-context', 'field-handshake'):
            p = json.loads((ROOT / (family + '.lock.json')).read_text())
            (self.root / (family + '.lock.json')).write_text(json.dumps(p))
            shutil.copytree(ROOT / p['path'], self.root / p['path'])

    def test_owner_consumer_and_independent_node_reference(self):
        self.assertEqual(checker.verify(ROOT)['maximum_record_bytes'], 494)
        self.assertFalse(checker.verify(self.root)['authenticated_readiness'])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            runpy.run_path(str(ROOT / 'tools/verify_setup_transfer.py'), run_name='__main__')
        self.assertEqual(json.loads(out.getvalue())['records'], len(V['valid']))

    def repin(self):
        pin = copy.deepcopy(PIN)
        pin['files'] = {n:hashlib.sha256((self.folder / n).read_bytes()).hexdigest() for n in PIN['files']}
        (self.root / 'setup-transfer.lock.json').write_text(json.dumps(pin))

    def test_pin_hash_inventory_and_dependency_drift_fail(self):
        for key, value in (('version', True), ('version', 2), ('profile', 'unknown'),
                           ('path', '../escape'), ('source_repository', 'bad'), ('files', {})):
            (self.root / 'setup-transfer.lock.json').write_text(json.dumps({**PIN, key:value}))
            with self.assertRaises(ValueError): checker.verify(self.root)
        (self.root / 'setup-transfer.lock.json').write_text(json.dumps(PIN))
        extra = self.folder / 'extra'; extra.write_text('bad')
        with self.assertRaises(ValueError): checker.verify(self.root)
        extra.unlink(); p = self.folder / 'codec.py'; original = p.read_bytes(); p.write_bytes(original + b'\n')
        with self.assertRaises(ValueError): checker.verify(self.root)
        p.write_bytes(original)
        bad = copy.deepcopy(PIN); bad['requires_proof_context_files_sha256'] = {}
        (self.root / 'setup-transfer.lock.json').write_text(json.dumps(bad))
        with self.assertRaises(ValueError): checker.verify(self.root)

    def test_symlinks_dependency_bytes_and_repinned_profile_schema_are_rejected(self):
        p = self.root / 'setup-transfer.lock.json'; p.unlink(); p.symlink_to(ROOT / 'setup-transfer.lock.json')
        with self.assertRaises(ValueError): checker.verify(self.root)
        p.unlink(); p.write_text(json.dumps(PIN))
        dependency = json.loads((self.root / 'proof-context.lock.json').read_text())
        p = self.root / dependency['path'] / 'profile.json'; old = p.read_bytes(); p.write_bytes(old + b'\n')
        with self.assertRaises(ValueError): checker.verify(self.root)
        p.write_bytes(old)
        for name in ('profile.json', 'record.schema.json'):
            p = self.folder / name; old = p.read_bytes(); p.write_bytes(old + b'\n'); self.repin()
            with self.assertRaises(ValueError): checker.verify(self.root)
            p.write_bytes(old); self.repin()
        shutil.rmtree(self.folder); self.folder.symlink_to(FOLDER, target_is_directory=True)
        with self.assertRaises(ValueError): checker.verify(self.root)

    def test_invalid_vectors_actual_byte_mismatch_and_false_reference_cannot_pass(self):
        p = self.folder / 'vectors.json'; original = p.read_bytes()
        for modify in (lambda v:v.update(synthetic=False), lambda v:v.update(valid=[]),
                       lambda v:v['valid'][0].update(hex='00')):
            v = json.loads(original); modify(v); p.write_text(json.dumps(v)); self.repin()
            with self.assertRaises(ValueError): checker.verify(self.root)
        p.write_bytes(original); self.repin()
        with patch.object(checker.subprocess, 'run', return_value=type('Result', (), {'stdout':'{}'})()):
            with self.assertRaises(ValueError): checker.verify(self.root)
