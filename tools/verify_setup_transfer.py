#!/usr/bin/env python3
"""Verify pinned candidate setup-record snapshots; no live BLE or authority."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess

INVENTORY = {'profile.json', 'record.schema.json', 'codec.py', 'reference.mjs', 'vectors.json'}
PROFILE_SHA256 = '3da9a73abfa2dd4b3d011d4c3eb255dd4a840d947d60bbafb549f7087538a563'
SCHEMA_SHA256 = '4f79a1d24d37a7ebb482130c53c05e9880522bb9d554506140a479684eb036ac'


def verify(root):
    root = Path(root).resolve()
    lock_path = root / 'setup-transfer.lock.json'
    if lock_path.is_symlink():
        raise ValueError('Invalid setup transfer pin')
    pin = json.loads(lock_path.read_text())
    if (pin.get('profile') != 'octatrace-setup-transfer' or type(pin.get('version')) is not int
            or pin['version'] != 1 or pin.get('source_repository') != 'octatrace-firmware'
            or pin.get('path') not in ('contracts/setup-transfer', 'vendor/setup-transfer')
            or set(pin.get('files', {})) != INVENTORY):
        raise ValueError('Invalid setup transfer pin')
    folder = root / pin['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir()} != INVENTORY:
        raise ValueError('Invalid setup transfer inventory')
    for name, expected in pin['files'].items():
        p = folder / name
        if p.is_symlink() or type(expected) is not str or not re.fullmatch('[0-9a-f]{64}', expected) or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            raise ValueError('Invalid setup transfer checksum')
    for family in ('device-credential', 'device-authority', 'proof-context', 'field-handshake'):
        dependency = json.loads((root / (family + '.lock.json')).read_text())
        if pin.get('requires_' + family.replace('-', '_') + '_files_sha256') != dependency['files']:
            raise ValueError('Invalid setup transfer dependency')
        for name, digest in dependency['files'].items():
            if hashlib.sha256((root / dependency['path'] / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Invalid setup transfer dependency bytes')
    if pin['files']['profile.json'] != PROFILE_SHA256 or pin['files']['record.schema.json'] != SCHEMA_SHA256:
        raise ValueError('Invalid setup transfer profile')
    codec = runpy.run_path(str(folder / 'codec.py'))
    vectors = json.loads((folder / 'vectors.json').read_text())
    if vectors.get('synthetic') is not True or len(vectors.get('valid', [])) < 16 or len(vectors.get('invalid_records', [])) < 8:
        raise ValueError('Invalid setup transfer vectors')
    for row in vectors['valid']:
        f = row['fields']
        data = codec['encode'](f['kind'], f['device_uuid'], f['correlation_uuid'], bytes.fromhex(f['body_hex']))
        decoded = codec['decode'](data)
        if data.hex() != row['hex'] or decoded.body.hex() != f['body_hex'] or [p.hex() for p in codec['frames'](data, row['transfer'])] != row['frames']:
            raise ValueError('Invalid setup transfer vector bytes')
    result = subprocess.run(['node', str(folder / 'reference.mjs'), str(folder / 'vectors.json')],
                            text=True, capture_output=True, check=True)
    reference = json.loads(result.stdout)
    if reference != {'valid': len(vectors['valid']), 'invalid': len(vectors['invalid_records']),
                     'result': 'pass', 'scope': 'untrusted record carrier only'}:
        raise ValueError('Invalid independent setup transfer reference')
    return {'result': 'pass', 'records': len(vectors['valid']), 'invalid_records': len(vectors['invalid_records']),
            'maximum_record_bytes': 494, 'maximum_bluetooth_frames': 42, 'authenticated_readiness': False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
