#!/usr/bin/env python3
"""Check a complete pinned claim-QR snapshot and both independent codecs."""
import base64
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess

INVENTORY = {'profile.json', 'claim.schema.json', 'vectors.json', 'codec.py', 'reference.mjs'}


def verify(root):
    root = Path(root).resolve()
    lock = json.loads((root / 'claim-qr.lock.json').read_text())
    if (lock.get('profile') != 'octatrace-claim-qr' or lock.get('version') != 1 or
            lock.get('source_repository') != 'octatrace-firmware' or
            lock.get('path') not in ('contracts/claim-qr', 'vendor/claim-qr') or
            set(lock.get('files', {})) != INVENTORY):
        raise ValueError('Unsupported claim QR pin')
    folder = (root / lock['path']).resolve()
    if not folder.is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()} != INVENTORY:
        raise ValueError('Invalid claim QR inventory')
    for name, digest in lock['files'].items():
        path = folder / name
        if (path.is_symlink() or not re.fullmatch('[0-9a-f]{64}', digest) or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError('Claim QR checksum mismatch')
    profile = json.loads((folder / 'profile.json').read_text())
    if (profile['format'] != 'octatrace-claim-qr' or profile['version'] != 1 or
            profile['text'] != {'prefix': 'OCTATRACE-CLAIM-1:', 'characters': 145,
                                'encoding': 'ASCII; unpadded canonical base64url'} or
            profile['cbor']['bytes'] != 95 or
            profile['cbor']['map_pairs'] != 6 or
            profile['cbor']['fields'] != [
                {'key': i + 1, 'name': name, 'encoding': 'uint' if i < 3 else 'bstr',
                 'bytes': size} for i, (name, size) in enumerate(zip(
                     ('v', 'environment', 'role', 'device_uuid', 'public_key_sha256', 'claim_secret'),
                     (1, 1, 1, 16, 32, 32)))] or
            profile['environment'] != {'development': 1, 'production': 2} or
            profile['role'] != {'Link': 1, 'Core': 2} or
            profile['authority'] != 'untrusted input; online registry and claim verification required'):
        raise ValueError('Unsupported claim QR profile')
    codec = runpy.run_path(str(folder / 'codec.py'))
    schema = json.loads((folder / 'claim.schema.json').read_text())
    properties = {
        'v': {'type': 'integer', 'const': 1},
        'environment': {'type': 'string', 'enum': ['development', 'production']},
        'role': {'type': 'string', 'enum': ['Link', 'Core']},
        'device_uuid': {'type': 'string', 'minLength': 36, 'maxLength': 36,
                        'pattern': '^' + codec['UUID'] + '$'}}
    for name in ('public_key_sha256', 'claim_secret'):
        properties[name] = {'type': 'string', 'minLength': 64, 'maxLength': 64,
                            'pattern': '^' + codec['HEX32'] + '$', 'not': {'const': '0' * 64}}
    properties['claim_secret']['writeOnly'] = True
    if schema != {'$schema': 'https://json-schema.org/draft/2020-12/schema',
                  '$id': 'urn:octatrace:claim-qr:1', 'title': 'Untrusted claim QR v1 fields',
                  'type': 'object', 'additionalProperties': False,
                  'required': list(codec['FIELDS']), 'properties': properties}:
        raise ValueError('Unsupported claim QR schema')
    vectors = json.loads((folder / 'vectors.json').read_text())
    if not vectors['synthetic'] or len(vectors['valid']) < 4 or len(vectors['invalid_text']) < 40 or len(vectors['invalid_fields']) < 20:
        raise ValueError('Incomplete claim QR vectors')
    for row in vectors['valid']:
        if (codec['encode'](row['fields']) != row['text'] or
                codec['decode'](row['text'], row['fields']['environment']).to_fields() != row['fields'] or
                base64.urlsafe_b64decode(row['text'][18:] + '=').hex() != row['cbor_hex']):
            raise ValueError('Claim QR positive vector mismatch')
    for kind, operation in [('invalid_text', lambda r: codec['decode'](r['text'], r['environment'])),
                            ('invalid_fields', lambda r: codec['encode'](r['fields']))]:
        for row in vectors[kind]:
            try:
                operation(row)
            except ValueError as error:
                if str(error) != 'Invalid claim QR':
                    raise ValueError('Claim QR error may disclose input') from None
            else:
                raise ValueError('Claim QR negative vector accepted')
    result = subprocess.run(['node', str(folder / 'reference.mjs'), str(folder / 'vectors.json')],
                            capture_output=True, text=True)
    expected = {name: len(vectors[name]) for name in ('valid', 'invalid_text', 'invalid_fields')}
    if result.returncode or json.loads(result.stdout) != expected:
        raise ValueError('Independent claim QR reference failed')
    return expected


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
