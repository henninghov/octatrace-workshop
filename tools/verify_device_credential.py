#!/usr/bin/env python3
"""Check pinned factory identity credentials. No private keys or device/cloud IO."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess

INVENTORY = {'profile.json', 'credential.schema.json', 'vectors.json', 'codec.py', 'reference.mjs'}
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
NAMES = ['v', 'purpose', 'environment', 'credential_uuid', 'credential_revision', 'device_uuid',
         'role', 'key_revision', 'public_key', 'serial', 'article_uuid', 'article_revision_uuid', 'hardware_uid']
PROFILE = {'format': 'octatrace-device-credential', 'version': 1,
           'purpose': 'factory identity only; no ownership, command authority or private-key possession proof',
           'cose': {'tag': 18, 'algorithm': -7, 'protected_labels': [1, 4], 'unprotected': {},
                    'issuer_kid_bytes': 8, 'signature_bytes': 64,
                    'external_aad': 'OCTATRACE-DEVICE-CREDENTIAL-1', 'hash': 'SHA-256 exactly once'},
           'payload_labels': {name: i + 1 for i, name in enumerate(NAMES)},
           'limits': {'object_bytes': 271, 'signing_bytes': 245, 'backend_signing_bytes': 512,
                      'revision_max': 4294967295, 'trusted_issuers': 8},
           'revision': 'monotonic per device; same revision and signed content is retry; conflicting/lower revision denied; never wrap',
           'expiry': 'none; factory identity does not grant field access',
           'references': ['https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2',
                          'https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1',
                          'https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1']}


def schema():
    props = {'v': {'type': 'integer', 'const': 1},
             'purpose': {'type': 'string', 'const': 'device_identity'},
             'environment': {'type': 'string', 'enum': ['development', 'production']},
             'role': {'type': 'string', 'enum': ['Link', 'Core']},
             'serial': {'type': 'string', 'minLength': 13, 'maxLength': 13,
                        'pattern': '^[DRO][0-9]{12}$', 'not': {'enum': [p + '0' * 12 for p in 'DRO']}}}
    for name in ('credential_uuid', 'device_uuid', 'article_uuid', 'article_revision_uuid'):
        props[name] = {'type': 'string', 'minLength': 36, 'maxLength': 36, 'pattern': '^' + UUID + '$'}
    for name in ('credential_revision', 'key_revision'):
        props[name] = {'type': 'integer', 'minimum': 1, 'maximum': 4294967295}
    for name in ('public_key', 'hardware_uid', 'issuer_kid'):
        length = 130 if name == 'public_key' else 16
        props[name] = {'type': 'string', 'minLength': length, 'maxLength': length,
                       'pattern': '^04[0-9a-f]{128}$' if length == 130 else '^[0-9a-f]{16}$',
                       'not': {'const': '0' * length}}
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema',
            '$id': 'urn:octatrace:device-credential:1', 'title': 'Factory device credential v1 metadata (not authority)',
            'type': 'object', 'additionalProperties': False, 'required': NAMES + ['issuer_kid'], 'properties': props}


def verify(root):
    root = Path(root).resolve()
    lock = json.loads((root / 'device-credential.lock.json').read_text())
    if (lock.get('profile') != 'octatrace-device-credential' or lock.get('version') != 1 or
            lock.get('source_repository') != 'octatrace-firmware' or
            lock.get('path') not in ('contracts/device-credential', 'vendor/device-credential') or
            set(lock.get('files', {})) != INVENTORY):
        raise ValueError('Unsupported device credential pin')
    folder = root / lock['path']
    if (folder.is_symlink() or not folder.resolve().is_relative_to(root) or
            {p.name for p in folder.iterdir() if p.is_file()} != INVENTORY):
        raise ValueError('Invalid device credential inventory')
    for name, digest in lock['files'].items():
        path = folder / name
        if (path.is_symlink() or not re.fullmatch('[0-9a-f]{64}', digest) or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError('Device credential checksum mismatch')
    if json.loads((folder / 'profile.json').read_text()) != PROFILE:
        raise ValueError('Unsupported device credential profile')
    if json.loads((folder / 'credential.schema.json').read_text()) != schema():
        raise ValueError('Unsupported device credential schema')
    codec = runpy.run_path(str(folder / 'codec.py'))
    vectors = json.loads((folder / 'vectors.json').read_text())
    if (vectors.get('synthetic') is not True or len(vectors['valid']) < 7 or
            len(vectors['invalid_objects']) < 30 or len(vectors['invalid_fields']) < 80):
        raise ValueError('Incomplete device credential vectors')
    for row in vectors['valid']:
        if (codec['signing_bytes'](row['fields']).hex() != row['signing_hex'] or
                codec['assemble'](row['fields'], bytes.fromhex(row['signature_hex'])).hex() != row['hex']):
            raise ValueError('Device credential positive vector mismatch')
    for row in vectors['invalid_fields']:
        try:
            codec['fields'](row['fields'])
        except ValueError as error:
            if str(error) != 'Invalid device credential':
                raise ValueError('Device credential error may disclose input') from None
        else:
            raise ValueError('Device credential invalid fields accepted')
    result = subprocess.run(['node', str(folder / 'reference.mjs'), str(folder / 'vectors.json')],
                            capture_output=True, text=True)
    expected = {name: len(vectors[name]) for name in ('valid', 'invalid_objects', 'invalid_fields')}
    if result.returncode or json.loads(result.stdout) != expected:
        raise ValueError('Independent device credential reference failed')
    return expected


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
