#!/usr/bin/env python3
"""Verify signed owner/controller/peer metadata snapshots and independent vectors."""
import hashlib
import itertools
import json
from pathlib import Path
import re
import runpy
import subprocess

import verify_device_credential as dependency

INVENTORY = {'profile.json', 'authority.schema.json', 'vectors.json', 'codec.py', 'reference.mjs'}
NAMES = ['v', 'purpose', 'environment', 'object_uuid', 'revision', 'resource_uuid', 'resource_role',
         'resource_key_sha256', 'resource_key_revision', 'owner_ref', 'ownership_epoch']
CAPS = ['read_state', 'start', 'stop', 'rejoin']
COUNTS = ('valid', 'invalid_objects', 'invalid_fields', 'revisions', 'contexts', 'subjects')
PROFILE = {'format': 'octatrace-device-authority', 'version': 1,
           'purposes': {'ownership_receipt': 1, 'phone_controller': 2, 'core_link': 3},
           'cose': {'tag': 18, 'algorithm': -7, 'protected_labels': [1, 4], 'unprotected': {},
                    'issuer_kid_bytes': 8, 'signature_bytes': 64,
                    'external_aad': 'OCTATRACE-DEVICE-AUTHORITY-1', 'hash': 'SHA-256 exactly once'},
           'common_labels': {name: i + 1 for i, name in enumerate(NAMES)},
           'ownership_labels': {'claim_operation_uuid': 12},
           'policy_labels': {'state': 12, 'capabilities': 13},
           'phone_subject_labels': {'phone_installation_uuid': 14, 'phone_key_sha256': 15},
           'peer_subject_labels': {'link_uuid': 14, 'link_key_sha256': 15, 'link_key_revision': 16, 'link_ownership_epoch': 17},
           'state': {'grant': 1, 'removed': 2}, 'capabilities': dict(zip(CAPS, [1, 2, 4, 8])),
           'limits': {'object_bytes': 270, 'signing_bytes': 243, 'backend_signing_bytes': 512,
                      'revision_max': 4294967295, 'trusted_issuers': 8},
           'validity': 'No expiry or online renewal; effective removal/replacement requires delivery and durable installation',
           'revision': 'Per resource/purpose, never reset on owner change; lower/conflicting same revision denied; signed content excludes signature bytes',
           'owner': 'Opaque environment-scoped UUID; same owner required for controlling LINK and CORE; no team/reader/relay authority',
           'context': {'domain': 'OCTATRACE-AUTHORITY-CONTEXT-1', 'bytes': 32,
                       'input': 'CBOR [domain-bstr, policy-content-sha256, resource-owner-content-sha256, link-owner-content-sha256-or-empty-bstr]',
                       'meaning': 'Stable policy binding only; not a fresh proof, installed readiness or command permission'},
           'subject_binding': 'Exact Phone installation or Link UUID and SHA256(point65); point validation; fresh private-key possession proof is separate',
           'references': ['https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2',
                          'https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1',
                          'https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1']}


def schema():
    uuid = {'type': 'string', 'minLength': 36, 'maxLength': 36, 'pattern': '^' + dependency.UUID + '$'}
    digest = {'type': 'string', 'minLength': 64, 'maxLength': 64, 'pattern': '^[0-9a-f]{64}$', 'not': {'const': '0' * 64}}
    revision = {'type': 'integer', 'minimum': 1, 'maximum': 4294967295}
    common = {'v': {'type': 'integer', 'const': 1}, 'environment': {'type': 'string', 'enum': ['development', 'production']},
              'object_uuid': uuid, 'revision': revision, 'resource_uuid': uuid,
              'resource_key_sha256': digest, 'resource_key_revision': revision,
              'owner_ref': uuid, 'ownership_epoch': revision,
              'issuer_kid': {'type': 'string', 'minLength': 16, 'maxLength': 16,
                             'pattern': '^[0-9a-f]{16}$', 'not': {'const': '0' * 16}}}
    variants = []
    for purpose, role in [('ownership_receipt', None), ('phone_controller', 'Link'), ('core_link', 'Core')]:
        for state in ([None] if role is None else ['grant', 'removed']):
            props = {**common, 'purpose': {'type': 'string', 'const': purpose},
                     'resource_role': {'type': 'string', 'enum': ['Link', 'Core']} if role is None else {'type': 'string', 'const': role}}
            if role is None:
                props['claim_operation_uuid'] = uuid
            else:
                props['state'] = {'type': 'string', 'const': state}
                combinations = [list(c) for n in range(1, 5) for c in itertools.combinations(CAPS, n)] if state == 'grant' else [[]]
                props['capabilities'] = {'type': 'array', 'enum': combinations}
                if state == 'grant':
                    if purpose == 'phone_controller':
                        props.update(phone_installation_uuid=uuid, phone_key_sha256=digest)
                    else:
                        props.update(link_uuid=uuid, link_key_sha256=digest, link_key_revision=revision, link_ownership_epoch=revision)
            variants.append({'type': 'object', 'additionalProperties': False,
                             'required': list(props), 'properties': props})
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:octatrace:device-authority:1',
            'title': 'Signed ownership/control metadata v1; not bearer permission', 'oneOf': variants}


def verify(root):
    root = Path(root).resolve()
    lock = json.loads((root / 'device-authority.lock.json').read_text())
    if (lock.get('profile') != 'octatrace-device-authority' or lock.get('version') != 1 or
            lock.get('source_repository') != 'octatrace-firmware' or
            lock.get('path') not in ('contracts/device-authority', 'vendor/device-authority') or
            set(lock.get('files', {})) != INVENTORY):
        raise ValueError('Unsupported device authority pin')
    dependency.verify(root)
    dep = json.loads((root / 'device-credential.lock.json').read_text())
    if lock.get('requires_device_credential_files_sha256') != dep['files']:
        raise ValueError('Device authority dependency mismatch')
    folder = root / lock['path']
    if (folder.is_symlink() or not folder.resolve().is_relative_to(root) or
            {p.name for p in folder.iterdir() if p.is_file()} != INVENTORY):
        raise ValueError('Invalid device authority inventory')
    for name, digest in lock['files'].items():
        path = folder / name
        if (path.is_symlink() or not re.fullmatch('[0-9a-f]{64}', digest) or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError('Device authority checksum mismatch')
    if json.loads((folder / 'profile.json').read_text()) != PROFILE:
        raise ValueError('Unsupported device authority profile')
    if json.loads((folder / 'authority.schema.json').read_text()) != schema():
        raise ValueError('Unsupported device authority schema')
    codec = runpy.run_path(str(folder / 'codec.py'))
    vectors = json.loads((folder / 'vectors.json').read_text())
    if vectors.get('synthetic') is not True or any(len(vectors[k]) < minimum for k, minimum in zip(COUNTS, [42, 109, 325, 28, 27, 12])):
        raise ValueError('Incomplete device authority vectors')
    for row in vectors['valid']:
        if (codec['signing_bytes'](row['fields']).hex() != row['signing_hex'] or
                codec['assemble'](row['fields'], bytes.fromhex(row['signature_hex'])).hex() != row['hex']):
            raise ValueError('Device authority positive vector mismatch')
    for row in vectors['invalid_fields']:
        try:
            codec['fields'](row['fields'])
        except ValueError as error:
            if str(error) != 'Invalid device authority':
                raise ValueError('Device authority error may disclose input') from None
        else:
            raise ValueError('Device authority invalid fields accepted')
    result = subprocess.run(['node', str(folder / 'reference.mjs'), str(folder / 'vectors.json')], capture_output=True, text=True)
    expected = {name: len(vectors[name]) for name in COUNTS}
    if result.returncode or json.loads(result.stdout) != expected:
        raise ValueError('Independent device authority reference failed')
    return expected


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
