#!/usr/bin/env python3
"""Verify the pinned credential reservation; no device IO or erasure."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import verify_authority_layout
import verify_device_credential

FILES = {'contract.json': 'a649dea15d72db0585a6aaecf75748e236a411861d2aeacc1501e4a07f6964f5',
         'manifest.schema.json': '585b7e1381b92758d5946a39287e3b8fab4f37c058187c51d3c2bbe0ddd31f67',
         'policy.py': 'c85a2546098c1d487f0b91f2f5ed3bb5f446a78dc3ca680059159551e4947635'}
PROFILE = 't114-nrf52840-s140v6-credential-reservation-v1'
GUARD_SHA256 = '632eae7afadb681dd5e6536e66c290791837a2eaad2cd5d9c2cee94e07853201'


def verify(root):
    root = Path(root).resolve()
    pin = json.loads((root / 'credential-layout.lock.json').read_text())
    if (pin.get('profile') != 'octatrace-credential-layout' or type(pin.get('version')) is not int or pin.get('version') != 1 or
            pin.get('source_repository') != 'octatrace-firmware' or
            pin.get('path') not in ('contracts/credential-layout', 'vendor/credential-layout') or
            pin.get('files') != FILES):
        raise ValueError('Unsupported credential layout pin')
    verify_authority_layout.verify(root)
    verify_device_credential.verify(root)
    authority = json.loads((root / 'authority-layout.lock.json').read_text())
    credential = json.loads((root / 'device-credential.lock.json').read_text())
    if (pin.get('requires_authority_layout_files_sha256') != authority['files'] or
            pin.get('requires_device_credential_files_sha256') != credential['files']):
        raise ValueError('Credential layout dependency mismatch')
    folder = root / pin['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()} != set(FILES):
        raise ValueError('Invalid credential layout inventory')
    for name, digest in pin['files'].items():
        file = folder / name
        if file.is_symlink() or not re.fullmatch('[0-9a-f]{64}', digest) or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError('Credential layout checksum mismatch')
    contract = json.loads((folder / 'contract.json').read_text())
    policy = runpy.run_path(str(folder / 'policy.py'))
    if (contract.get('format') != 'octatrace-credential-layout' or contract.get('version') != 1 or
            contract.get('profile') != PROFILE or contract.get('application_start') != 0x26000 or
            contract.get('application_end_exclusive') != 0xdf000 or contract.get('credential_start') != 0xdf000 or
            contract.get('credential_end_exclusive') != 0xe1000 or contract.get('page_bytes') != 4096 or
            contract.get('pages') != 2 or contract.get('scope') != 'reservation_only' or
            contract.get('runtime_credential') is not False or contract.get('maintenance_version') != 0 or
            contract.get('linker_guard_sha256') != GUARD_SHA256 or
            contract.get('symbols') != policy['SYMBOLS'] or policy['START'] != 0xdf000 or policy['END'] != 0xe1000 or
            policy['PAGE'] != 4096 or policy['PROFILE'] != PROFILE):
        raise ValueError('Credential layout contract mismatch')
    cap = policy['capability']('a' * 64, GUARD_SHA256)
    manifest = {'credential_storage_reservation': cap, 'credential_storage_symbols': dict(policy['SYMBOLS']),
                'phone_storage_reservation': {'__octatrace_image_end': policy['START']}}
    if not policy['compatible'](manifest, cap):
        raise ValueError('Credential layout positive manifest rejected')
    manifest['phone_storage_reservation']['__octatrace_image_end'] += 1
    if policy['compatible'](manifest, cap):
        raise ValueError('Credential layout overlap accepted')
    return {'profile': PROFILE, 'start': hex(policy['START']), 'end_exclusive': hex(policy['END']),
            'bytes': policy['END'] - policy['START'], 'runtime_credential': False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
