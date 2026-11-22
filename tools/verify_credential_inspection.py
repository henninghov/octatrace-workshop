#!/usr/bin/env python3
"""Verify the pinned read-only credential-inspection contract and dependencies."""
import hashlib
import json
from pathlib import Path
import runpy

import verify_credential_layout

FILES = {
    'contract.json': '0d05102bf687a659eb65b4cfdb9a364678603fc7eb6921583af06b7710ffe3bf',
    'response.schema.json': '4944740227662b1e86a2d0b0ce2788ecdfefb8c9dcb24ec484a619509a5c7cf3',
    'policy.py': '8ca1f3ca603d418263aa548207ca152d65860a39b2d4f6373c81b835d0860950',
    'vectors.json': '40a3a1f14351c7e86fa1aff62e4480b49b15aa4ed4b4f3e7a034cba8e7078c90',
}


def verify(root):
    root = Path(root).resolve()
    lock = root / 'credential-inspection.lock.json'
    if lock.is_symlink():
        raise ValueError('Invalid inspection pin')
    pin = json.loads(lock.read_text())
    if (set(pin) != {'profile', 'version', 'source_repository', 'path',
                     'requires_credential_layout_files_sha256', 'requires_usb_provisioning_files_sha256', 'files'} or
            pin['profile'] != 'octatrace-credential-inspection' or type(pin['version']) is not int or pin['version'] != 1 or
            pin['source_repository'] != 'octatrace-firmware' or
            pin['path'] not in ('contracts/credential-inspection', 'vendor/credential-inspection') or pin['files'] != FILES):
        raise ValueError('Unsupported inspection pin')
    verify_credential_layout.verify(root)
    layout = json.loads((root / 'credential-layout.lock.json').read_text())
    usb_lock = root / 'usb-provisioning.lock.json'
    if not usb_lock.exists():
        usb_lock = root / 'vendor/usb-provisioning.lock.json'
    if usb_lock.is_symlink():
        raise ValueError('Invalid USB provisioning dependency')
    usb = json.loads(usb_lock.read_text())
    usb_files = {Path(name).name: digest for name, digest in usb['files'].items()}
    if (pin['requires_credential_layout_files_sha256'] != layout['files'] or
            type(usb.get('version')) is not int or usb['version'] != 1 or
            usb.get('format') != 'octatrace-usb-provisioning' or
            len(usb_files) != len(usb['files']) or pin['requires_usb_provisioning_files_sha256'] != usb_files):
        raise ValueError('Inspection dependency mismatch')
    usb_root = usb_lock.parent
    for name, digest in usb['files'].items():
        path = usb_root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('USB provisioning dependency checksum mismatch')
    folder = root / pin['path']
    if (folder.is_symlink() or not folder.resolve().is_relative_to(root) or
            {p.name for p in folder.iterdir() if p.is_file()} != set(FILES)):
        raise ValueError('Invalid inspection contract inventory')
    for name, digest in FILES.items():
        path = folder / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Inspection contract checksum mismatch')
    contract = json.loads((folder / 'contract.json').read_text())
    if (contract['profile'] != pin['profile'] or type(contract['version']) is not int or contract['version'] != 1 or
            contract['roles'] != ['Link', 'Core'] or contract['start'] != '0xdf000' or
            contract['end_exclusive'] != '0xe1000' or contract['bytes'] != 8192 or
            contract['states'] != ['unavailable', 'blank', 'unknown', 'recognizable', 'interrupted'] or
            contract['hash'] != 'SHA-256 over all 8192 bytes in address order'):
        raise ValueError('Inspection contract mismatch')
    policy = runpy.run_path(str(folder / 'policy.py'))
    vectors = json.loads((folder / 'vectors.json').read_text())
    for item in vectors['valid']:
        policy['validate'](item, vectors['request_id'])
    for item in vectors['invalid']:
        try:
            policy['validate'](item, vectors['request_id'])
        except ValueError:
            continue
        raise ValueError('Invalid inspection vector accepted')
    return {'profile': pin['profile'], 'version': 1, 'roles': contract['roles'], 'bytes': contract['bytes'],
            'hash': 'SHA-256', 'scope': 'read-only'}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
