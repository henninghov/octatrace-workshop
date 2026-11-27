#!/usr/bin/env python3
"""Verify the pinned crypto reentry contract, USB dependency and fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy

FILES = {
    'contract.json': '655a7cfa7b59dbb2c1ffcb5cda40855bb1095e781532afa105fc1235c6e4439f',
    'policy.py': '4174b57f6a5b3c19a709475974b78dc41f9f9c0a13a086d9bd0263fd6401d146',
    'response.schema.json': 'de2618205eca3007a1810e8fcceb6d41e394648067aa302aa52b2df0666f9b7a',
    'vectors.json': '234fecbbae2fb2a85a8be679317210481c29ae34ae3c34468c524d6868801110',
}


def verify(root):
    root = Path(root).resolve()
    lock = root / 'crypto-reentry.lock.json'
    if lock.is_symlink():
        raise ValueError('Invalid crypto reentry pin')
    pin = json.loads(lock.read_text())
    if (set(pin) != {'profile', 'version', 'source_repository', 'path',
                     'requires_usb_provisioning_files_sha256', 'files'} or
            pin['profile'] != 'octatrace-crypto-reentry' or type(pin['version']) is not int or
            pin['version'] != 1 or pin['source_repository'] != 'octatrace-firmware' or
            pin['path'] not in ('contracts/crypto-reentry', 'vendor/crypto-reentry') or pin['files'] != FILES):
        raise ValueError('Unsupported crypto reentry pin')
    usb_lock = root / 'usb-provisioning.lock.json'
    if not usb_lock.exists():
        usb_lock = root / 'vendor/usb-provisioning.lock.json'
    if usb_lock.is_symlink():
        raise ValueError('Invalid USB provisioning dependency')
    usb = json.loads(usb_lock.read_text())
    usb_files = {Path(name).name: digest for name, digest in usb['files'].items()}
    if (usb.get('format') != 'octatrace-usb-provisioning' or type(usb.get('version')) is not int or
            usb['version'] != 1 or len(usb_files) != len(usb['files']) or
            pin['requires_usb_provisioning_files_sha256'] != usb_files):
        raise ValueError('Crypto probe USB dependency mismatch')
    for name, digest in usb['files'].items():
        path = usb_lock.parent / name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('USB provisioning dependency checksum mismatch')
    folder = root / pin['path']
    if (folder.is_symlink() or not folder.resolve().is_relative_to(root) or
            {p.name for p in folder.iterdir() if p.is_file()} != set(FILES)):
        raise ValueError('Invalid crypto reentry contract inventory')
    for name, digest in FILES.items():
        path = folder / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Crypto probe contract checksum mismatch')
    contract = json.loads((folder / 'contract.json').read_text())
    if (contract['profile'] != pin['profile'] or contract['version'] != 1 or
            contract['roles'] != ['Link', 'Core'] or
            contract['states'] != ['idle', 'queued', 'running', 'passed', 'failed', 'interrupted'] or
            contract['checks'] != ['nested_refused', 'outer_failed', 'output_cleared', 'input_intact', 'later_hash']):
        raise ValueError('Crypto probe contract mismatch')
    policy = runpy.run_path(str(folder / 'policy.py'))['validate']
    vectors = json.loads((folder / 'vectors.json').read_text())
    for item in vectors['valid']:
        policy(item, vectors['request_id'], vectors['selection'])
    for item in vectors['invalid']:
        try:
            policy(item, vectors['request_id'], vectors['selection'])
        except ValueError:
            continue
        raise ValueError('Invalid crypto reentry vector accepted')
    return {'profile': pin['profile'], 'version': 1, 'roles': contract['roles'],
            'valid': len(vectors['valid']), 'invalid': len(vectors['invalid'])}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    print(json.dumps(verify(parser.parse_args().root), sort_keys=True))
