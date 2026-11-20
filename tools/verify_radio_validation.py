#!/usr/bin/env python3
"""Verify pinned radio-validation contract and synthetic CCM vectors."""
import hashlib
import json
from pathlib import Path
import subprocess

MANIFEST_SHA256 = '58ea8f6aa9cc13a784942e4214f56b9728566e1ed5bb41b21aca3924814f5aae'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, detail):
    if not ok:
        raise ValueError('Radio validation contract mismatch: ' + detail)


def verify(root):
    root = root.resolve()
    prefix = 'contracts' if (root / 'firmware/octatrace').is_dir() else 'vendor'
    pin = json.loads((root / 'radio-validation.lock.json').read_text())
    require(type(pin['version']) is int and (pin['profile'], pin['version'], pin['source_repository'], pin['path']) ==
            ('octatrace-radio-validation', 1, 'octatrace-firmware', prefix + '/radio-validation'), 'identity')
    manifest = {key: pin[key] for key in ('files', 'dependencies')}
    require(sha(json.dumps(manifest, sort_keys=True).encode()) == MANIFEST_SHA256, 'manifest')
    folder = root / pin['path']
    require({p.name for p in folder.iterdir()} == set(pin['files']), 'inventory')
    for family, files in [('radio-validation', pin['files']), *pin['dependencies'].items()]:
        location = root / prefix / family
        require(location.resolve() == location, family)
        if family != 'radio-validation':
            other = json.loads((root / (family + '.lock.json')).read_text())
            require(other['path'] == prefix + '/' + family and other['files'] == files, family + ' lock')
        for name, digest in files.items():
            path = location / name
            require(not path.is_symlink() and sha(path.read_bytes()) == digest, family + '/' + name)
    profile = json.loads((folder / 'profile.json').read_text())
    require(type(profile['version']) is int and profile['version'] == 1 and profile['format'] == pin['profile'], 'profile')
    output = subprocess.run(['node', str(folder / 'verify.mjs')], cwd=root, text=True, capture_output=True, check=True)
    result = json.loads(output.stdout)
    require(result == {'result': 'pass', 'level': 'synthetic AES-CCM host only', 'vectors': 4}, 'synthetic vectors')
    return {'result': 'pass', 'level': 'host contract only', 'profile': pin['profile'],
            'manifest_sha256': MANIFEST_SHA256, 'synthetic_ccm_vectors': result['vectors']}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
