#!/usr/bin/env python3
"""Verify exact candidate bytes and independent framing vectors; no crypto claim."""
import hashlib
import json
from pathlib import Path
import runpy

MANIFEST_SHA256 = '103b8599c8f56ae0458af3c3ea195544bf5492730f8d9e2d4a867b955638d72e'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, detail):
    if not ok:
        raise ValueError('First-channel contract mismatch: ' + detail)


def verify(root):
    root = root.resolve()
    owner = (root / 'firmware/octatrace').is_dir()
    prefix = 'contracts' if owner else 'vendor'
    pin = json.loads((root / 'setup-first-channel.lock.json').read_text())
    require(type(pin['version']) is int and (pin['profile'], pin['version'], pin['source_repository'], pin['path']) ==
            ('octatrace-link-core-bluetooth-field', 1, 'octatrace-firmware', prefix + '/setup-first-channel'), 'identity')
    require(digest(json.dumps({key: pin[key] for key in ('files', 'dependencies')}, sort_keys=True).encode()) == MANIFEST_SHA256, 'manifest')
    folder = root / pin['path']
    require({p.name for p in folder.iterdir() if p.name != '__pycache__'} == set(pin['files']), 'inventory')
    for family, files in [('setup-first-channel', pin['files']), *pin['dependencies'].items()]:
        path = root / prefix / family
        require(path.resolve() == path, family)
        if family != 'setup-first-channel':
            other = json.loads((root / (family + '.lock.json')).read_text())
            require(other['path'] == prefix + '/' + family and other['files'] == files, family + ' lock')
        for name, expected in files.items():
            item = path / name
            require(not item.is_symlink() and digest(item.read_bytes()) == expected, family + '/' + name)
    profile = json.loads((folder / 'profile.json').read_text())
    vectors = json.loads((folder / 'vectors.json').read_text())
    ref = runpy.run_path(str(folder / 'reference.py'))
    require(type(profile['version']) is int and profile['format'] == pin['profile'] and profile['version'] == pin['version'], 'profile')
    require(ref['PROFILE_HASH'] == bytes.fromhex(pin['files']['profile.json']), 'profile hash')
    for case in vectors['frames']:
        message = bytes.fromhex(case['message'])
        frame = bytes.fromhex(case['frame'])
        require(ref['frame'](case['flight'], message, case['index']) == frame, 'frame vector')
        require(ref['decode'](frame) == (case['flight'], len(message), case['index'],
                                         message[case['index'] * 12:(case['index'] + 1) * 12]), 'decode vector')
    for case in vectors['invalid_frames']:
        try:
            ref['decode'](bytes.fromhex(case))
        except ValueError:
            continue
        raise ValueError('First-channel invalid vector accepted')
    return {'result': 'pass', 'level': 'host contract only', 'profile': pin['profile'],
            'manifest_sha256': MANIFEST_SHA256, 'frame_vectors': len(vectors['frames']),
            'invalid_vectors': len(vectors['invalid_frames'])}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
