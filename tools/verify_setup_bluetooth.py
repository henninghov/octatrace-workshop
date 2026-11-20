#!/usr/bin/env python3
"""Check the firmware-owned BLE setup interface and exact local contract bytes."""
import hashlib
import json
from pathlib import Path
import runpy

PROFILE = 'octatrace-setup-bluetooth'
MANIFEST_SHA256 = 'fdb09f53317449950b36ea0dfe4aace20856332a9a1790d647aad783f6641677'


def check(ok, detail):
    if not ok:
        raise ValueError('Setup Bluetooth contract mismatch: ' + detail)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(root):
    root = root.resolve()
    pin = json.loads((root / 'setup-bluetooth.lock.json').read_text())
    prefix = 'contracts' if (root / 'firmware/octatrace').is_dir() else 'vendor'
    check(type(pin['version']) is int and (pin['profile'], pin['version'], pin['source_repository'], pin['path']) ==
          (PROFILE, 1, 'octatrace-firmware', prefix + '/setup-bluetooth'), 'profile')
    manifest = {key: pin[key] for key in ('files', 'dependencies')}
    check(sha(json.dumps(manifest, sort_keys=True).encode()) == MANIFEST_SHA256, 'manifest')
    folder = root / pin['path']
    check({p.name for p in folder.iterdir() if p.name != '__pycache__'} == set(pin['files']), 'inventory')
    for family, files in [('setup-bluetooth', pin['files']), *pin['dependencies'].items()]:
        location = root / prefix / family
        check(location.resolve() == location, family)
        if family != 'setup-bluetooth':
            dependency = json.loads((root / (family + '.lock.json')).read_text())
            check(dependency['files'] == files and dependency['path'] == prefix + '/' + family, family)
        for name, digest in files.items():
            path = location / name
            check(not path.is_symlink() and sha(path.read_bytes()) == digest, family + '/' + name)

    profile = json.loads((folder / 'profile.json').read_text())
    vectors = json.loads((folder / 'vectors.json').read_text())
    ref = runpy.run_path(str(folder / 'reference.py'))
    operations = {int(code): (spec['route'], spec['required']) for code, spec in profile['operations'].items()}
    check(operations == ref['OPERATIONS'], 'operation capabilities')
    for case in vectors['exchanges']:
        offer = bytes.fromhex(case['hello'])
        try:
            reply = ref['respond'](offer, case['route'], case['local'], supports_v1=case['v1'])
        except ValueError:
            reply = None
        check((reply.hex() if reply else None) == case['reply'], case['case'])
        check(bool(reply and reply[1] == ref['SELECT']) == case['compatible'], case['case'])
    target = vectors['find']
    ticket = ref['Selection'](1, ref['PHONE_LINK'], 2, 2)
    for name, kind in [('request', ref['FIND']), ('matched', ref['CANDIDATE_MATCHES']), ('ended', ref['SEARCH_ENDED'])]:
        check(ref['target_message'](ticket, kind, target['target']).hex() == target[name], name)
    return {'profile': PROFILE, 'version': 1, 'manifest_sha256': MANIFEST_SHA256,
            'exchanges': len(vectors['exchanges']), 'target_messages': 3, 'level': 'host contract', 'result': 'pass'}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
