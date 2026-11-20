#!/usr/bin/env python3
"""Verify the local signed bootstrap profile before running its public byte fixtures."""
import json
from pathlib import Path
import runpy

import verify_setup_bluetooth as bluetooth

MANIFEST_SHA256 = '68b305d5c96cf26523905d5ed20af8085990160c7f57f4dba82fa3c4d8b8debf'


def verify(root):
    root = root.resolve()
    # This also checks the actual framing, storage and factory-credential snapshots.
    bluetooth.verify(root)
    prefix = 'contracts' if (root / 'firmware/octatrace').is_dir() else 'vendor'
    pin = json.loads((root / 'setup-bootstrap.lock.json').read_text())
    expected = {'profile':'octatrace-setup-bootstrap', 'version':1, 'source_repository':'octatrace-firmware',
                'path':prefix + '/setup-bootstrap'}
    bluetooth.check(all(pin[k] == v and type(pin[k]) is type(v) for k, v in expected.items()), 'bootstrap pin')
    manifest = {k:pin[k] for k in ('files', 'dependencies')}
    bluetooth.check(bluetooth.sha(json.dumps(manifest, sort_keys=True).encode()) == MANIFEST_SHA256, 'bootstrap manifest')
    folder = root / pin['path']
    bluetooth.check({p.name for p in folder.iterdir() if p.name != '__pycache__'} == set(pin['files']), 'bootstrap inventory')
    for family, files in [('setup-bootstrap', pin['files']), *pin['dependencies'].items()]:
        path = root / prefix / family
        bluetooth.check(path.resolve() == path, family)
        if family != 'setup-bootstrap':
            dep = json.loads((root / (family + '.lock.json')).read_text())
            bluetooth.check(dep['files'] == files and dep['path'] == prefix + '/' + family, family)
        for name, digest in files.items():
            item = path / name
            bluetooth.check(not item.is_symlink() and bluetooth.sha(item.read_bytes()) == digest, name)
    ref = runpy.run_path(str(folder/'reference.py'))
    vectors = json.loads((folder/'vectors.json').read_text())
    for name, code, kind, hex_bytes in vectors['control']:
        fields = (code, kind, vectors['transfer'], vectors['delivery'])
        bluetooth.check(ref['control'](*fields).hex() == hex_bytes and ref['parse'](bytes.fromhex(hex_bytes)) == fields, name)
    for invalid in vectors['invalid']:
        malformed = bytes.fromhex(invalid)
        try:
            parsed = ref['parse'](malformed)
        except ValueError:
            parsed = None
        bluetooth.check(parsed is None, 'invalid OPEN accepted')
    body = bytes.fromhex(vectors['custody_body_hex'])
    wire = ref['WIRE']
    record = wire['encode']('phone_custody', vectors['target'], vectors['delivery'], body)
    bluetooth.check(record[36:68].hex() == vectors['custody_sha256_of_body'] and record[68:] == body
                    and len(wire['frames'](record, vectors['transfer'])) == 9, 'typed phone custody')
    signed = json.loads((folder/'signed-report.json').read_text())
    fields = signed['fields']
    receipt = wire['encode']('phone_custody', fields['target_uuid'], fields['delivery_uuid'],
                             bytes.fromhex(signed['signed_content_sha256']))
    bluetooth.check(signed['synthetic'] is True and receipt.hex() == signed['custody_record_hex'], 'C6 custody fixture')
    return {'profile':pin['profile'], 'version':1, 'manifest_sha256':MANIFEST_SHA256, 'control':len(vectors['control']),
            'invalid':len(vectors['invalid']), 'custody_frames':9, 'result':'pass', 'level':'host contract'}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
