#!/usr/bin/env python3
"""Verify the pinned installation contract and its frozen dependencies."""
import hashlib
import json
from pathlib import Path
import runpy
import verify_credential_delivery
import verify_credential_layout

FILES={'contract.json': '3dd34a2334b0df7ee905c69b03803b41654473533ffd7b1d6a4419ea601de772', 'policy.py': 'fe36ea2e3893376383bb4e153ef8da01a080dc412be2c9c85d4f853a4e3f3253', 'proof.mjs': 'ad2c7c5a97b4ec46267e1148a2910fd7ac0095a25989568d663dd749a11f6041', 'response.schema.json': 'eda8789a86159ca5c809c7abc02c4de8b09d2f32f1565492c051c0764e465abf', 'status.schema.json': '84f5446af557abe410481aa15e70ce4f2b8e920095705eac0d6b12d12a8ae561', 'vectors.json': '6da52b7b25ceabb7fe79a6de7d7625f3eefbb9b2a8ed35b6c76ff0fa902340b3'}
def verify(root):
    root=Path(root).resolve();path=root/'credential-installation.lock.json'
    if path.is_symlink():raise ValueError('Invalid installation pin')
    pin=json.loads(path.read_text())
    if (set(pin)!={'profile','version','source_repository','path','requires_delivery_files_sha256','requires_layout_files_sha256','files'} or
        pin['profile']!='octatrace-credential-installation' or type(pin['version']) is not int or pin['version']!=1 or
        pin['source_repository']!='octatrace-firmware' or pin['path'] not in ('contracts/credential-installation','vendor/credential-installation') or pin['files']!=FILES):raise ValueError('Unsupported installation pin')
    verify_credential_delivery.verify(root);verify_credential_layout.verify(root)
    if (pin['requires_delivery_files_sha256']!=json.loads((root/'credential-delivery.lock.json').read_text())['files'] or
        pin['requires_layout_files_sha256']!=json.loads((root/'credential-layout.lock.json').read_text())['files']):raise ValueError('Installation dependency mismatch')
    folder=root/pin['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()}!=set(FILES):raise ValueError('Installation inventory mismatch')
    for name,digest in FILES.items():
        file=folder/name
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest()!=digest:raise ValueError('Installation snapshot mismatch')
    contract=json.loads((folder/'contract.json').read_text());vector=json.loads((folder/'vectors.json').read_text())
    if (contract['format']!=pin['profile'] or contract['version']!=1 or contract['max_credential_bytes']!=271 or
        contract['deadline_ms']!=30000 or contract['reply_max_bytes']!=1280 or contract['proof_max_bytes']!=768 or
        contract['proof_domain']!='OCTATRACE-CREDENTIAL-INSTALLATION-1' or vector['synthetic_only'] is not True):raise ValueError('Installation contract mismatch')
    policy=runpy.run_path(str(folder/'policy.py'))
    if policy['message'](vector['frame']).decode('ascii')!=vector['message_ascii']:raise ValueError('Installation proof encoding mismatch')
    policy['verify'](vector['frame'],vector['frame']['id'],vector['expected'])
    return {'profile':pin['profile'],'version':1,'scope':'confirmed append-only installation'}

if __name__=='__main__':print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
