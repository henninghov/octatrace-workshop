#!/usr/bin/env python3
"""Validate pinned startup readiness contract and its inspection dependency."""
import hashlib
import json
from pathlib import Path
import runpy
import verify_credential_inspection

FILES = {
    'policy.py': '0f0f5abc1d08a27c2a7a98150ccaeae11160dcdfd4b01629883c66b83b9dd01a',
    'vectors.json': 'a4e342c15c1052015615f7006b931d873f3bf98bd212a3006403bf9101c45d29',
    'response.schema.json': '696a265bd28508c661922808c703fcd653a9944164ec210d7c42ab33af214756',
    'contract.json': '861fa572377335e9eba102656493e0c333ead748589f9bc794cc46f4734f5398',
}

def verify(root):
    root=Path(root).resolve(); lock=root/'credential-readiness.lock.json'
    if lock.is_symlink(): raise ValueError('Invalid readiness pin')
    pin=json.loads(lock.read_text())
    if (set(pin) != {'profile','version','source_repository','path','requires_credential_inspection_files_sha256','files'} or
        pin['profile'] != 'octatrace-credential-readiness' or type(pin['version']) is not int or pin['version'] != 1 or
        pin['source_repository'] != 'octatrace-firmware' or pin['path'] not in ('contracts/credential-readiness','vendor/credential-readiness') or pin['files'] != FILES):
        raise ValueError('Unsupported readiness pin')
    verify_credential_inspection.verify(root)
    if pin['requires_credential_inspection_files_sha256'] != json.loads((root/'credential-inspection.lock.json').read_text())['files']:
        raise ValueError('Readiness inspection dependency mismatch')
    folder=root/pin['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()} != set(FILES):
        raise ValueError('Invalid readiness contract inventory')
    for name,digest in FILES.items():
        path=folder/name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest: raise ValueError('Readiness checksum mismatch')
    contract=json.loads((folder/'contract.json').read_text())
    if (contract['profile'] != pin['profile'] or contract['version'] != 1 or contract['roles'] != ['Link','Core'] or
        contract['states'] != ['unavailable','empty','ready','pending'] or contract['command'] != 'P1 <id> credential-readiness'):
        raise ValueError('Readiness contract mismatch')
    policy=runpy.run_path(str(folder/'policy.py')); vectors=json.loads((folder/'vectors.json').read_text())
    for row in vectors['valid']: policy['validate'](row,vectors['request_id'])
    for row in vectors['invalid']:
        try: policy['validate'](row,vectors['request_id'])
        except ValueError: continue
        raise ValueError('Invalid readiness vector accepted')
    return {'profile':pin['profile'],'version':1,'scope':'read-only'}

if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
