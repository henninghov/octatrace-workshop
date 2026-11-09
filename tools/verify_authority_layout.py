#!/usr/bin/env python3
"""Verify the target reservation contract and frozen journal dependency; no device IO."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import verify_authority_storage as dependency
INVENTORY={'contract.json','manifest.schema.json','policy.py'}
CONTRACT = {'format': 'octatrace-authority-layout', 'version': 1, 'profile': 't114-nrf52840-s140v6-authority-v1', 'application_start': 155648, 'application_end_exclusive': 921600, 'authority_start': 921600, 'authority_end_exclusive': 946176, 'page_bytes': 4096, 'banks': 3, 'bank_bytes': 8192, 'scope': 'reservation_only', 'runtime_authority': False, 'maintenance_version': 0, 'symbols': {'__octatrace_authority_start': 921600, '__octatrace_authority_end': 946176, '__octatrace_control_start': 946176, '__octatrace_control_end': 954368, '__octatrace_client_start': 954368, '__octatrace_client_end': 962560, '__octatrace_bond_start': 962560, '__octatrace_bond_end': 970752, '__octatrace_identity_start': 970752, '__octatrace_identity_end': 978944}, 'linker_script_sha256': '16ae4c316ef0f09fea4ece4029e3699cc1770c1079012b4e94c1f401d38b08a0', 'workspace_budget_bytes': 12288, 'protected_regions_unchanged': {'control': ['0xe7000', '0xe9000'], 'client': ['0xe9000', '0xeb000'], 'bonds': ['0xeb000', '0xed000'], 'identity': ['0xed000', '0xef000']}, 'initialisation': 'No authority writer or erase command in this checkpoint. New region may contain old application bytes; future approved inspection/preparation must preserve recognised authority and fail closed on uncertainty.', 'rollback': 'Ordinary catalogue/image guard only; not secure boot, bootloader enforcement or physical anti-rollback.'}
SCHEMA = {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:octatrace:authority-layout:1', 'title': 'Target reservation metadata, not live authority capability', 'type': 'object', 'additionalProperties': False, 'required': ['version', 'profile', 'start', 'end_exclusive', 'page_bytes', 'pages', 'bank_bytes', 'banks', 'journal_version', 'scope', 'runtime_authority', 'maintenance_version', 'layout_lock_sha256', 'journal_lock_sha256'], 'properties': {'version': {'type': 'integer', 'const': 1}, 'profile': {'const': 't114-nrf52840-s140v6-authority-v1'}, 'start': {'const': '0xe1000'}, 'end_exclusive': {'const': '0xe7000'}, 'page_bytes': {'type': 'integer', 'const': 4096}, 'pages': {'type': 'integer', 'const': 6}, 'bank_bytes': {'type': 'integer', 'const': 8192}, 'banks': {'type': 'integer', 'const': 3}, 'journal_version': {'type': 'integer', 'const': 1}, 'scope': {'const': 'reservation_only'}, 'runtime_authority': {'type': 'boolean', 'const': False}, 'maintenance_version': {'type': 'integer', 'const': 0}, 'layout_lock_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}, 'journal_lock_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}}}


def verify(root):
    root=Path(root).resolve();pin=json.loads((root/'authority-layout.lock.json').read_text())
    if (pin.get('profile')!='octatrace-authority-layout' or pin.get('version')!=1 or pin.get('source_repository')!='octatrace-firmware' or
            pin.get('path') not in ('contracts/authority-layout','vendor/authority-layout') or set(pin.get('files',{}))!=INVENTORY):
        raise ValueError('Unsupported authority layout pin')
    dependency.verify(root)
    journal=json.loads((root/'authority-storage.lock.json').read_text())
    if pin.get('requires_authority_storage_files_sha256')!=journal['files']:
        raise ValueError('Authority layout dependency mismatch')
    folder=root/pin['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()}!=INVENTORY:
        raise ValueError('Invalid authority layout inventory')
    for name,digest in pin['files'].items():
        p=folder/name
        if p.is_symlink() or not re.fullmatch('[0-9a-f]{64}',digest) or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
            raise ValueError('Authority layout checksum mismatch')
    c=json.loads((folder/'contract.json').read_text());schema=json.loads((folder/'manifest.schema.json').read_text())
    if json.dumps(c,sort_keys=True)!=json.dumps(CONTRACT,sort_keys=True):
        raise ValueError('Unsupported authority layout contract')
    if schema!=SCHEMA:
        raise ValueError('Unsupported authority layout schema')
    p=runpy.run_path(str(folder/'policy.py'));geometry=dependency.PROFILE['geometry']
    if (p['START']!=c['authority_start'] or p['END']!=c['authority_end_exclusive'] or p['PAGE']!=c['page_bytes'] or
            p['SYMBOLS']!=c['symbols'] or p['TOTAL']!=geometry['total_bytes'] or c['banks']!=geometry['banks'] or c['bank_bytes']!=geometry['bank_bytes']):
        raise ValueError('Authority layout policy/geometry mismatch')
    cap=p['capability']('a'*64,'b'*64)
    manifest={'authority_storage_reservation':cap,'phone_storage_reservation':dict(p['SYMBOLS'],__octatrace_image_end=p['START'])}
    if not p['compatible'](manifest,cap):
        raise ValueError('Authority layout positive manifest rejected')
    manifest['phone_storage_reservation']['__octatrace_image_end']+=1
    if p['compatible'](manifest,cap):
        raise ValueError('Authority layout overlap accepted')
    return {'profile':c['profile'],'start':hex(p['START']),'end_exclusive':hex(p['END']),'bytes':p['TOTAL'],'runtime_authority':False}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
