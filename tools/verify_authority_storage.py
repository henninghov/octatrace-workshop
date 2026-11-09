#!/usr/bin/env python3
"""Check the firmware-owned authority-storage snapshot. Public fixtures only."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import verify_device_authority as dependency

INVENTORY={'profile.json','snapshot.schema.json','vectors.json','codec.py','file_flash.py','reference.mjs'}
COUNTS=('snapshots','transitions','merges','images','eligible','invalid_snapshots')
PROFILE={'format':'octatrace-authority-storage','version':1,'owner':'octatrace-firmware',
 'geometry':{'address':None,'page_bytes':4096,'bank_bytes':8192,'banks':3,'total_bytes':24576,'header_bytes':64,'payload_capacity':8128,'max_signed_records':24,'word_bytes':4,'program_chunk_max':128},
 'header':{'magic_ascii':'OCTAAS01','byte_order':'little','version_offset':8,'generation_offset':12,'length_offset':16,'payload_sha256_offset':20,'header_crc32_offset':52,'commit_offset':56,'reserved_ff_offset':60,'payload_offset':64,'commit_value':0,'erased_byte':255,'crc_scope':'bytes0..51; CRC32/ISO-HDLC','digest_scope':'exact canonical snapshot payload'},
 'snapshot':'canonical CBOR [1,environment_enum,local_uuid_bstr16,role_enum,key_sha256_bstr32,key_revision_uint32,sorted_signed_record_bstrs]; sort by purpose enum then UUID; no pruning',
 'commit':'Two identical complete committed copies of highest generation required for Ready/Installed; single newer candidate is Pending, completed under a fresh trusted guard; lower generation never silently selected after quorum loss',
 'fault_model':'Serialized writer, completed erase/program operations, interruption at boundaries and word-prefix torn operations; detected corruption fails closed. Not arbitrary hardware corruption, full-flash rollback, secure boot, physical key protection or endurance qualification.',
 'preparation':'All-FF is Unprepared, not first-installed. Explicit trusted preparation writes empty bound generation1 in two copies; no automatic erase of preexisting or corrupt state.',
 'authority':'Verify every signed record with configured factory audience and ownership-control issuer; retain per-resource revision/owner epoch/removal; policy installation requires current owner evidence; changing owner leaves stale child policy ineligible',
 'offline':'No network or clock renewal; no traffic key/readiness/Start restoration',
 'limits':'24 signed records is a storage-format bound, not supported CORE count. Relative banks reserve no target address. Live SDK worker/command admission C8; compatibility/resource closure C4.3.3; physical C9.',
 'references':['https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/nvmc.html']}


def schema():
    uuid={'type':'string','pattern':'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$','minLength':36,'maxLength':36}
    local={'type':'object','additionalProperties':False,'required':['environment','resource_uuid','resource_role','resource_key_sha256','resource_key_revision'],'properties':{'environment':{'enum':['development','production']},'resource_uuid':uuid,'resource_role':{'enum':['Link','Core']},'resource_key_sha256':{'type':'string','pattern':'^[0-9a-f]{64}$','not':{'const':'0'*64}},'resource_key_revision':{'type':'integer','minimum':1,'maximum':4294967295}}}
    return {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:octatrace:authority-storage:1','title':'Readable authority snapshot fields, never authority by themselves','type':'object','additionalProperties':False,'required':['v','local','records_hex'],'properties':{'v':{'type':'integer','const':1},'local':local,'records_hex':{'type':'array','maxItems':24,'uniqueItems':True,'items':{'type':'string','minLength':2,'maxLength':540,'pattern':'^([0-9a-f]{2}){1,270}$'}}}}


def verify(root):
    root=Path(root).resolve()
    lock=json.loads((root/'authority-storage.lock.json').read_text())
    if (lock.get('profile')!='octatrace-authority-storage' or lock.get('version')!=1 or lock.get('source_repository')!='octatrace-firmware' or
            lock.get('path') not in ('contracts/authority-storage','vendor/authority-storage') or set(lock.get('files',{}))!=INVENTORY):
        raise ValueError('Unsupported authority storage pin')
    dependency.verify(root)
    for family in ['device-authority','device-credential']:
        pin=json.loads((root/(family+'.lock.json')).read_text())
        if lock.get('requires_'+family.replace('-','_')+'_files_sha256')!=pin['files']:
            raise ValueError('Authority storage dependency mismatch')
    folder=root/lock['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()}!=INVENTORY:
        raise ValueError('Invalid authority storage inventory')
    for name,digest in lock['files'].items():
        p=folder/name
        if p.is_symlink() or not re.fullmatch('[0-9a-f]{64}',digest) or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
            raise ValueError('Authority storage checksum mismatch')
    if json.loads((folder/'profile.json').read_text())!=PROFILE:
        raise ValueError('Unsupported authority storage profile')
    if json.loads((folder/'snapshot.schema.json').read_text())!=schema():
        raise ValueError('Unsupported authority storage schema')
    c=runpy.run_path(str(folder/'codec.py'));v=json.loads((folder/'vectors.json').read_text())
    if v.get('synthetic') is not True or any(len(v[k])<n for k,n in zip(COUNTS,[25,21,18,16,8,11])):
        raise ValueError('Incomplete authority storage vectors')
    authorities={r['name']:r for r in v['authorities']}
    for s in v['snapshots']:
        records=sorted((authorities[n] for n in s['records']),key=lambda r:(c['PURPOSES'][r['fields']['purpose']],r['fields']['resource_uuid']))
        expected=c['BASE']['cbor'](c['prefix'](s['local'])+[[bytes.fromhex(r['hex']) for r in records]])
        raw=bytes.fromhex(s['hex']);bank=c['bank_bytes'](s['generation'],raw)
        if raw!=expected or c['uncbor'](raw)!=c['uncbor'](expected) or bank[:64].hex()!=s['header_hex'] or hashlib.sha256(bank).hexdigest()!=s['bank_sha256']:
            raise ValueError('Authority storage positive vector mismatch')
    try:
        c['bank_bytes'](0,b'private')
    except ValueError as error:
        if str(error)!='Authority storage operation denied':
            raise ValueError('Authority storage error may disclose input') from None
    else:
        raise ValueError('Authority storage invalid generation accepted')
    result=subprocess.run(['node',str(folder/'reference.mjs'),str(folder/'vectors.json')],capture_output=True,text=True)
    expected={k:len(v[k]) for k in COUNTS}
    if result.returncode or json.loads(result.stdout)!=expected:
        raise ValueError('Independent authority storage reference failed')
    return expected


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
