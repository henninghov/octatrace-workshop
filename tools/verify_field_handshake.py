#!/usr/bin/env python3
"""Pinned field-profile metadata checks only; never authenticated peer readiness."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import verify_proof_context as dependency

INVENTORY={'profile.json','profile.schema.json','codec.py','reference.mjs','vectors.json'}
PROFILE_SHA256='d5a62808978fbb88a475d4cc71b257a1170e396632aabd16fe47ee180e270481'


def fail(reason):
    raise ValueError('Invalid field handshake '+reason)


def verify(root):
    root=root.resolve();p=root/'field-handshake.lock.json'
    if p.is_symlink():
        fail('pin')
    lock=json.loads(p.read_text())
    if (type(lock) is not dict or set(lock)!={'profile','version','source_repository','path','files','requires_proof_context_files_sha256'} or
            lock.get('profile')!='octatrace-field-handshake' or type(lock.get('version')) is not int or lock['version']!=2 or
            lock.get('source_repository')!='octatrace-firmware' or lock.get('path') not in ('contracts/field-handshake','vendor/field-handshake') or
            type(lock.get('files')) is not dict or set(lock['files'])!=INVENTORY):
        fail('pin')
    dependency.verify(root)
    dep=json.loads((root/'proof-context.lock.json').read_text())
    if lock['requires_proof_context_files_sha256']!=dep['files']:
        fail('dependency')
    folder=root/lock['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir()}!=INVENTORY:
        fail('inventory')
    for name,expected in lock['files'].items():
        p=folder/name
        if p.is_symlink() or type(expected) is not str or not re.fullmatch('[0-9a-f]{64}',expected) or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
            fail('checksum')
    if hashlib.sha256((folder/'profile.json').read_bytes()).hexdigest()!=PROFILE_SHA256:
        fail('profile')
    profile=json.loads((folder/'profile.json').read_text())
    schema={'$schema':'https://json-schema.org/draft/2020-12/schema','title':'Octatrace bounded field handshake profile v2','const':profile}
    if json.loads((folder/'profile.schema.json').read_text())!=schema:
        fail('schema')
    c=runpy.run_path(str(folder/'codec.py'));v=json.loads((folder/'vectors.json').read_text())
    if v.get('synthetic') is not True or [len(v.get(k,[])) for k in ('credentials','preludes','fields','invalid_public_keys','receiver_selectors')]!=[4,2,4,5,4]:
        fail('vectors')
    class PublicFixture:
        def valid_public_key(self,_):return True
    for row in v['credentials']:
        r=c['credential'](bytes.fromhex(row['public_key']),PublicFixture())
        if {n:getattr(r,n).hex() for n in ('ccs','kid','key_sha256','id_cred')}!=row['expected'] or len(r.ccs)!=81:
            fail('credential vector')
    for row in v['preludes']:
        data=bytes.fromhex(row['hex'])
        if c['encode_prelude'](row['fields'])!=data or c['decode_prelude'](data,row['fields']['attempt_uuid']).to_fields()!=row['fields']:
            fail('prelude vector')
    for row in v['fields']:
        r=c['export_request']('initiator_confirmation',bytes.fromhex(row['hex']),row['fields'])
        if r.context.hex()!=row['context'] or r.field_sha256.hex()!=row['field_sha256']:
            fail('export vector')
    for row in v['receiver_selectors']:
        if c['receiver_selector'](**row['fields']).hex()!=row['hex']:
            fail('receiver vector')
    result=subprocess.run(['node',str(folder/'reference.mjs'),str(folder/'vectors.json')],capture_output=True,text=True)
    if result.returncode or json.loads(result.stdout).get('result')!='pass':
        fail('independent reference')
    return {'profile_sha256':PROFILE_SHA256,'result':'pass','credentials':4,'preludes':2,'field_contexts':4,'authenticated_readiness':False}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
