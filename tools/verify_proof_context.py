#!/usr/bin/env python3
"""Pinned claim/proof/field-context contract checks; public synthetic fixtures only."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import verify_device_authority as authority_dependency

INVENTORY = {'profile.json','fields.schema.json','vectors.json','codec.py','reference.mjs'}
COUNTS = ('challenges','proofs','fields','invalid_objects','invalid_fields','invalid_relations','completions','local_windows','bindings')
MINIMUM = (7,12,4,112,195,9,13,8,7)
CHALLENGE = [('v','version'),('purpose','purpose'),('environment','environment'),('challenge_uuid','uuid'),('operation_uuid','uuid'),('owner_ref','uuid'),('link_uuid','uuid'),('link_role','link_role'),('link_key_sha256','hash'),('link_key_revision','revision'),('link_boot','boot'),('link_nonce','hash'),('phone_installation_uuid','uuid'),('phone_key_sha256','hash'),('phone_boot','boot'),('server_nonce','hash'),('issued_at','revision'),('expires_at','revision'),('owner_receipt_sha256','optional_hash'),('ownership_epoch','counter'),('controller_revision','counter')]
PROOF = [('v','version'),('signer','signer'),('challenge_content_sha256','hash'),('challenge_uuid','uuid'),('signer_boot','boot')]
FIELD = [('v','version'),('kind','kind'),('environment','environment'),('handshake_profile_sha256','hash'),('attempt_uuid','uuid'),('authority_context_sha256','hash'),('initiator_uuid','uuid'),('initiator_key_sha256','hash'),('initiator_boot','boot'),('responder_uuid','uuid'),('responder_key_sha256','hash'),('responder_boot','boot'),('initiator_nonce','hash'),('responder_nonce','hash'),('transcript_sha256','hash')]
PROFILE = {'format':'octatrace-proof-context','version':1,
 'setup_window_seconds':300,'setup_ux':'Hidden automatic challenge after LINK connection readiness; expiry renews same authorised operation without QR rescan or precommit code consumption; committed ownership recovery is separate',
 'challenge':{'aad':'OCTATRACE-SETUP-CHALLENGE-1','protected_labels':[1,4],'issuer':'ownership_control','labels':{n:i+1 for i,(n,_) in enumerate(CHALLENGE)},'purpose':{'first_claim':1,'phone_replace':2}},
 'proof':{'aad':'OCTATRACE-SETUP-PROOF-1','protected_labels':[1],'signer':{'Link':1,'Phone':2},'labels':{n:i+1 for i,(n,_) in enumerate(PROOF)},'challenge_content_id':'SHA256 of challenge COSE Sig_structure, excludes signature bytes'},
 'field':{'prefix':'OCTATRACE-FIELD-CONTEXT-1:','kind':{'phone_link':1,'link_core':2},'labels':{n:i+1 for i,(n,_) in enumerate(FIELD)},'trust':'Untrusted application binding only; no authenticated handshake/readiness'},
 'cose':{'tag':18,'algorithm':-7,'signature_bytes':64,'hash':'SHA-256 exactly once','unprotected':{}},
 'limits':{'challenge_bytes':426,'challenge_signing_bytes':398,'proof_bytes':151,'proof_signing_bytes':118,'field_bytes':368,'adapter_maximum':512,'uint32_max':4294967295},
 'freshness':'Server verifies current known unused challenge and issued_at <= now < expires_at; device verifies current pending boot/nonce and elapsed < 300000ms; atomic consumption is later backend/storage work',
 'field_policy':'No expiry or online renewal; current policy/owners, endpoints, boots, nonces, approved handshake-profile and authenticated-transcript hashes must bind in later C4.4',
 'claim_route':'LINK first claim / phone replacement only; CORE QR-only ownership claim needs no powered device proof',
 'references':['https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2','https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1','https://www.rfc-editor.org/rfc/rfc9528.html#section-3.9']}


def schema():
    uid={'type':'string','minLength':36,'maxLength':36,'pattern':'^'+authority_dependency.dependency.UUID+'$'}
    def hex_rule(size):
        return {'type':'string','minLength':size*2,'maxLength':size*2,'pattern':'^[0-9a-f]{'+str(size*2)+'}$','not':{'const':'0'*(size*2)}}
    rules={'version':{'type':'integer','const':1},'revision':{'type':'integer','minimum':1,'maximum':4294967295},
      'counter':{'type':'integer','minimum':0,'maximum':4294967295},'uuid':uid,'hash':hex_rule(32),'boot':hex_rule(16),
      'environment':{'type':'string','enum':['development','production']},'purpose':{'type':'string','enum':['first_claim','phone_replace']},
      'link_role':{'type':'string','const':'Link'},'signer':{'type':'string','enum':['Link','Phone']},'kind':{'type':'string','enum':['phone_link','link_core']}}
    variants=[]
    for kind,rows,purpose in [('challenge',CHALLENGE,'first_claim'),('challenge',CHALLENGE,'phone_replace'),('proof',PROOF,None),('field',FIELD,None)]:
        props={n:rules[t] for n,t in rows if t!='optional_hash'}
        if kind=='challenge':
            props['purpose']={'type':'string','const':purpose};props['issuer_kid']=hex_rule(8)
            props['owner_receipt_sha256']={'type':'string','const':''} if purpose=='first_claim' else hex_rule(32)
            if purpose=='first_claim':
                props['ownership_epoch']={'type':'integer','const':0};props['controller_revision']={'type':'integer','const':0}
            else:
                props['ownership_epoch']=rules['revision']
        variants.append({'type':'object','additionalProperties':False,'required':['kind','fields'],
          'properties':{'kind':{'type':'string','const':kind},'fields':{'type':'object','additionalProperties':False,'required':list(props),'properties':props}}})
    return {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:octatrace:proof-context:1',
            'title':'Proof-context v1 metadata; relationships/signatures/freshness require codec and trusted state','oneOf':variants}


def verify(root):
    root=Path(root).resolve();lock=json.loads((root/'proof-context.lock.json').read_text())
    if (lock.get('profile')!='octatrace-proof-context' or lock.get('version')!=1 or
            lock.get('source_repository')!='octatrace-firmware' or lock.get('path') not in ('contracts/proof-context','vendor/proof-context') or
            set(lock.get('files',{}))!=INVENTORY):
        raise ValueError('Unsupported proof context pin')
    authority_dependency.verify(root)
    for family in ('device-credential','device-authority'):
        dependency=json.loads((root/(family+'.lock.json')).read_text())
        if lock.get('requires_'+family.replace('-','_')+'_files_sha256')!=dependency['files']:
            raise ValueError('Proof context dependency mismatch')
    folder=root/lock['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()}!=INVENTORY:
        raise ValueError('Invalid proof context inventory')
    for name,digest in lock['files'].items():
        path=folder/name
        if path.is_symlink() or not re.fullmatch('[0-9a-f]{64}',digest) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Proof context checksum mismatch')
    if json.loads((folder/'profile.json').read_text())!=PROFILE:
        raise ValueError('Unsupported proof context profile')
    if json.loads((folder/'fields.schema.json').read_text())!=schema():
        raise ValueError('Unsupported proof context schema')
    codec=runpy.run_path(str(folder/'codec.py'));vectors=json.loads((folder/'vectors.json').read_text())
    if vectors.get('synthetic') is not True or any(len(vectors[k])<n for k,n in zip(COUNTS,MINIMUM)):
        raise ValueError('Incomplete proof context vectors')
    for kind,collection in [('challenge','challenges'),('proof','proofs')]:
        for row in vectors[collection]:
            if (codec['signing_bytes'](kind,row['fields']).hex()!=row['signing_hex'] or
                    codec['assemble'](kind,row['fields'],bytes.fromhex(row['signature_hex'])).hex()!=row['hex']):
                raise ValueError('Proof context positive vector mismatch')
    for row in vectors['fields']:
        if codec['encode_field'](row['fields']).hex()!=row['hex']:
            raise ValueError('Proof context field vector mismatch')
    for row in vectors['invalid_fields']+vectors['invalid_relations']:
        try:
            codec['fields'](row['kind'],row['fields'])
        except ValueError as error:
            if str(error)!='Invalid proof context':
                raise ValueError('Proof context error may disclose input') from None
        else:
            raise ValueError('Proof context invalid fields accepted')
    result=subprocess.run(['node',str(folder/'reference.mjs'),str(folder/'vectors.json')],capture_output=True,text=True)
    expected={k:len(vectors[k]) for k in COUNTS}
    if result.returncode or json.loads(result.stdout)!=expected:
        raise ValueError('Independent proof context reference failed')
    return expected


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]),sort_keys=True))
