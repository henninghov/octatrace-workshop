"""Pinned extension of the non-writing delivery codec; no device operations."""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile

DELIVERY=runpy.run_path(str(Path(__file__).resolve().parent.parent/'credential-delivery/policy.py'))
EXTRA=('result','journal_state','slots_used','journal_revision','journal_content_id','fault')
FIELDS=DELIVERY['PROOF_FIELDS']|frozenset(EXTRA)
STATUS_FIELDS=frozenset(('v','id','ok','type','role','build','hardware','boot','state'))
HEX=DELIVERY['valid_hex'];UINT=DELIVERY['number']

def status(frame,request_id):
    DELIVERY['common'](frame,request_id,STATUS_FIELDS,'credential_installation_status')
    if frame['state'] not in ('idle','reviewing','reviewed','writing','complete','failed'):raise ValueError('Invalid installation state')
    return dict(frame)

def proof(frame,request_id):
    if type(frame) is not dict or set(frame)!=FIELDS or frame['type']!='credential_installation':raise ValueError('Invalid installation proof')
    base={key:frame[key] for key in DELIVERY['PROOF_FIELDS']};base['type']='credential_delivery'
    DELIVERY['proof'](base,request_id)
    result,state=frame['result'],frame['journal_state']
    if (result not in ('review','installed','retry','full','rejected','interrupted') or state not in ('unavailable','empty','ready','pending') or
        not UINT(frame['slots_used']) or frame['slots_used']>9 or not UINT(frame['journal_revision']) or
        not HEX(frame['journal_content_id'],32) or type(frame['fault']) is not int or frame['fault'] not in (0,1) or
        (state=='ready')!=(frame['journal_revision']!=0) or (state=='ready')!=(frame['journal_content_id']!='0'*64) or
        (state in ('unavailable','empty') and frame['slots_used']!=0) or (state in ('ready','pending') and frame['slots_used']==0) or
        (result=='review' and state=='unavailable') or
        (result in ('installed','retry') and (state!='ready' or frame['journal_revision']!=frame['credential_revision'] or frame['journal_content_id']!=frame['content_id'])) or
        (result=='full' and (state!='ready' or frame['slots_used']!=9)) or
        (frame['fault']==1 and result not in ('review','interrupted'))):raise ValueError('Inconsistent installation proof')
    return dict(frame)

def message(frame):
    base=DELIVERY['message'](frame).split(b'\n',1)[1]
    return b'OCTATRACE-CREDENTIAL-INSTALLATION-1\n'+base+('\n'.join(str(frame[key]) for key in EXTRA)+'\n').encode('ascii')

def verify(frame,request_id,expected,run=subprocess.run):
    proof(frame,request_id)
    if type(expected) is not dict or not HEX(expected.get('public_key'),65) or not expected['public_key'].startswith('04'):raise ValueError('Invalid selected identity')
    for field in ('role','boot','hardware','device_id','serial','article_id','article_revision_id','transfer_id','challenge','credential_revision','content_id','envelope_sha256','fault'):
        if frame[field]!=expected.get(field):raise ValueError('Installation proof does not match selection')
    if frame['build']!=expected.get('source') or ('result' in expected and frame['result']!=expected['result']):raise ValueError('Installation result or build changed')
    with tempfile.TemporaryDirectory(prefix='octatrace-install-proof-') as temporary:
        folder=Path(temporary)
        public=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')+bytes.fromhex(expected['public_key'])
        for name,data in [('public.der',public),('signature.der',DELIVERY['der'](bytes.fromhex(frame['signature']))),('message',message(frame))]:
            fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:out.write(data)
        result=run(['/usr/bin/openssl','dgst','-sha256','-verify',str(folder/'public.der'),'-keyform','DER','-signature',str(folder/'signature.der'),str(folder/'message')],capture_output=True,timeout=5)
        if result.returncode:raise ValueError('Installation signature verification failed')
    return dict(frame)
