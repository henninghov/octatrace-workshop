"""Strict public-credential delivery frames and device proof verification."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

MAX_ID=0xffffffff
STATUS_FIELDS=frozenset(('v','id','ok','type','role','build','hardware','boot','state','last_transfer','transfer_id','total','received'))
PROOF_FIELDS=frozenset(('v','id','ok','type','role','build','hardware','boot','device_id','serial','article_id',
    'article_revision_id','transfer_id','challenge','credential_revision','content_id','envelope_sha256','signature'))
UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')

def valid_hex(value,n,nonzero=False):
    return (type(value) is str and len(value)==2*n and re.fullmatch('[0-9a-f]+',value) is not None
            and (not nonzero or value!='0'*(2*n)))

def number(value,minimum=0):
    return type(value) is int and minimum<=value<=MAX_ID

def common(frame,request_id,fields,kind):
    if (type(frame) is not dict or set(frame)!=fields or not number(request_id,1) or
        type(frame['v']) is not int or frame['v']!=1 or type(frame['id']) is not int or frame['id']!=request_id or
        frame['ok'] is not True or frame['type']!=kind or frame['role'] not in ('Link','Core') or
        not valid_hex(frame['build'],32) or not valid_hex(frame['hardware'],8,True) or not valid_hex(frame['boot'],16,True)):
        raise ValueError('Invalid credential delivery frame')

def status(frame,request_id):
    common(frame,request_id,STATUS_FIELDS,'credential_delivery_status')
    if (frame['state'] not in ('idle','receiving','verifying','verified','failed') or
        any(not number(frame[key]) for key in ('last_transfer','transfer_id','total','received')) or
        frame['received']>frame['total'] or frame['total']>271):
        raise ValueError('Invalid credential delivery status')
    if frame['state'] in ('receiving','verifying','verified'):
        if not frame['transfer_id'] or frame['transfer_id']!=frame['last_transfer'] or not frame['total']:
            raise ValueError('Invalid credential delivery status')
        if frame['state'] in ('verifying','verified') and frame['received']!=frame['total']:
            raise ValueError('Invalid credential delivery status')
    elif frame['transfer_id'] or frame['total'] or frame['received']:
        raise ValueError('Invalid credential delivery status')
    return dict(frame)

def proof(frame,request_id):
    common(frame,request_id,PROOF_FIELDS,'credential_delivery')
    if (any(type(frame[key]) is not str or not UUID.fullmatch(frame[key]) for key in ('device_id','article_id','article_revision_id')) or
        type(frame['serial']) is not str or not re.fullmatch(r'D[0-9]{12}',frame['serial']) or frame['serial']=='D000000000000' or
        not number(frame['transfer_id'],1) or not number(frame['credential_revision'],1) or
        not valid_hex(frame['challenge'],32,True) or not valid_hex(frame['content_id'],32,True) or
        not valid_hex(frame['envelope_sha256'],32,True) or not valid_hex(frame['signature'],64,True)):
        raise ValueError('Invalid credential delivery proof')
    return dict(frame)

def message(frame):
    return ('OCTATRACE-CREDENTIAL-DELIVERY-1\n'+'\n'.join(str(frame[key]) for key in
        ('role','build','boot','hardware','device_id','serial','article_id','article_revision_id',
         'transfer_id','challenge','credential_revision','content_id','envelope_sha256'))+'\n').encode('ascii')

def der(raw):
    def integer(value):
        value=value.lstrip(b'\0') or b'\0'
        if value[0]&128:value=b'\0'+value
        return b'\x02'+bytes([len(value)])+value
    body=integer(raw[:32])+integer(raw[32:])
    return b'\x30'+bytes([len(body)])+body

def verify(frame,request_id,expected,run=subprocess.run):
    proof(frame,request_id)
    if type(expected) is not dict or not valid_hex(expected.get('public_key'),65) or not expected['public_key'].startswith('04'):
        raise ValueError('Invalid selected device identity')
    for field in ('role','boot','hardware','device_id','serial','article_id','article_revision_id','transfer_id',
                  'challenge','credential_revision','content_id','envelope_sha256'):
        if frame[field]!=expected.get(field):raise ValueError('Credential delivery proof does not match selection')
    if frame['build']!=expected.get('source'):raise ValueError('Credential delivery build changed')
    with tempfile.TemporaryDirectory(prefix='octatrace-delivery-proof-') as tmp:
        folder=Path(tmp)
        public=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')+bytes.fromhex(expected['public_key'])
        for name,data in [('public.der',public),('signature.der',der(bytes.fromhex(frame['signature']))),('message',message(frame))]:
            fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:out.write(data)
        result=run(['/usr/bin/openssl','dgst','-sha256','-verify',str(folder/'public.der'),'-keyform','DER',
                    '-signature',str(folder/'signature.der'),str(folder/'message')],capture_output=True,timeout=5)
        if result.returncode:raise ValueError('Credential delivery signature verification failed')
    return dict(frame)
