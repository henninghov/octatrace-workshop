"""Public fixture-only server custody acceptance; no DB, KMS or private user QR."""
import contextlib
import copy
from functools import lru_cache
import hashlib
import hmac
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_qr_custody as checker
LOCK=json.loads((ROOT/'qr-custody.lock.json').read_text())
FOLDER=ROOT/LOCK['path']
C=runpy.run_path(str(FOLDER/'codec.py'))
V=json.loads((FOLDER/'vectors.json').read_text())
S=V['seals'][0]
SOURCES={r['name']:r for r in V['seals']}
ACCESS={r['name']:r for r in V['access']}

@lru_cache(maxsize=2048)
def primitive(encoded,helper=str(FOLDER/'reference.mjs')):
    # Never use this fixture adapter with real secrets; stdin avoids key-bearing argv.
    result=subprocess.run(['node',helper,'--crypto'],input=encoded,capture_output=True,text=True)
    if result.returncode:raise ValueError('fixture crypto rejected')
    return bytes.fromhex(json.loads(result.stdout)['hex'])

class Crypto:
    def __init__(self,source=S,keys=None):
        self.keys=copy.deepcopy(V['keys'] if keys is None else keys)
        self.nonce=bytes.fromhex(source['wrap_nonce']);self.hook=lambda stage:None
        self.helper=str(FOLDER/'reference.mjs')
    def key(self,kid,env,purpose,write=False):
        rows=[k for k in self.keys if k['key_id']==kid and k['environment']==env and k['purpose']==purpose]
        if len(rows)!=1 or rows[0]['mode'] not in ('active','read_only') or (write and rows[0]['mode']!='active'):raise ValueError('fixture key denied')
        return C['unhex'](rows[0]['key_hex'],32,True)
    def aes(self,op,key,nonce,aad,data):
        return primitive(json.dumps(dict(op=op,key=key.hex(),nonce=nonce.hex(),aad=aad.hex(),data=data.hex()),sort_keys=True),self.helper)
    def encrypt(self,key,nonce,aad,data):return self.aes('encrypt',key,nonce,aad,data)
    def decrypt(self,key,nonce,aad,data):
        out=self.aes('decrypt',key,nonce,aad,data);self.hook('decrypt');return out
    def wrap(self,kid,env,key,aad):return self.nonce+self.aes('encrypt',self.key(kid,env,'qr_wrapping',True),self.nonce,aad,key)
    def unwrap(self,kid,env,data,aad):
        if len(data)!=60:raise ValueError('fixture wrap length')
        out=self.aes('decrypt',self.key(kid,env,'qr_wrapping'),data[:12],aad,data[12:]);self.hook('unwrap');return out
    def mac(self,kid,env,data):return hmac.digest(self.key(kid,env,'qr_verifier',True),data,'sha256')
    def verify_mac(self,kid,env,data,mac):return hmac.compare_digest(hmac.digest(self.key(kid,env,'qr_verifier'),data,'sha256'),mac)

def opening(s=S,crypto=None,codec=C):return codec['_open_checked'](s['record'],s['verifier'],s['binding'],crypto or Crypto(s))[0]
def sealing(s=S,crypto=None,reserve=lambda *args:True,codec=C):
    return codec['seal'](s['text'],s['template'],s['verifier_template'],s['binding'],bytes.fromhex(s['data_key']),crypto or Crypto(s),reserve)

def reveal_case(row,codec=C,extra=None):
    s=SOURCES[row['source']];a=ACCESS[row['access']];state=copy.deepcopy(a['snapshot']);audits=[];clock=[a['now']];crypto=Crypto(s)
    def mutate(stage):
        if row.get('mutate_stage')==stage:state.update(row['changes'])
        if extra:extra(stage,state,clock)
    crypto.hook=mutate
    def get(q):return copy.deepcopy(state)
    def gate(q,stamp,event):
        mutate('gate')
        try:
            fresh,_=codec['authorise'](s['record'],s['verifier'],s['binding'],q,state,clock[0])
            if fresh!=stamp or row.get('audit_failure'):return False
            audits.append(event);return True
        except ValueError:return False
    result=codec['reveal'](s['record'],s['verifier'],s['binding'],a['request'],crypto,get,lambda:clock[0],gate)
    return result,audits

class CustodyTest(unittest.TestCase):
    def denied(self,operation):
        with self.assertRaises(ValueError) as caught:operation()
        self.assertEqual(str(caught.exception),C['ERROR'])
    def test_published_primitive_answers_and_four_canonical_envelopes(self):
        for row in V['primitive_vectors']:
            args={k:row[k] for k in ('op','key','nonce','aad','data') if k in row}
            self.assertEqual(primitive(json.dumps(args,sort_keys=True)).hex(),row['result'])
        for s in V['seals']:
            with self.subTest(name=s['name']):
                r,v=sealing(s);self.assertEqual((r,v),(s['record'],s['verifier']));self.assertEqual(opening(s),s['text'])
                self.assertEqual(C['payload_aad'](r).hex(),s['payload_aad']);self.assertEqual(C['wrap_aad'](r).hex(),s['wrap_aad'])
                self.assertEqual(C['mac_input'](v,s['text']).hex(),s['mac_input'])
                self.assertEqual(len(bytes.fromhex(r['ciphertext'])),161)
                self.assertEqual(len(s['text']),145)
    def test_all_invalid_fields_and_authenticated_tampering_rejected(self):
        funcs={'binding':'bind','record':'record','verifier':'verifier','request':'request','snapshot':'snapshot'}
        for row in V['invalid_fields']:
            with self.subTest(name=row['name']):self.denied(lambda:C[funcs[row['kind']]](row['value']))
        for row in V['failures']:
            s=SOURCES[row['source']]
            with self.subTest(name=row['name']):self.denied(lambda:C['_open_checked'](row.get('record',s['record']),row.get('verifier',s['verifier']),row.get('binding',s['binding']),Crypto(s)))
        for f in ['binding_of','record','verifier','request','snapshot','bind']:
            for x in [None,[],{},'private QR']:self.denied(lambda:C[f](x))
        self.denied(lambda:C['record']({**S['record'],'payload_revision':2}))
        for x in [None,True,-1,1.5,4294967296]:self.denied(lambda:C['number'](x))
        self.assertEqual(C['bind']({**S['binding'],'v':1.0,'claim_revision':1.0}),S['binding'])
    def test_hmac_is_a_code_factor_without_any_ownership_grant(self):
        self.assertTrue(C['matches_claim'](S['text'],S['verifier'],S['binding'],Crypto()))
        claim=C['QR']['decode'](S['text'],S['binding']['environment'])
        fields=claim.to_fields();fields['claim_secret']='99'*32
        changed=C['QR']['encode'](fields)
        self.assertFalse(C['matches_claim'](changed,S['verifier'],S['binding'],Crypto()))
        self.denied(lambda:C['matches_claim'](S['text'],S['verifier'],{**S['binding'],'claim_revision':2},Crypto()))
        self.denied(lambda:C['plaintext'](S['text'],{**S['binding'],'device_uuid':S['record']['record_uuid']}))
        self.denied(lambda:C['plaintext'](S['text'],{**S['binding'],'role':'Core'}))
        for result in [None,1,'true']:
            with patch.object(Crypto,'verify_mac',return_value=result):self.denied(lambda:opening())
        with patch.object(Crypto,'verify_mac',return_value=False):self.denied(lambda:opening())
        self.assertNotIn('ownership',C['matches_claim'].__code__.co_names)
    def test_reservation_is_before_encryption_and_burned_after_failure(self):
        used=set()
        def reserve(key,*ids):
            if key in used:return False
            used.add(key);return True
        before=copy.deepcopy(S)
        with patch.object(Crypto,'encrypt',side_effect=RuntimeError('PRIVATE')):self.denied(lambda:sealing(reserve=reserve))
        self.assertEqual(len(used),1)
        with patch.object(Crypto,'encrypt',side_effect=AssertionError('must not encrypt reused key')):
            self.denied(lambda:sealing(reserve=reserve))
            other=copy.deepcopy(S);other['template']['nonce']='77'*12;other['template']['record_uuid']=S['record']['payload_uuid']
            self.denied(lambda:sealing(other,reserve=reserve))
        self.assertEqual(before,S)
        for result in [False,None,1]:self.denied(lambda:sealing(reserve=lambda *args:result))
        for value in [None,b'x',b'\0'*32,bytearray(b'x'*32)]:
            self.denied(lambda:C['seal'](S['text'],S['template'],S['verifier_template'],S['binding'],value,Crypto(),lambda *args:True))
    def test_crypto_errors_sizes_types_and_oversized_inputs_are_redacted(self):
        for method,values in [('encrypt',[None,b'x']),('wrap',[None,b'',b'x'*2049]),('mac',[None,b'x']),('unwrap',[None,b'x',b'\0'*32]),('decrypt',[None,b'x',b'\xff'*145,b'x'*145])]:
            for value in values:
                with patch.object(Crypto,method,return_value=value):self.denied(lambda:opening() if method in ('unwrap','decrypt') else sealing())
        for method in ['encrypt','wrap','mac','unwrap','decrypt','verify_mac']:
            with patch.object(Crypto,method,side_effect=RuntimeError(S['text'])):self.denied(lambda:opening() if method in ('unwrap','decrypt','verify_mac') else sealing())
        self.denied(lambda:C['invoke'](None,'method'));self.denied(lambda:C['guarded'](None))
        self.denied(lambda:C['plaintext']('private'*200000,S['binding']))
        self.denied(lambda:C['record']({**S['record'],'wrapped_key':'aa'*1000000}))
        self.denied(lambda:C['pair'](S['record'],{**S['verifier'],'claim_revision':2},S['binding']))
    def test_rotation_preserves_original_qr_and_read_only_keys_can_recover(self):
        for row in V['rotations']:
            s=SOURCES[row['source']];crypto=Crypto(s);crypto.nonce=bytes.fromhex(row['wrap_nonce'])
            r,v=s['record'],s['verifier']
            if row['kind']=='wrap':r=C['rewrap'](r,v,s['binding'],row['new_key_id'],crypto);self.assertEqual(r,row['result'])
            else:v=C['rotate_verifier'](r,v,s['binding'],row['new_key_id'],crypto);self.assertEqual(v,row['result'])
            self.assertEqual(C['validate_update'](r,v,s['record'],s['verifier'],crypto),'newer')
            self.assertEqual(C['_open_checked'](r,v,s['binding'],crypto)[0],s['text'])
        self.assertEqual(C['rewrap'](S['record'],S['verifier'],S['binding'],S['record']['wrapping_key_id'],Crypto()),S['record'])
        self.assertEqual(C['rotate_verifier'](S['record'],S['verifier'],S['binding'],S['verifier']['verifier_key_id'],Crypto()),S['verifier'])
        keys=copy.deepcopy(V['keys'])
        for key in keys:key['mode']='read_only'
        self.assertEqual(opening(crypto=Crypto(keys=keys)),S['text']);self.denied(lambda:sealing(crypto=Crypto(keys=keys)))
        for f,kid in [('rewrap',S['verifier']['verifier_key_id']),('rotate_verifier',S['record']['wrapping_key_id'])]:self.denied(lambda:C[f](S['record'],S['verifier'],S['binding'],kid,Crypto()))
        for f,method in [('rewrap','wrap'),('rotate_verifier','mac')]:
            kid=V['rotations'][0 if f=='rewrap' else 1]['new_key_id']
            for out in [None,b'',b'x'*2049]:
                with patch.object(Crypto,method,return_value=out):self.denied(lambda:C[f](S['record'],S['verifier'],S['binding'],kid,Crypto()))
        # Authenticated old rows at maximum counters fail rotation rather than wrap.
        for which,f in [('record','rewrap'),('verifier','rotate_verifier')]:
            r,v=copy.deepcopy(S['template']),copy.deepcopy(S['verifier_template'])
            (r if which=='record' else v)[which+'_revision']=4294967295
            sample={**S,'template':r,'verifier_template':v};r,v=sealing(sample)
            kid=V['rotations'][0 if which=='record' else 1]['new_key_id']
            self.denied(lambda:C[f](r,v,S['binding'],kid,Crypto()))
    def test_update_rollback_conflicts_and_qr_substitution(self):
        r,v=S['record'],S['verifier'];self.assertEqual(C['compare_update'](dict(reversed(list(r.items()))),v,r,v),'retry')
        for nr,nv in [({**r,'record_uuid':r['payload_uuid']},v),({**r,'record_revision':2,'payload_revision':2},v)]:
            if nr['record_revision']==1:self.denied(lambda:C['compare_update'](nr,nv,r,v))
        self.denied(lambda:C['compare_update'](r,v,{**r,'record_revision':2},v))
        self.denied(lambda:C['compare_update'](r,v,r,{**v,'verifier_revision':2}))
        self.denied(lambda:C['compare_update'](r,v,{**r,'record_revision':2,'payload_revision':2},v))
        self.denied(lambda:C['compare_update']({**r,'wrapped_key':'aa'},v,r,v))
        self.denied(lambda:C['compare_update'](r,{**v,'mac':'00'*32},r,v))
        self.denied(lambda:C['compare_update']({**r,'record_revision':2,'nonce':'33'*12},v,r,v))
        fresh=copy.deepcopy(S);fresh['template'].update(record_revision=2,payload_revision=2,payload_uuid=r['record_uuid'],nonce='68'*12);fresh['data_key']='69'*32
        nr,nv=sealing(fresh);self.assertEqual(C['validate_update'](nr,nv,r,v,Crypto()),'newer')
        fields=C['QR']['decode'](S['text'],S['binding']['environment']).to_fields();fields['claim_secret']='98'*32
        fresh['text']=C['QR']['encode'](fields);fresh['verifier_template']['verifier_revision']=2
        changed,cv=sealing(fresh);self.assertEqual(C['compare_update'](changed,cv,r,v),'newer')
        self.denied(lambda:C['validate_update'](changed,cv,r,v,Crypto()))
    def test_current_owner_operator_and_recent_actual_sign_in_access(self):
        for row in V['access']:
            s=SOURCES[row['source']];op=lambda:C['authorise'](s['record'],s['verifier'],s['binding'],row['request'],row['snapshot'],row['now'])
            with self.subTest(name=row['name']):
                if row['result']=='deny':self.denied(op)
                else:self.assertEqual(op()[1],row['result'])
        a=next(r for r in V['access'] if r['result']=='owner');r=SOURCES[a['source']]
        for field,value in [('v',2),('auth_event','bad'),('owner_uuid',None),('operator_revision',0)]:
            state={**a['snapshot'],field:value}
            if field=='operator_revision':state['operator_enabled']=True
            self.denied(lambda:C['snapshot'](state))
        q={**a['request'],'v':2};self.denied(lambda:C['request'](q))
        state={**a['snapshot'],'v':2};self.denied(lambda:C['snapshot'](state))
        self.denied(lambda:C['authorise'](r['record'],r['verifier'],r['binding'],a['request'],a['snapshot'],None))
    def test_reveal_rechecks_access_during_crypto_and_atomic_audit_gate(self):
        for row in V['reveals']:
            with self.subTest(name=row['name']):
                if row['result']=='deny':self.denied(lambda:reveal_case(row))
                else:
                    private,audits=reveal_case(row);s=SOURCES[row['source']]
                    self.assertEqual(private.reveal(),s['text']);self.assertNotIn(s['text'],repr(private));self.assertEqual(len(audits),1)
                    self.assertFalse(set(audits[0]) & {'ciphertext','mac','wrapped_key','claim_secret','text'})
                    headers=private.headers();headers.clear();self.assertEqual(private.headers()['Cache-Control'],'no-store')
        base=next(r for r in V['reveals'] if r['result']!='deny')
        for stage in ['unwrap','decrypt','gate']:
            self.denied(lambda:reveal_case(base,extra=lambda at,state,now:now.__setitem__(0,now[0]+900) if at==stage else None))
            # A changed but still-authorised role/session must restart the attempt.
            self.denied(lambda:reveal_case(base,extra=lambda at,state,now:state.update(session_revision=state['session_revision']+1) if at==stage else None))
        a=ACCESS[base['access']];s=SOURCES[base['source']]
        args=(s['record'],s['verifier'],s['binding'],a['request'],Crypto())
        for out in [False,None,1]:self.denied(lambda:C['reveal'](*args,lambda q:a['snapshot'],lambda:a['now'],lambda *x:out))
        def broken(*args):raise RuntimeError(S['text'])
        for get,clock,gate in [(broken,lambda:a['now'],lambda *x:True),(lambda q:a['snapshot'],broken,lambda *x:True),(lambda q:a['snapshot'],lambda:a['now'],broken)]:self.denied(lambda:C['reveal'](*args,get,clock,gate))
    def test_negative_controls_detect_authentication_gate_binding_and_qr_changes(self):
        source=(FOLDER/'codec.py').read_text()
        def altered(before,after):
            self.assertEqual(source.count(before),1);scope={'__file__':str(FOLDER/'codec.py')}
            exec(compile(source.replace(before,after),'<custody-negative-control>','exec'),scope);return scope
        variant=altered('if guarded(release_gate, q, stamp, event) is not True:\n        fail()','guarded(release_gate, q, stamp, event)')
        row=next(r for r in V['reveals'] if r.get('mutate_stage')=='gate')
        with self.assertRaises(AssertionError):self.denied(lambda:reveal_case(row,variant))
        variant=altered("uid(b['device_uuid'])","b''")
        self.assertNotEqual(variant['payload_aad'](S['record']).hex(),S['payload_aad'])
        variant=altered('if not hmac.compare_digest(old, new):\n        fail()','pass')
        fresh=copy.deepcopy(S);fresh['template'].update(record_revision=2,payload_revision=2);fresh['verifier_template']['verifier_revision']=2
        fields=C['QR']['decode'](S['text'],S['binding']['environment']).to_fields();fields['claim_secret']='95'*32;fresh['text']=C['QR']['encode'](fields)
        nr,nv=sealing(fresh)
        with self.assertRaises(AssertionError):self.denied(lambda:variant['validate_update'](nr,nv,S['record'],S['verifier'],Crypto()))
        # Deliberately bypass the GCM tag: the rejection test MUST fail.
        with tempfile.TemporaryDirectory(dir=ROOT/"build") as temp:
            helper=Path(temp)/'broken.mjs';js=(FOLDER/'reference.mjs').read_text();before='out=Buffer.concat([decipher.update(ciphertext),decipher.final()]);'
            self.assertEqual(js.count(before),1);helper.write_text(js.replace(before,'out=decipher.update(ciphertext);'))
            crypto=Crypto();crypto.helper=str(helper)
            bad=copy.deepcopy(S);cipher=bytes.fromhex(bad['record']['ciphertext']);bad['record']['ciphertext']=(cipher[:-1]+bytes([cipher[-1]^1])).hex()
            with self.assertRaises(AssertionError):self.denied(lambda:opening(bad,crypto))

class CustodyPinTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.folder=self.root/LOCK['path'];shutil.copytree(FOLDER,self.folder)
        (self.root/'qr-custody.lock.json').write_text(json.dumps(LOCK))
        for family in ['claim-qr','device-credential']:
            lock=json.loads((ROOT/(family+'.lock.json')).read_text());shutil.copytree(ROOT/lock['path'],self.root/lock['path']);(self.root/(family+'.lock.json')).write_text(json.dumps(lock))
    def repin(self):
        lock=copy.deepcopy(LOCK);lock['files']={n:hashlib.sha256((self.folder/n).read_bytes()).hexdigest() for n in LOCK['files']};(self.root/'qr-custody.lock.json').write_text(json.dumps(lock))
    def test_owner_consumer_pins_cli_and_dependencies(self):
        expected={k:len(V[k]) for k in checker.COUNTS};self.assertEqual(checker.verify(ROOT),expected);self.assertEqual(checker.verify(self.root),expected)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):runpy.run_path(str(ROOT/'tools/verify_qr_custody.py'),run_name='__main__')
        self.assertEqual(json.loads(stream.getvalue()),expected)
        for family in ['claim_qr','device_credential']:
            lock=copy.deepcopy(LOCK);lock['requires_'+family+'_files_sha256']={};(self.root/'qr-custody.lock.json').write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError,'dependency mismatch'):checker.verify(self.root)
    def test_inventory_hash_path_and_symlink_guards(self):
        for key,val in [('profile','bad'),('version',2),('source_repository','bad'),('path','../bad'),('files',{})]:
            (self.root/'qr-custody.lock.json').write_text(json.dumps({**LOCK,key:val}))
            with self.assertRaisesRegex(ValueError,'Unsupported QR custody pin'):checker.verify(self.root)
        (self.root/'qr-custody.lock.json').write_text(json.dumps(LOCK));extra=self.folder/'extra';extra.write_text('x')
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
        extra.unlink();p=self.folder/'codec.py';old=p.read_bytes();p.write_bytes(old+b'\n')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        p.write_bytes(old);lock=copy.deepcopy(LOCK);lock['files']['codec.py']='bad';(self.root/'qr-custody.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        (self.root/'qr-custody.lock.json').write_text(json.dumps(LOCK));p.unlink();p.symlink_to(FOLDER/'codec.py')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        shutil.rmtree(self.folder);self.folder.symlink_to(FOLDER,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
    def test_repinned_semantic_tampering_and_redaction(self):
        cases=[('profile.json',lambda x:x.update(version=2),'profile'),('custody.schema.json',lambda x:x.update(oneOf=[]),'schema'),('vectors.json',lambda x:x.update(synthetic=False),'vectors'),('vectors.json',lambda x:x.update(seals=[]),'vectors'),('vectors.json',lambda x:x['seals'][0].update(payload_aad='00'),'positive vector'),('vectors.json',lambda x:x['invalid_fields'][0].update(value=S['binding']),'invalid fields accepted')]
        for name,change,message in cases:
            p=self.folder/name;old=p.read_bytes();value=json.loads(p.read_text());change(value);p.write_text(json.dumps(value));self.repin()
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,message):checker.verify(self.root)
            p.write_bytes(old);self.repin()
        p=self.folder/'codec.py';p.write_text(p.read_text().replace("ERROR = 'Private QR operation denied'","ERROR = 'PRIVATE'"));self.repin()
        with self.assertRaisesRegex(ValueError,'may disclose'):checker.verify(self.root)
    def test_reference_failure_wrong_summary_and_false_negative(self):
        actual=checker.subprocess.run
        for result in [subprocess.CompletedProcess([],1,'',''),subprocess.CompletedProcess([],0,'{}','')]:
            def run(args,**kwargs):return result if 'qr-custody/reference.mjs' in args[1] else actual(args,**kwargs)
            with patch.object(checker.subprocess,'run',side_effect=run):
                with self.assertRaisesRegex(ValueError,'Independent QR custody'):checker.verify(self.root)
        p=self.folder/'vectors.json';v=json.loads(p.read_text());v['failures'][0]['record']=S['record'];v['failures'][0]['verifier']=S['verifier'];v['failures'][0]['binding']=S['binding'];p.write_text(json.dumps(v));self.repin()
        with self.assertRaisesRegex(ValueError,'Independent QR custody'):checker.verify(self.root)

if __name__=='__main__':unittest.main()
