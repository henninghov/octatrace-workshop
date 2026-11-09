"""Authority journal acceptance. Public keys/fixtures, real files and fault model."""
import contextlib
import copy
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
import random
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'authority-storage.lock.json').is_file())
sys.path.insert(0,str(ROOT/'tools'))
import verify_authority_storage as checker
LOCK=json.loads((ROOT/'authority-storage.lock.json').read_text());FOLDER=ROOT/LOCK['path']
C=runpy.run_path(str(FOLDER/'codec.py'));FILE=runpy.run_path(str(FOLDER/'file_flash.py'))['FileFlash']
V=json.loads((FOLDER/'vectors.json').read_text());ROWS={r['name']:r for r in V['authorities']};SN={r['name']:r for r in V['snapshots']}

class PublicCrypto:
    @staticmethod
    def spki(point):return bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')+point
    @lru_cache(maxsize=64)
    def valid_public_key(self,point):
        r=subprocess.run(['openssl','ec','-pubin','-inform','DER','-pubout','-outform','DER'],input=self.spki(point),capture_output=True)
        return r.returncode==0 and r.stdout==self.spki(point)
    @lru_cache(maxsize=512)
    def verify(self,point,message,signature):
        def integer(b):
            b=b.lstrip(b'\0') or b'\0'
            if b[0]&128:b=b'\0'+b
            return b'\x02'+bytes([len(b)])+b
        parts=integer(signature[:32])+integer(signature[32:])
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);(p/'key').write_bytes(self.spki(point));(p/'sig').write_bytes(b'\x30'+bytes([len(parts)])+parts);(p/'message').write_bytes(message)
            r=subprocess.run(['openssl','dgst','-sha256','-verify',str(p/'key'),'-keyform','DER','-signature',str(p/'sig'),str(p/'message')],capture_output=True)
        return r.returncode==0
CRYPTO=PublicCrypto()
def raw(name):return bytes.fromhex(ROWS[name]['hex'])
def context(name='dev-link-empty',codec=C):
    s=SN[name];return codec['Context'](s['local'],s['registry'],V['issuers'],CRYPTO)
def snapshot(name='dev-link-empty',codec=C):return context(name,codec).decode(bytes.fromhex(SN[name]['hex']))
def image(row):
    b=bytearray(b'\xff'*C['SIZE'])
    for p in row['patches']:b[p['offset']:p['offset']+len(bytes.fromhex(p['hex']))]=bytes.fromhex(p['hex'])
    return bytes(b)

class Flash:
    """Independent test IO: zero-to-one refusal and injectable word-prefix power cuts."""
    def __init__(self,data=None,cut=None):self.data=bytearray(data if data is not None else b'\xff'*C['SIZE']);self.cut=cut;self.trace=[]
    def read(self,offset,size):return bytes(self.data[offset:offset+size])
    def change(self,kind,offset,data):
        index=len(self.trace);self.trace.append((kind,offset,data))
        if self.cut and index==self.cut[0]:
            n=self.cut[1];self.data[offset:offset+n]=data[:n];self.cut=None;raise RuntimeError('simulated power cut')
        self.data[offset:offset+len(data)]=data;return True
    def erase_page(self,page):return self.change('erase',page*C['PAGE'],b'\xff'*C['PAGE'])
    def program(self,offset,data):
        assert offset%4==0 and len(data)%4==0 and len(data)<=128
        assert all((a&b)==b for a,b in zip(self.data[offset:offset+len(data)],data))
        return self.change('program',offset,data)

def baseline(codec=C):
    f=Flash();j=codec['Journal'](f,context(codec=codec));j.prepare(lambda:True)
    for n in ['dev-link-owner','dev-phone1']:j.install(raw(n),lambda:True)
    return f,j

class StorageTest(unittest.TestCase):
    def denied(self,operation):
        with self.assertRaises(ValueError) as e:operation()
        self.assertEqual(str(e.exception),C['ERROR'])
    def test_independent_bytes_signed_records_and_all_recovery_vectors(self):
        for s in V['snapshots']:
            ctx=context(s['name']);value=ctx.encode([raw(n) for n in s['records']]);self.assertEqual(value.payload.hex(),s['hex']);self.assertEqual(ctx.decode(value.payload),value)
            b=C['bank_bytes'](s['generation'],value.payload);self.assertEqual(b[:64].hex(),s['header_hex']);self.assertEqual(hashlib.sha256(b).hexdigest(),s['bank_sha256']);self.assertEqual(C['parse_bank'](b,ctx)[0],s['generation'])
        for row in V['images']:
            r=C['Journal'](Flash(image(row)),context(row['context'])).read();self.assertEqual((r.status,r.generation),(row['status'],row['generation']),row['name'])
        for row in V['transitions']:
            op=lambda:context(row['before']).transition(snapshot(row['before']),snapshot(row['after']))
            if row['result']=='deny':self.denied(op)
            else:self.assertIsNone(op())
        for row in V['merges']:
            op=lambda:context(row['snapshot']).merge(snapshot(row['snapshot']),raw(row['record']))
            if row['result']=='deny':self.denied(op)
            else:self.assertEqual(op().payload,snapshot(row['result']).payload)
        for row in V['eligible']:self.assertEqual(context(row['snapshot']).eligible(snapshot(row['snapshot']),row['purpose'],row['resource_uuid']),row['result'])
    def test_preparation_is_explicit_and_never_erases_unknown_state(self):
        f=Flash();j=C['Journal'](f,context());self.assertEqual(j.read().status,'Unprepared')
        for guard in [None,lambda:False,lambda:1]:self.denied(lambda:j.prepare(guard))
        self.denied(lambda:j.install(raw('dev-link-owner'),lambda:True));self.denied(lambda:j.recover(lambda:True))
        self.assertEqual(j.prepare(lambda:True),'installed');self.assertEqual(j.prepare(lambda:True),'unchanged');self.assertEqual(j.recover(lambda:True),'unchanged')
        j.install(raw('dev-link-owner'),lambda:True);self.denied(lambda:j.prepare(lambda:True))
        f=Flash();f.data[0]=0;j=C['Journal'](f,context());before=bytes(f.data);self.denied(lambda:j.prepare(lambda:True));self.assertEqual(bytes(f.data),before)
        f=Flash();empty=snapshot();f.data[:C['BANK']]=C['bank_bytes'](1,empty.payload);j=C['Journal'](f,context());self.assertEqual(j.read().status,'Pending');self.denied(lambda:j.recover(lambda:True));self.assertEqual(j.prepare(lambda:True),'installed')
    def test_real_file_restart_removal_lost_reply_and_owner_epoch(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'flash';io=FILE.create(p);j=C['Journal'](io,context());j.prepare(lambda:True)
            for n in ['dev-link-owner','dev-phone1','dev-phone-removed']:self.assertEqual(j.install(raw(n),lambda:True),'installed')
            again=C['Journal'](FILE(p),context());self.assertEqual(again.read().generation,4);self.denied(lambda:again.install(raw('dev-phone1'),lambda:True));self.assertEqual(again.install(raw('dev-phone-removed'),lambda:True),'unchanged')
            again.install(raw('dev-link-transfer'),lambda:True);self.assertFalse(context().eligible(again.read().snapshot,'phone_controller',SN['dev-link-empty']['local']['resource_uuid']))
            again.install(raw('dev-phone-after-transfer'),lambda:True);r=C['Journal'](FILE(p),context()).read();self.assertTrue(context().eligible(r.snapshot,'phone_controller',SN['dev-link-empty']['local']['resource_uuid']))
            self.assertEqual(len(p.read_bytes()),C['SIZE'])
    def test_each_mutation_word_prefix_power_cut_never_confirms_older_state(self):
        f,j=baseline();before=bytes(f.data);good=Flash(before);C['Journal'](good,context()).install(raw('dev-phone-removed'),lambda:True);trace=good.trace
        cases=0;outcomes=set()
        for operation,(_,_,data) in enumerate(trace):
            for n in range(0,len(data)+1,4):
                io=Flash(before,(operation,n));journal=C['Journal'](io,context())
                try:result=journal.install(raw('dev-phone-removed'),lambda:True)
                except ValueError:result='not-installed'
                state=journal.read();outcomes.add(state.status);cases+=1
                if result=='installed':self.assertEqual(state.generation,4);self.assertEqual(state.status,'Ready')
                if state.status=='Ready':self.assertIn(state.generation,(3,4))
                elif state.status=='Pending':
                    self.assertEqual(state.generation,4);self.assertEqual(journal.recover(lambda:True),'installed');self.assertEqual(journal.read().generation,4)
                else:self.assertEqual(state.status,'Fault')
        self.assertGreater(cases,4000);self.assertEqual(outcomes,{'Ready','Pending','Fault'});print(json.dumps({'word_prefix_cut_cases':cases}))
    def test_real_file_all_mutation_boundaries_close_reopen_and_recover(self):
        f,_=baseline();before=bytes(f.data)
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'flash';p.write_bytes(before);events=[]
            io=FILE(p,lambda stage,*args:events.append((stage,args)) if stage.startswith(('before_program','after_program','before_erase','after_erase')) else None)
            C['Journal'](io,context()).install(raw('dev-phone-removed'),lambda:True)
            self.assertGreater(len(events),20);print(json.dumps({'real_file_mutation_boundaries':len(events)}))
            for point in range(len(events)):
                p.write_bytes(before);count=[0];fired=[False]
                def hook(stage,*args):
                    if stage.startswith(('before_program','after_program','before_erase','after_erase')):
                        if count[0]==point and not fired[0]:fired[0]=True;raise RuntimeError('power lost')
                        count[0]+=1
                j=C['Journal'](FILE(p,hook),context())
                try:result=j.install(raw('dev-phone-removed'),lambda:True)
                except ValueError:result='not-installed'
                reopened=C['Journal'](FILE(p),context());state=reopened.read();self.assertIn(state.status,('Ready','Pending'))
                if result=='installed':self.assertEqual(state.generation,4)
                if state.status=='Pending':self.assertEqual(reopened.recover(lambda:True),'installed')
    def test_commit_callback_is_not_durable_confirmation_and_cancel_has_no_false_success(self):
        f,j=baseline();old=bytes(f.data);actual=f.program
        def dropped(offset,data):
            if offset%C['BANK']==56:return False
            return actual(offset,data)
        with patch.object(f,'program',side_effect=dropped):self.denied(lambda:j.install(raw('dev-phone-removed'),lambda:True))
        self.assertEqual(j.read().generation,3)
        f=Flash(old);j=C['Journal'](f,context());actual=f.program
        def completed_but_error(offset,data):
            result=actual(offset,data)
            if offset%C['BANK']==56:return False
            return result
        with patch.object(f,'program',side_effect=completed_but_error):self.assertEqual(j.install(raw('dev-phone-removed'),lambda:True),'installed')
        for value in [False,None,1]:self.denied(lambda:j.install(raw('dev-phone-removed'),lambda:value));self.denied(lambda:j.recover(lambda:value))
        f=Flash(old);j=C['Journal'](f,context());calls=[0]
        def cancel():calls[0]+=1;return calls[0]<6
        self.denied(lambda:j.install(raw('dev-phone-removed'),cancel));self.assertEqual(j.read().generation,3)
    def test_faults_wrong_sizes_exhaustion_and_corruption_do_not_reset_history(self):
        f,j=baseline()
        with patch.object(f,'read',side_effect=RuntimeError('PRIVATE')):self.assertEqual(j.read().status,'Unavailable')
        with patch.object(f,'read',return_value=b'x'):self.assertEqual(j.read().status,'Fault')
        for method in ['erase_page','program']:
            with patch.object(f,method,return_value=False):self.denied(lambda:j.install(raw('dev-phone-removed'),lambda:True))
        # A readback mismatch must fail; reload cannot invent a commit.
        actual=f.read
        with patch.object(f,'read',side_effect=lambda a,n:b'x'*n if n<128 else actual(a,n)):self.denied(lambda:j.install(raw('dev-phone-removed'),lambda:True))
        f,j=baseline();s=j.read().snapshot;f.data[:]=C['bank_bytes'](4294967295,s.payload)*3
        self.denied(lambda:j.install(raw('dev-phone-removed'),lambda:True));self.assertEqual(j.read().generation,4294967295)
        f,j=baseline();state=j.read();bank=state.copies[0];f.data[bank*C['BANK']+64]^=1;self.assertEqual(j.read().status,'Fault');before=bytes(f.data)
        self.denied(lambda:j.install(raw('dev-phone-removed'),lambda:True));self.denied(lambda:j.recover(lambda:True));self.assertEqual(bytes(f.data),before)
        # Loss of both newer copies cannot silently resurrect the remaining older grant.
        f,j=baseline();j.install(raw('dev-phone-removed'),lambda:True);state=j.read()
        for bank in state.copies:f.data[bank*C['BANK']:(bank+1)*C['BANK']]=b'\xff'*C['BANK']
        self.assertEqual(j.read().status,'Fault')
    def test_full_capacity_preserves_all_24_signed_records_and_refuses_25th(self):
        payload=snapshot('dev-capacity-full').payload;bank=C['bank_bytes'](8,payload);f=Flash(bank*3);j=C['Journal'](f,context('dev-capacity-full'));before=bytes(f.data)
        self.assertEqual(j.read().status,'Ready');self.assertEqual(len(j.read().snapshot.entries),24)
        self.denied(lambda:j.install(raw('dev-phone1'),lambda:True));self.assertEqual(bytes(f.data),before)

    def test_strict_snapshot_parser_truncations_capacity_and_registry_boundaries(self):
        for row in V['invalid_snapshots']:self.denied(lambda:context(row['context']).decode(bytes.fromhex(row['hex'])))
        source=snapshot('dev-link-phone').payload
        for n in range(len(source)):self.denied(lambda:context().decode(source[:n]))
        for data in [None,b'',b'x'*1000000,bytearray(source)]:self.denied(lambda:context().decode(data))
        for data in [b'\x18\x01',b'\x19\x00\x18',b'\x1a\0\0\0\xff',b'\x1b'+b'\0'*8,b'\x58',b'\x58\xff',b'\x81'*5+b'\x00',b'\x20',b'\xa0']:
            self.denied(lambda:C['uncbor'](data))
        self.assertEqual(C['uncbor'](b'\x18\x18'),24);self.assertEqual(C['uncbor'](b'\x19\x01\0'),256);self.assertEqual(C['uncbor'](b'\x1a\0\x01\0\0'),65536)
        self.denied(lambda:C['uncbor'](b'\x18'))
        for bad in [None,b'',b'x'*8129]:self.denied(lambda:C['uncbor'](bad))
        for x in [None,[],{},'private']:self.denied(lambda:C['binding'](x))
        b=SN['dev-link-empty']['local'];registry=SN['dev-link-empty']['registry']
        for r in [None,{},[],{**registry,'bad':b},{b['resource_uuid']:{**b,'environment':'production'}},{'x':b}]:self.denied(lambda:C['Context'](b,r,V['issuers'],CRYPTO))
        other=copy.deepcopy(registry);other[b['resource_uuid']]['resource_key_revision']=2;self.denied(lambda:C['Context'](b,other,V['issuers'],CRYPTO))
        for raws in [None,{},[raw('dev-link-owner')]*25,[raw('dev-link-owner')]*2]:self.denied(lambda:context().encode(raws))
        for r in [None,b'x',b'x'*271,b'\xd2\x80']:
            self.denied(lambda:context().entry(r))
        unknown=C['Context'](b,{b['resource_uuid']:b},V['issuers'],CRYPTO);self.denied(lambda:unknown.entry(raw('dev-coreA-owner')))
        self.denied(lambda:context('dev-core-empty').entry(raw('dev-phone1')));self.denied(lambda:context('dev-core-empty').entry(raw('dev-coreB-peer1')))
        for payload in [None,b'',b'x'*8129]:self.denied(lambda:C['bank_bytes'](1,payload))
        for data in [None,b'',b'x'*8193]:self.denied(lambda:C['parse_bank'](data,context()))
        for n in [None,True,-1,4294967296]:self.denied(lambda:C['bank_bytes'](n,source))
        # Conservative upper bound: every signed object at b2's maximum size.
        worst=C['BASE']['cbor'](C['prefix']({**b,'resource_key_revision':4294967295})+[[b'x'*270]*24]);self.assertLessEqual(len(worst),C['CAPACITY']);self.assertGreater(len(worst),6500);print(json.dumps({'worst_snapshot_bound_bytes':len(worst)}))
        with patch.dict(C['BASE'],cbor=lambda v:b'x'*8129):self.denied(lambda:context().encode([]))
        rng=random.Random(432)
        for _ in range(150):self.denied(lambda:context().decode(bytes(rng.randrange(256) for _ in range(rng.randrange(1,70)))))
    def test_no_network_clock_or_read_side_effect_and_no_traffic_key_restore(self):
        f,j=baseline();before=bytes(f.data);writes=len(f.trace)
        with patch.object(socket,'create_connection',side_effect=AssertionError('network')),patch.object(time,'time',side_effect=AssertionError('clock')):
            for _ in range(3):self.assertEqual(j.read().status,'Ready')
        self.assertEqual(bytes(f.data),before);self.assertEqual(len(f.trace),writes)
        self.assertNotIn('resource_uuid',repr(j.read()));self.assertNotIn('raw',repr(j.read().snapshot))
        with self.assertRaises(Exception):j.read().snapshot.entries=()
    def test_file_flash_bounds_zero_to_one_short_io_and_callbacks(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'flash';f=FILE.create(p)
            with self.assertRaises(FileExistsError):FILE.create(p)
            for args in [(-1,4),(0,0),(0,24577),(True,4),(0,True)]:
                with self.assertRaises(ValueError):f.read(*args)
            for a,d in [(0,None),(0,b''),(0,b'x'*132),(1,b'xxxx'),(0,b'x'),(True,b'xxxx'),(24576,b'xxxx')]:
                with self.assertRaises(ValueError):f.program(a,d)
            f.program(0,b'\0'*4)
            with self.assertRaises(ValueError):f.program(0,b'\xff'*4)
            f.erase_page(0);self.assertEqual(f.read(0,4),b'\xff'*4)
            for n in [None,True,-1,6]:
                with self.assertRaises(ValueError):f.erase_page(n)
            p.write_bytes(b'x')
            with self.assertRaises(ValueError):FILE(p)
            with self.assertRaises(ValueError):f.read(0,4)
            class Short:
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def seek(self,*args):pass
                def write(self,*args):return 0
            with patch.object(Path,'open',return_value=Short()):
                with self.assertRaises(ValueError):f.change(0,b'\0'*4,'program')
    def test_negative_controls_single_copy_ack_removal_rollback_and_missing_readback(self):
        source=(FOLDER/'codec.py').read_text()
        def altered(before,after):
            self.assertEqual(source.count(before),1);scope={'__file__':str(FOLDER/'codec.py')};exec(compile(source.replace(before,after),'<journal-negative-control>','exec'),scope);return scope
        variant=altered('if len(copies) >= 2:','if len(copies) >= 1:')
        row=next(r for r in V['images'] if r['name']=='pending-then-quorum')
        self.assertNotEqual(variant['Journal'](Flash(image(row)),context(codec=variant)).read().status,row['status'])
        variant=altered('generation = generations[-1]','generation = generations[0]')
        self.assertNotEqual(variant['Journal'](Flash(image(row)),context(codec=variant)).read().generation,row['generation'])
        variant=altered("result = guarded(AUTH['compare_revision'], e.authority, None if prior is None else prior.authority)","result = 'retry'")
        variant['Context'].merge.__globals__['AUTH']=dict(variant['AUTH'],compare_revision=lambda *args:'newer')
        with self.assertRaises(AssertionError):self.denied(lambda:context('dev-link-removed',variant).merge(snapshot('dev-link-removed',variant),raw('dev-phone1')))
        variant=altered('if readback != raw:','if False:')
        f=Flash();j=variant['Journal'](f,context(codec=variant));actual=f.read
        with patch.object(f,'read',side_effect=lambda a,n:b'\xff'*n if n==C['BANK'] else actual(a,n)):
            # A write_copy must detect mismatch even when a caller ignores the final publish check.
            with self.assertRaises(AssertionError):self.denied(lambda:j.write_copy(0,1,snapshot(codec=variant),lambda:True))

class PinTest(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.folder=self.root/LOCK['path'];shutil.copytree(FOLDER,self.folder);(self.root/'authority-storage.lock.json').write_text(json.dumps(LOCK))
        for family in ['device-authority','device-credential']:
            pin=json.loads((ROOT/(family+'.lock.json')).read_text());(self.root/(family+'.lock.json')).write_text(json.dumps(pin));shutil.copytree(ROOT/pin['path'],self.root/pin['path'])
    def repin(self):
        pin=copy.deepcopy(LOCK);pin['files']={n:hashlib.sha256((self.folder/n).read_bytes()).hexdigest() for n in LOCK['files']};(self.root/'authority-storage.lock.json').write_text(json.dumps(pin))
    def test_real_cli_dependencies_and_owner_consumer_pins(self):
        expected={k:len(V[k]) for k in checker.COUNTS};self.assertEqual(checker.verify(ROOT),expected);self.assertEqual(checker.verify(self.root),expected)
        out=io.StringIO()
        with contextlib.redirect_stdout(out):runpy.run_path(str(ROOT/'tools/verify_authority_storage.py'),run_name='__main__')
        self.assertEqual(json.loads(out.getvalue()),expected)
        for family in ['device_authority','device_credential']:
            p=copy.deepcopy(LOCK);p['requires_'+family+'_files_sha256']={};(self.root/'authority-storage.lock.json').write_text(json.dumps(p))
            with self.assertRaisesRegex(ValueError,'dependency mismatch'):checker.verify(self.root)
    def test_pin_inventory_hash_symlink_and_repinned_semantic_guards(self):
        for k,v in [('profile','x'),('version',2),('source_repository','x'),('path','../x'),('files',{})]:
            (self.root/'authority-storage.lock.json').write_text(json.dumps({**LOCK,k:v}))
            with self.assertRaisesRegex(ValueError,'Unsupported authority storage pin'):checker.verify(self.root)
        (self.root/'authority-storage.lock.json').write_text(json.dumps(LOCK));extra=self.folder/'extra';extra.write_text('x')
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
        extra.unlink();p=self.folder/'codec.py';old=p.read_bytes();p.write_bytes(old+b'\n')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        p.write_bytes(old);pin=copy.deepcopy(LOCK);pin['files']['codec.py']='bad';(self.root/'authority-storage.lock.json').write_text(json.dumps(pin))
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        (self.root/'authority-storage.lock.json').write_text(json.dumps(LOCK));p.unlink();p.symlink_to(FOLDER/'codec.py')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        shutil.rmtree(self.folder);self.folder.symlink_to(FOLDER,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
    def test_repinned_profile_schema_vectors_error_redaction_and_generation_guard(self):
        cases=[('profile.json',lambda v:v.update(version=2),'profile'),('snapshot.schema.json',lambda v:v.update(properties={}), 'schema'),('vectors.json',lambda v:v.update(synthetic=False),'vectors'),('vectors.json',lambda v:v.update(snapshots=[]),'vectors'),('vectors.json',lambda v:v['snapshots'][0].update(header_hex='00'),'positive vector')]
        for name,mutate,message in cases:
            p=self.folder/name;old=p.read_bytes();v=json.loads(p.read_text());mutate(v);p.write_text(json.dumps(v));self.repin()
            with self.assertRaisesRegex(ValueError,message):checker.verify(self.root)
            p.write_bytes(old);self.repin()
        p=self.folder/'codec.py';old=p.read_text();p.write_text(old.replace("ERROR = 'Authority storage operation denied'","ERROR = 'PRIVATE'"));self.repin()
        with self.assertRaisesRegex(ValueError,'may disclose'):checker.verify(self.root)
        p.write_text(old.replace("generation = number(generation)","generation = number(generation) if generation else 1"));self.repin()
        with self.assertRaisesRegex(ValueError,'invalid generation accepted'):checker.verify(self.root)
    def test_independent_reference_failure_and_wrong_counts(self):
        actual=checker.subprocess.run
        for result in [subprocess.CompletedProcess([],1,'',''),subprocess.CompletedProcess([],0,'{}','')]:
            def run(args,**kwargs):return result if 'authority-storage/reference.mjs' in args[1] else actual(args,**kwargs)
            with patch.object(checker.subprocess,'run',side_effect=run):
                with self.assertRaisesRegex(ValueError,'Independent authority storage'):checker.verify(self.root)
        p=self.folder/'vectors.json';v=json.loads(p.read_text());v['images'][0]['status']='Ready';p.write_text(json.dumps(v));self.repin()
        with self.assertRaisesRegex(ValueError,'Independent authority storage'):checker.verify(self.root)

if __name__=='__main__':unittest.main()
