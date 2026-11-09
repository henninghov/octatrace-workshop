"""Setup proof and field binding tests; public fixture keys only, no claim/device IO."""
import contextlib
import copy
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
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'proof-context.lock.json').is_file())
sys.path.insert(0,str(ROOT/'tools'))
import verify_proof_context as checker
LOCK=json.loads((ROOT/'proof-context.lock.json').read_text());FOLDER=ROOT/LOCK['path']
CODEC=runpy.run_path(str(FOLDER/'codec.py'));V=json.loads((FOLDER/'vectors.json').read_text())

class PublicOpenSSL:
    """Independent test adapter: LibreSSL imports P-256 SPKI and verifies SHA256/DER."""
    def __init__(self):
        self.cache = {}

    @staticmethod
    def spki(point):
        return bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + point

    def valid_public_key(self, point):
        if point not in self.cache:
            result = subprocess.run(['openssl', 'ec', '-pubin', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                                    input=self.spki(point), capture_output=True)
            self.cache[point] = result.returncode == 0 and result.stdout == self.spki(point)
        return self.cache[point]

    def verify(self, point, message, signature):
        def integer(value):
            value = value.lstrip(b'\0') or b'\0'
            if value[0] & 128:
                value = b'\0' + value
            return b'\x02' + bytes([len(value)]) + value
        parts = integer(signature[:32]) + integer(signature[32:])
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name, value in [('key.der', self.spki(point)), ('message', message),
                                ('sig.der', b'\x30' + bytes([len(parts)]) + parts)]:
                (folder / name).write_bytes(value)
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(folder / 'key.der'),
                                     '-keyform', 'DER', '-signature', str(folder / 'sig.der'),
                                     str(folder / 'message')], capture_output=True)
        return result.returncode == 0


CRYPTO=PublicOpenSSL()
CH={r['name']:r for r in V['challenges']};PR={r['name']:r for r in V['proofs']}
BASE=CH['dev-first_claim']
DEP=json.loads((ROOT/'device-authority.lock.json').read_text());AV=json.loads((ROOT/DEP['path']/'vectors.json').read_text())


def verify_ch(row=BASE,codec=CODEC,**options):
    args=dict(environment=row.get('environment',row.get('fields',{}).get('environment')),issuers=row.get('issuers',V['issuers']),crypto=CRYPTO,expected=row['expected']);args.update(options)
    return codec['verify_challenge'](bytes.fromhex(row['hex']),**args)


def verify_pr(row,codec=CODEC,**options):
    args=dict(current_challenge=options['current_challenge'] if 'current_challenge' in options else verify_ch(CH[row['challenge']],codec),public_key=bytes.fromhex(row['public_key']),crypto=CRYPTO);args.update(options)
    return codec['verify_proof'](bytes.fromhex(row['hex']),**args)


def authority(name,codec=CODEC):
    r=next(r for r in AV['valid'] if r['name']==name)
    return codec['AUTH']['verify'](bytes.fromhex(r['hex']),r['fields']['environment'],AV['issuers'],CRYPTO,r['expected'])


class ProofContextTest(unittest.TestCase):
    def denied(self,operation):
        with self.assertRaisesRegex(ValueError,'^Invalid proof context$'):
            operation()

    def test_all_real_signatures_and_exact_cose_bytes(self):
        combinations=set()
        for row in V['challenges']:
            with self.subTest(name=row['name']):
                self.assertEqual(CODEC['signing_bytes']('challenge',row['fields']).hex(),row['signing_hex'])
                self.assertEqual(CODEC['assemble']('challenge',row['fields'],bytes.fromhex(row['signature_hex'])).hex(),row['hex'])
                result=verify_ch(row);self.assertEqual(result.to_fields(),row['fields'])
                self.assertEqual(result.content_id.hex(),hashlib.sha256(bytes.fromhex(row['signing_hex'])).hexdigest())
                combinations.add((row['fields']['purpose'],row['fields']['environment']))
        self.assertEqual(combinations,{(p,e) for p in ['first_claim','phone_replace'] for e in ['development','production']})
        for row in V['proofs']:
            with self.subTest(name=row['name']):
                self.assertEqual(CODEC['signing_bytes']('proof',row['fields']).hex(),row['signing_hex'])
                self.assertEqual(CODEC['assemble']('proof',row['fields'],bytes.fromhex(row['signature_hex'])).hex(),row['hex'])
                result=verify_pr(row);self.assertEqual(result.to_fields(),row['fields'])
                self.assertEqual(result.key_sha256.hex(),hashlib.sha256(bytes.fromhex(row['public_key'])).hexdigest())
        a,b=verify_ch(),verify_ch(CH['dev-alternate-signature'])
        self.assertEqual(a.content_id,b.content_id)
        self.assertNotEqual(BASE['signature_hex'],CH['dev-alternate-signature']['signature_hex'])

    def test_all_invalid_wire_fields_and_relationships_fail_without_disclosure(self):
        for row in V['invalid_objects']:
            with self.subTest(name=row['name']):
                if row['kind']=='challenge':self.denied(lambda:verify_ch(row))
                elif row['kind']=='proof':self.denied(lambda:verify_pr(row))
                else:self.denied(lambda:CODEC['match_field'](bytes.fromhex(row['hex']),row['expected']))
        for row in V['invalid_fields']+V['invalid_relations']:
            with self.subTest(name=row['name']):self.denied(lambda:CODEC['fields'](row['kind'],row['fields']))

    def test_server_completion_expiry_replay_and_renewal_vectors(self):
        for row in V['completions']:
            with self.subTest(name=row['name']):
                ch=verify_ch(CH[row['challenge']]);lp=verify_pr(PR[row['link_proof']]);pp=verify_pr(PR[row['phone_proof']])
                operation=lambda:CODEC['check_setup_completion'](ch,lp,pp,row['now'],bytes.fromhex(row['known']),row['used'])
                if row['result']=='deny':self.denied(operation)
                else:self.assertIsNone(operation())
        # Pure validation has no database transaction/consumption side effect.
        ch=verify_ch();lp=verify_pr(PR['dev-first_claim-Link']);pp=verify_pr(PR['dev-first_claim-Phone'])
        for _ in range(2):self.assertIsNone(CODEC['check_setup_completion'](ch,lp,pp,BASE['fields']['issued_at'],ch.content_id,False))
        self.denied(lambda:CODEC['check_setup_completion'](ch,lp,pp,BASE['fields']['issued_at'],ch.content_id,True))
        for now in [None,True,-1,1.5,4294967296]:self.denied(lambda:CODEC['check_setup_completion'](ch,lp,pp,now,ch.content_id,False))
        for known in [None,'x'*32,b'x']:
            self.denied(lambda:CODEC['check_setup_completion'](ch,lp,pp,BASE['fields']['issued_at'],known,False))
        self.denied(lambda:CODEC['check_setup_completion'](ch,None,pp,BASE['fields']['issued_at'],ch.content_id,False))
        self.denied(lambda:CODEC['check_setup_completion'](None,lp,pp,BASE['fields']['issued_at'],ch.content_id,False))

    def test_device_local_window_is_current_boot_nonce_and_monotonic_elapsed(self):
        for row in V['local_windows']:
            operation=lambda:CODEC['check_local_window'](verify_ch(CH[row['challenge']]),row['boot'],row['nonce'],row['elapsed'])
            with self.subTest(name=row['name']):
                if row['result']=='deny':self.denied(operation)
                else:self.assertIsNone(operation())
        self.assertEqual(CODEC['WINDOW'],300)

    def test_field_bytes_match_but_remain_untrusted_without_a_handshake(self):
        for row in V['fields']:
            raw=CODEC['encode_field'](row['fields']);self.assertEqual(raw.hex(),row['hex'])
            result=CODEC['match_field'](raw,row['fields']);self.assertEqual(result.to_fields(),row['fields'])
            self.assertIsInstance(result,CODEC['UntrustedFieldContext'])
            self.assertEqual(result.context_id,hashlib.sha256(raw).digest())
            with self.assertRaises(TypeError):result.metadata['kind']='ready'
            exported=result.to_fields();exported['kind']='ready';self.assertEqual(result.to_fields(),row['fields'])
            self.assertNotIn('initiator_uuid',repr(result));self.assertFalse(hasattr(result,'authenticated'))

    def test_binding_derivation_requires_current_owner_policy_and_exact_attempt(self):
        for row in V['bindings']:
            args=(authority(row['policy']),authority(row['owner']),authority(row['link_owner']) if row.get('link_owner') else None,row['attempt'])
            with self.subTest(name=row['name']):
                if row['result']=='deny':self.denied(lambda:CODEC['build_field'](*args))
                else:self.assertEqual(CODEC['build_field'](*args).hex(),row['hex'])
        row=V['bindings'][0]
        for attempt in [None,{},[],{**row['attempt'],'ready':True}]:
            self.denied(lambda:CODEC['build_field'](authority(row['policy']),authority(row['owner']),None,attempt))

    def test_field_context_has_no_clock_network_or_online_expiry(self):
        row=V['bindings'][0];p,o=authority(row['policy']),authority(row['owner'])
        with patch.object(socket,'create_connection',side_effect=AssertionError('Unexpected network')), \
             patch.object(time,'time',side_effect=AssertionError('Unexpected wall clock')):
            raw=CODEC['build_field'](p,o,None,row['attempt'])
            result=CODEC['match_field'](raw,V['fields'][0]['fields'])
            self.assertIsInstance(result,CODEC['UntrustedFieldContext'])
        self.assertNotIn('expires_at',result.to_fields())

    def test_constructor_capacities_include_all_header_domain_and_payload_bytes(self):
        for kind,row,maximum,signing in [('challenge',CH['dev-maximum'],426,398),('proof',V['proofs'][0],151,118)]:
            self.assertEqual(len(CODEC['assemble'](kind,row['fields'],bytes.fromhex(row['signature_hex']),maximum)),maximum)
            self.denied(lambda:CODEC['assemble'](kind,row['fields'],bytes.fromhex(row['signature_hex']),maximum-1))
            self.assertEqual(len(CODEC['signing_bytes'](kind,row['fields'],signing)),signing)
            self.denied(lambda:CODEC['signing_bytes'](kind,row['fields'],signing-1))
        f=V['fields'][0]['fields'];self.assertEqual(len(CODEC['encode_field'](f,368)),368)
        self.denied(lambda:CODEC['encode_field'](f,367))
        for limit in [None,True,0,-1,513]:
            self.denied(lambda:CODEC['signing_bytes']('challenge',BASE['fields'],limit))
            self.denied(lambda:CODEC['assemble']('challenge',BASE['fields'],bytes.fromhex(BASE['signature_hex']),limit))
            self.denied(lambda:CODEC['encode_field'](f,limit))
        for sig in [None,'x'*64,b'x'*63]:self.denied(lambda:CODEC['assemble']('challenge',BASE['fields'],sig))
        self.denied(lambda:CODEC['signing_bytes']('field',f));self.denied(lambda:CODEC['assemble']('field',f,b'x'*64))
        for kind,value in [(None,{}),([],{}),('unknown',{}),('proof',None),('proof',[])]:self.denied(lambda:CODEC['fields'](kind,value))
        for encoding in ['purpose','signer','kind','link_role']:
            for value in [None,1,[], 'admin']:self.denied(lambda:CODEC['to_wire'](value,encoding))

    def test_every_truncation_large_input_and_malformed_cbor(self):
        for row,kind in [(BASE,'challenge'),(V['proofs'][0],'proof')]:
            raw=bytes.fromhex(row['hex'])
            for n in range(len(raw)):
                self.denied(lambda:CODEC['envelope'](kind,raw[:n]))
        raw=bytes.fromhex(V['fields'][0]['hex']);expected=V['fields'][0]['fields']
        for n in range(len(raw)):self.denied(lambda:CODEC['match_field'](raw[:n],expected))
        for value in [None,[],bytearray(b'x'),'secret',b'x'*1000000]:
            with patch.dict(CODEC['BASE'],uncbor=lambda _:self.fail('Parsed oversized/wrong-type input')):
                self.denied(lambda:CODEC['envelope']('challenge',value))
                self.denied(lambda:CODEC['match_field'](value,expected))
        rng=random.Random(4203)
        for _ in range(350):
            data=b'\xd2'+bytes(rng.randrange(256) for _ in range(rng.randrange(1,100)))
            self.denied(lambda:CODEC['envelope']('challenge',data))

    def test_expected_context_and_crypto_adapters_are_strict(self):
        for environment in [None,'staging',1,[]]:self.denied(lambda:verify_ch(environment=environment))
        for expected in [None,{},[],{**BASE['expected'],'ready':True},{**BASE['expected'],'link_uuid':'invalid'}]:
            self.denied(lambda:verify_ch(expected=expected))
        for method in ['valid_public_key','verify']:
            for value in [False,1,None]:
                with patch.object(CRYPTO,method,return_value=value):
                    self.denied(lambda:verify_ch());self.denied(lambda:verify_pr(V['proofs'][0],current_challenge=CHALLENGE_VERIFIED))
            with patch.object(CRYPTO,method,side_effect=RuntimeError('private input')):
                self.denied(lambda:verify_ch());self.denied(lambda:verify_pr(V['proofs'][0],current_challenge=CHALLENGE_VERIFIED))
        for key in [None,bytearray(bytes.fromhex(V['proofs'][0]['public_key'])),b'x'*65,b'\x04'*64]:
            self.denied(lambda:verify_pr(V['proofs'][0],public_key=key))
        self.denied(lambda:verify_pr(V['proofs'][0],current_challenge=None))
        for issuers in [None,{},[],V['issuers']*3,[None],[{}],
                        [{**V['issuers'][2],'environment':'staging'}],[{**V['issuers'][2],'purpose':'anything'}],
                        [{**V['issuers'][2],'kid':'00'*8}],[{**V['issuers'][2],'public_key':'02'+'11'*64}],
                        [V['issuers'][2],{**V['issuers'][2],'purpose':'factory_identity'}]]:
            self.denied(lambda:verify_ch(issuers=issuers))
        self.assertEqual(verify_ch(issuers=tuple(V['issuers'])).to_fields(),BASE['fields'])

    def test_envelope_headers_payloads_and_scalar_encodings(self):
        enc,dec=CODEC['BASE']['cbor'],CODEC['BASE']['uncbor'];env=dec(bytes.fromhex(BASE['hex'])[1:])
        def reject(value):self.denied(lambda:CODEC['envelope']('challenge',b'\xd2'+enc(value)))
        for value in [{},[0]*3,[0,{},env[2],env[3]],[env[0],[],env[2],env[3]],[env[0],{},0,env[3]],[env[0],{},env[2],0]]:reject(value)
        for h in [0,{}, {1:-7,4:1},{1:-7,4:b'x'}]:reject([enc(h),{},env[2],env[3]])
        for p in [[],{}, {1:1}]:reject([env[0],{},enc(p),env[3]])
        payload=dec(env[2])
        for index,value in [(2,b'\x01'),(4,'uuid'),(4,b'x'),(9,'hash')]:reject([env[0],{},enc({**payload,index:value}),env[3]])
        # Schema permits whole-number JSON values; encoder normalises to CBOR uint.
        whole={**BASE['fields'],'v':1.0,'issued_at':float(BASE['fields']['issued_at'])}
        self.assertEqual(CODEC['signing_bytes']('challenge',whole).hex(),BASE['signing_hex'])
        with self.assertRaises(TypeError):CHALLENGE_VERIFIED.metadata['owner_ref']='other'
        self.assertNotIn('owner_ref',repr(CHALLENGE_VERIFIED))

    def test_negative_controls_signature_expiry_account_and_nonce_binding(self):
        source=(FOLDER/'codec.py').read_text()
        def altered(before,after):
            self.assertEqual(source.count(before),1);scope={'__file__':str(FOLDER/'codec.py')}
            exec(compile(source.replace(before,after),'<proof-negative-control>','exec'),scope);return scope
        variant=altered('crypto.verify(public_key,message,signature) is True','True')
        bad=next(r for r in V['invalid_objects'] if r['name']=='dev-first_claim-Link-signature')
        with self.assertRaises(AssertionError):self.denied(lambda:verify_pr(bad,variant))
        variant=altered(" or instant >= value['expires_at']",'')
        ch=verify_ch(codec=variant);lp=verify_pr(PR['dev-first_claim-Link'],variant);pp=verify_pr(PR['dev-first_claim-Phone'],variant)
        with self.assertRaises(AssertionError):self.denied(lambda:variant['check_setup_completion'](ch,lp,pp,BASE['fields']['expires_at'],ch.content_id,False))
        variant=altered('for name in EXPECTED):',"for name in EXPECTED if name != 'owner_ref'):")
        bad=next(r for r in V['invalid_objects'] if r['name']=='dev-first_claim-wrong-owner')
        with self.assertRaises(AssertionError):self.denied(lambda:verify_ch(bad,variant))
        variant=altered('if value != expected:',"if {k:v for k,v in value.items() if k != 'responder_nonce'} != {k:v for k,v in expected.items() if k != 'responder_nonce'}:")
        row=V['fields'][0];changed={**row['fields'],'responder_nonce':'ab'*32}
        with self.assertRaises(AssertionError):self.denied(lambda:variant['match_field'](bytes.fromhex(row['hex']),changed))


CHALLENGE_VERIFIED=verify_ch()


class ProofContextPinTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name);self.folder=self.root/LOCK['path']
        shutil.copytree(FOLDER,self.folder);(self.root/'proof-context.lock.json').write_text(json.dumps(LOCK))
        for family in ['device-credential','device-authority']:
            lock=json.loads((ROOT/(family+'.lock.json')).read_text());shutil.copytree(ROOT/lock['path'],self.root/lock['path']);(self.root/(family+'.lock.json')).write_text(json.dumps(lock))

    def repin(self):
        lock=copy.deepcopy(LOCK);lock['files']={n:hashlib.sha256((self.folder/n).read_bytes()).hexdigest() for n in LOCK['files']};(self.root/'proof-context.lock.json').write_text(json.dumps(lock))

    def test_actual_snapshot_cli_and_both_dependency_pins(self):
        expected={k:len(V[k]) for k in checker.COUNTS};self.assertEqual(checker.verify(ROOT),expected);self.assertEqual(checker.verify(self.root),expected)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):runpy.run_path(str(ROOT/'tools/verify_proof_context.py'),run_name='__main__')
        self.assertEqual(json.loads(stream.getvalue()),expected)
        for family in ['device_credential','device_authority']:
            lock=copy.deepcopy(LOCK);lock['requires_'+family+'_files_sha256']={};(self.root/'proof-context.lock.json').write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError,'dependency mismatch'):checker.verify(self.root)

    def test_pin_inventory_hash_symlink_guards(self):
        for name,value in [('profile','other'),('version',2),('source_repository','other'),('path','../outside'),('files',{})]:
            (self.root/'proof-context.lock.json').write_text(json.dumps({**LOCK,name:value}))
            with self.assertRaisesRegex(ValueError,'Unsupported proof context pin'):checker.verify(self.root)
        (self.root/'proof-context.lock.json').write_text(json.dumps(LOCK));extra=self.folder/'extra';extra.write_text('unexpected')
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
        extra.unlink();path=self.folder/'codec.py';original=path.read_bytes();path.write_bytes(original+b'\n')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        path.write_bytes(original);lock=copy.deepcopy(LOCK);lock['files']['codec.py']='invalid';(self.root/'proof-context.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        (self.root/'proof-context.lock.json').write_text(json.dumps(LOCK));path.unlink();path.symlink_to(FOLDER/'codec.py')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        shutil.rmtree(self.folder);self.folder.symlink_to(FOLDER,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)

    def test_repinned_schema_profile_vectors_and_redaction(self):
        cases=[('profile.json',lambda x:x.update(version=2),'profile'),('fields.schema.json',lambda x:x.update(oneOf=[]),'schema'),
          ('vectors.json',lambda x:x.update(synthetic=False),'vectors'),('vectors.json',lambda x:x.update(challenges=[]),'vectors'),
          ('vectors.json',lambda x:x['challenges'][0].update(signing_hex='00'),'positive vector'),('vectors.json',lambda x:x['proofs'][0].update(hex='00'),'positive vector'),
          ('vectors.json',lambda x:x['fields'][0].update(hex='00'),'field vector'),('vectors.json',lambda x:x['invalid_fields'][0].update(fields=BASE['fields']),'invalid fields accepted')]
        for name,change,message in cases:
            path=self.folder/name;original=path.read_bytes();value=json.loads(path.read_text());change(value);path.write_text(json.dumps(value));self.repin()
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,message):checker.verify(self.root)
            path.write_bytes(original);self.repin()
        path=self.folder/'codec.py';path.write_text(path.read_text().replace("ERROR = 'Invalid proof context'","ERROR = 'private payload'"));self.repin()
        with self.assertRaisesRegex(ValueError,'may disclose'):checker.verify(self.root)

    def test_independent_reference_failure_and_false_negative_vector(self):
        actual=checker.subprocess.run
        for result in [subprocess.CompletedProcess([],1,'',''),subprocess.CompletedProcess([],0,'{}','')]:
            def run(args,**kwargs):return result if 'proof-context/reference.mjs' in args[1] else actual(args,**kwargs)
            with patch.object(checker.subprocess,'run',side_effect=run):
                with self.assertRaisesRegex(ValueError,'Independent proof context'):checker.verify(self.root)
        path=self.folder/'vectors.json';v=json.loads(path.read_text());v['invalid_objects'][0].update(hex=BASE['hex']);path.write_text(json.dumps(v));self.repin()
        with self.assertRaisesRegex(ValueError,'Independent proof context'):checker.verify(self.root)


if __name__=='__main__':unittest.main()
