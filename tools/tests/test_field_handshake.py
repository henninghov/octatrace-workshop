"""Portable profile/credential metadata tests; not an authenticated handshake."""
import contextlib
import copy
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'field-handshake.lock.json').is_file())
sys.path.insert(0,str(ROOT/'tools'))
import verify_field_handshake as checker
PIN=json.loads((ROOT/'field-handshake.lock.json').read_text());FOLDER=ROOT/PIN['path'];C=runpy.run_path(str(FOLDER/'codec.py'));V=json.loads((FOLDER/'vectors.json').read_text())
class PublicFixture:
 def valid_public_key(self,_):return True

class CodecTest(unittest.TestCase):
 def test_profile_dimensions_airtime_baseline_and_time_policies_are_separate(self):
  profile=json.loads((FOLDER/'profile.json').read_text());transport=profile['transport'];self.assertEqual(profile['version'],2);self.assertEqual(transport['radio']['version'],2);self.assertEqual(transport['bluetooth']['version'],2);self.assertEqual(transport['radio']['header'][5],'receiver_selector8');self.assertEqual(transport['active_attempts_per_endpoint'],1)
  self.assertEqual(transport['message_bytes'],256);self.assertEqual(transport['workspace_budget_bytes'],12288)
  for name,header,frame in [('radio',32,74),('bluetooth',8,20)]:
   item=transport[name];payload=frame-header;self.assertEqual(item['fragment_payload_bytes'],payload)
   self.assertEqual(item['maximum_fragments'],(256+payload-1)//payload);self.assertIn('zero-pad',item['frame_encoding'])
  self.assertEqual(transport['radio']['attempt_window_ms'],300000);self.assertEqual(transport['bluetooth']['attempt_window_ms'],30000)
  self.assertEqual(profile['binding']['confirmation_ciphertext_bytes'],48);self.assertEqual(profile['protocol']['ead'],'none')
  self.assertEqual(profile['protocol']['method'],0);self.assertEqual(profile['protocol']['suite'],2)
  self.assertIn('no wall-clock expiry',profile['lifecycle']['offline'])
 def test_exact_credential_and_short_reference_are_public_untrusted_metadata(self):
  for row in V['credentials']:
   point=bytes.fromhex(row['public_key']);r=C['credential'](point,PublicFixture());self.assertEqual(len(r.ccs),81)
   self.assertEqual({n:getattr(r,n).hex() for n in ['ccs','kid','key_sha256','id_cred']},row['expected'])
   self.assertEqual(C['resolve'](r.kid,point,PublicFixture()),r);self.assertTrue(type(r).__name__.startswith('Untrusted'))
   self.assertFalse(hasattr(r,'authenticated'));self.assertFalse(hasattr(r,'ready'))
   with self.assertRaises(FrozenInstanceError):r.kid=b'copied'
  r=subprocess.run(['node',str(FOLDER/'reference.mjs'),str(FOLDER/'vectors.json')],capture_output=True,text=True,check=True)
  self.assertEqual(json.loads(r.stdout)['checks'],19)
 def test_public_key_lengths_real_provider_result_and_lookup_failure_are_strict(self):
  point=bytes.fromhex(V['credentials'][0]['public_key'])
  for p in [None,True,'04'*65,b'',bytearray(point),point[:64],b'\x03'+point[1:],point+b'\x00']:
   with self.assertRaisesRegex(ValueError,'^Invalid field handshake metadata$'):C['credential'](p,PublicFixture())
  class Result:
   def __init__(self,v):self.v=v
   def valid_public_key(self,_):
    if isinstance(self.v,Exception):raise self.v
    return self.v
  for value in [False,1,None,'true',RuntimeError('private diagnostic')]:
   with self.assertRaisesRegex(ValueError,'^Invalid field handshake metadata$'):C['credential'](point,Result(value))
  with self.assertRaisesRegex(ValueError,'^Invalid field handshake metadata$'):C['credential'](point,object())
  for kid in [None,True,'00'*8,b'',b'\0'*7,b'\0'*9,b'\0'*8]:
   with self.assertRaises(ValueError):C['resolve'](kid,point,PublicFixture())
 def test_prelude_bytes_attempt_match_and_immutability(self):
  for row in V['preludes']:
   data=C['encode_prelude'](row['fields']);self.assertEqual(data.hex(),row['hex']);p=C['decode_prelude'](data,row['fields']['attempt_uuid']);self.assertEqual(p.to_fields(),row['fields'])
   fields=p.to_fields();fields['boot']='other';self.assertEqual(p.to_fields(),row['fields']);self.assertNotIn(row['fields']['nonce'],repr(p))
   with self.assertRaises(TypeError):p.metadata['boot']='changed'
   with self.assertRaises(FrozenInstanceError):p.metadata={}
   for bad in [None,'',bytearray(data),data+b'\0',b'x'*1000000,*[data[:n] for n in range(64)]]:
    with self.assertRaises(ValueError):C['decode_prelude'](bad,row['fields']['attempt_uuid'])
   for expected in ['00000000-0000-4000-8000-000000000099',None,True,'invalid']:
    with self.assertRaises(ValueError):C['decode_prelude'](data,expected)
 def test_prelude_strict_shape_uuid_nonzero_hex_and_invalid_wire(self):
  value=V['preludes'][0]['fields']
  for bad in [None,[],True,{},dict(value,secret='do not echo')]:
   with self.assertRaisesRegex(ValueError,'^Invalid field handshake metadata$'):C['encode_prelude'](bad)
  for key,items in [('attempt_uuid',[None,True,'not-a-uuid','00000000-0000-1000-8000-000000000001']),('boot',[None,'00'*16,'AA'*16,'01'*15]),('nonce',[False,'00'*32,'AA'*32,'01'*31])]:
   for invalid in items:
    with self.assertRaises(ValueError):C['encode_prelude']({**value,key:invalid})
  data=bytes.fromhex(V['preludes'][0]['hex'])
  for bad in [data[:16]+b'\0'*16+data[32:],data[:32]+b'\0'*32]:
   with self.assertRaises(ValueError):C['decode_prelude'](bad,value['attempt_uuid'])
 def test_exact_field_export_labels_contexts_aad_and_no_key_or_readiness(self):
  contexts=[]
  for row in V['fields']:
   data=bytes.fromhex(row['hex']);contexts.append(row['context'])
   for purpose,label in C['PURPOSES'].items():
    r=C['export_request'](purpose,data,row['fields']);self.assertEqual((r.label,r.context.hex(),r.length,r.field_sha256.hex()),(label,row['context'],16,row['field_sha256']))
    self.assertTrue(type(r).__name__.startswith('Untrusted'));self.assertFalse(hasattr(r,'key'));self.assertFalse(hasattr(r,'ready'))
    with self.assertRaises(FrozenInstanceError):r.label=0
   for purpose,flight in [('initiator_confirmation',7),('responder_confirmation',8)]:
    aad=C['confirmation_aad'](purpose,data,row['fields']);kind=1 if row['fields']['kind']=='phone_link' else 2
    self.assertEqual(aad,C['CONFIRM_DOMAIN']+bytes([kind,flight])+bytes.fromhex(row['context']))
  self.assertEqual(len(set(contexts)),4);self.assertEqual(len(set(C['PURPOSES'].values())),4)
 def test_rotating_receiver_selector_is_only_routing_bound_to_attempt_kind_and_full_receiver_key(self):
  for row in V['receiver_selectors']:
   value=row['fields'];selector=C['receiver_selector'](**value);self.assertEqual(selector.hex(),row['hex']);self.assertEqual(len(selector),8)
   for field,replacement in [('kind','link_core' if value['kind']=='phone_link' else 'phone_link'),('attempt_uuid','00000000-0000-4000-8000-000000000099'),('recipient_key_sha256','fe'*32)]:
    self.assertNotEqual(C['receiver_selector'](**{**value,field:replacement}),selector)
   for field,values in [('kind',[None,True,1,'other']),('attempt_uuid',[None,True,'invalid','00000000-0000-1000-8000-000000000001']),('recipient_key_sha256',[None,True,'00'*32,'AA'*32,'01'*31])]:
    for bad in values:
     with self.assertRaisesRegex(ValueError,'^Invalid field handshake metadata$'):C['receiver_selector'](**{**value,field:bad})
 def test_bad_purpose_field_profile_and_every_current_context_binding_deny(self):
  row=V['fields'][0];data=bytes.fromhex(row['hex']);expected=row['fields']
  for purpose in [None,True,{},[],0,'','other']:
   with self.assertRaises(ValueError):C['export_request'](purpose,data,expected)
  for purpose in ['initiator_traffic',None,[]]:
   with self.assertRaises(ValueError):C['confirmation_aad'](purpose,data,expected)
  for bad in [None,b'',data[:-1],data+b'\0',b'x'*1000000]:
   with self.assertRaises(ValueError):C['export_request']('initiator_confirmation',bad,expected)
  for key in expected:
   changed={**expected,key:None}
   with self.assertRaises(ValueError):C['export_request']('initiator_confirmation',data,changed)
  for key in ['authority_context_sha256','initiator_key_sha256','responder_key_sha256','initiator_nonce','responder_nonce','transcript_sha256']:
   changed={**expected,key:'fe'*32}
   with self.assertRaises(ValueError):C['export_request']('initiator_confirmation',data,changed)
  changed={**expected,'handshake_profile_sha256':'ee'*32};wrong=C['PROOF']['encode_field'](changed)
  with self.assertRaises(ValueError):C['export_request']('initiator_confirmation',wrong,changed)
 def test_deliberate_fault_controls_detect_missing_reference_and_profile_checks(self):
  source=(FOLDER/'codec.py').read_text()
  def changed(old,new):
   self.assertEqual(source.count(old),1);scope={'__file__':str(FOLDER/'codec.py')};exec(compile(source.replace(old,new),'<field-negative-control>','exec'),scope);return scope
  bad=changed('if kid!=result.kid:','if False:');p=bytes.fromhex(V['credentials'][0]['public_key']);self.assertTrue(bad['resolve'](b'\0'*8,p,PublicFixture()))
  bad=changed("if match.metadata['handshake_profile_sha256']!=PROFILE_SHA256.hex():",'if False:');value={**V['fields'][0]['fields'],'handshake_profile_sha256':'ee'*32};data=C['PROOF']['encode_field'](value);self.assertTrue(bad['export_request']('initiator_confirmation',data,value))

class PinTest(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
  for family in ['field-handshake','proof-context','device-authority','device-credential']:
   pin=json.loads((ROOT/(family+'.lock.json')).read_text());(self.root/(family+'.lock.json')).write_text(json.dumps(pin));shutil.copytree(ROOT/pin['path'],self.root/pin['path'])
  self.folder=self.root/PIN['path']
 def repin(self):
  pin=copy.deepcopy(PIN);pin['files']={n:hashlib.sha256((self.folder/n).read_bytes()).hexdigest() for n in PIN['files']};(self.root/'field-handshake.lock.json').write_text(json.dumps(pin))
 def test_pins_cli_dependencies_and_valid_portable_snapshot(self):
  self.assertIs(checker.verify(ROOT)['authenticated_readiness'],False);self.assertEqual(checker.verify(self.root)['profile_sha256'],C['PROFILE_SHA256'].hex());out=io.StringIO()
  with contextlib.redirect_stdout(out):runpy.run_path(str(ROOT/'tools/verify_field_handshake.py'),run_name='__main__')
  self.assertFalse(json.loads(out.getvalue())['authenticated_readiness'])
  pin=copy.deepcopy(PIN);pin['requires_proof_context_files_sha256']={};(self.root/'field-handshake.lock.json').write_text(json.dumps(pin))
  with self.assertRaisesRegex(ValueError,'dependency'):checker.verify(self.root)
 def test_strict_pin_inventory_digest_and_symlink_fail_closed(self):
  for key,value in [('profile','other'),('version',True),('version',1),('files',[]),('path','../other'),('source_repository','wrong'),('files',{})]:
   (self.root/'field-handshake.lock.json').write_text(json.dumps({**PIN,key:value}))
   with self.assertRaisesRegex(ValueError,'pin'):checker.verify(self.root)
  (self.root/'field-handshake.lock.json').write_text('[]')
  with self.assertRaisesRegex(ValueError,'pin'):checker.verify(self.root)
  (self.root/'field-handshake.lock.json').write_text(json.dumps(PIN));p=self.folder/'extra';p.mkdir()
  with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
  p.rmdir();p=self.folder/'codec.py';original=p.read_text();p.write_text(original+'\n')
  with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
  p.write_text(original);pin=copy.deepcopy(PIN);pin['files']['codec.py']=True;(self.root/'field-handshake.lock.json').write_text(json.dumps(pin))
  with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
  (self.root/'field-handshake.lock.json').write_text(json.dumps(PIN));p.unlink();p.symlink_to(FOLDER/'codec.py')
  with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
  shutil.rmtree(self.folder);self.folder.symlink_to(FOLDER,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
  p=self.root/'field-handshake.lock.json';p.unlink();p.symlink_to(ROOT/'field-handshake.lock.json')
  with self.assertRaisesRegex(ValueError,'pin'):checker.verify(self.root)
 def test_repinned_profile_schema_and_each_vector_kind_remain_checked(self):
  for name,message,mutate in [('profile.json','profile',lambda v:v.update(version=True)),('profile.schema.json','schema',lambda v:v.update(const={})),('vectors.json','vectors',lambda v:v.update(synthetic=False)),('vectors.json','credential vector',lambda v:v['credentials'][0]['expected'].update(kid='00'*8)),('vectors.json','prelude vector',lambda v:v['preludes'][0]['fields'].update(boot='aa'*16)),('vectors.json','export vector',lambda v:v['fields'][0].update(context='00'*32)),('vectors.json','independent reference',lambda v:v['invalid_public_keys'].__setitem__(0,v['credentials'][0]['public_key'])),('vectors.json','receiver vector',lambda v:v['receiver_selectors'][0].update(hex='00'*8))]:
   p=self.folder/name;original=p.read_text();v=json.loads(original);mutate(v);p.write_text(json.dumps(v));self.repin()
   with self.assertRaisesRegex(ValueError,message):checker.verify(self.root)
   p.write_text(original);self.repin()

if __name__=='__main__':unittest.main()
