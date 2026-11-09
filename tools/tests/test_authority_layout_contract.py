"""Portable target-reservation contract tests. No device or flash writer."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'authority-layout.lock.json').is_file())
sys.path.insert(0,str(ROOT/'tools'))
import verify_authority_layout as checker
PIN=json.loads((ROOT/'authority-layout.lock.json').read_text());FOLDER=ROOT/PIN['path'];P=runpy.run_path(str(FOLDER/'policy.py'))

class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.cap=P['capability']('a'*64,'b'*64);self.manifest={'authority_storage_reservation':self.cap,'phone_storage_reservation':dict(P['SYMBOLS'],__octatrace_image_end=P['START'])}
    def test_exact_reservation_keeps_existing_regions_and_is_not_runtime_authority(self):
        self.assertTrue(P['compatible'](self.manifest,self.cap));self.assertEqual(P['TOTAL'],24576);self.assertEqual(self.cap['scope'],'reservation_only');self.assertIs(self.cap['runtime_authority'],False);self.assertEqual(self.cap['maintenance_version'],0)
        self.assertEqual(P['SYMBOLS']['__octatrace_control_start'],0xe7000);self.assertEqual(P['SYMBOLS']['__octatrace_identity_end'],0xef000)
        for value in [None,{},[],True]:
            if value!={}:self.assertFalse(P['compatible'](value,self.cap))
        for field in self.cap:
            m=copy.deepcopy(self.manifest);m['authority_storage_reservation'].pop(field);self.assertFalse(P['compatible'](m,self.cap))
        for value in [None,[],{},'legacy']:
            self.assertFalse(P['compatible']({**self.manifest,'authority_storage_reservation':value},self.cap))
        m=copy.deepcopy(self.manifest);m['authority_storage_reservation']['runtime_authority']=True;self.assertFalse(P['compatible'](m,self.cap))
        m=copy.deepcopy(self.manifest);m['authority_storage_reservation']['version']=True;self.assertFalse(P['compatible'](m,self.cap))
        m=copy.deepcopy(self.manifest);m['authority_storage_reservation']['version']=1.0;self.assertFalse(P['compatible'](m,self.cap))
    def test_every_symbol_and_image_boundary_is_exact_and_rejects_bool(self):
        for name in P['SYMBOLS']:
            for value in [None,True,str(P['SYMBOLS'][name]),P['SYMBOLS'][name]+4]:
                m=copy.deepcopy(self.manifest);m['phone_storage_reservation'][name]=value;self.assertFalse(P['compatible'](m,self.cap))
        for value in [None,{},[],True]:self.assertFalse(P['compatible']({**self.manifest,'phone_storage_reservation':value},self.cap))
        for value in [None,True,0x25fff,P['START']+1]:
            m=copy.deepcopy(self.manifest);m['phone_storage_reservation']['__octatrace_image_end']=value;self.assertFalse(P['compatible'](m,self.cap))
        for value in [0x26000,P['START']]:
            m=copy.deepcopy(self.manifest);m['phone_storage_reservation']['__octatrace_image_end']=value;self.assertTrue(P['compatible'](m,self.cap))
    def test_digest_fields_and_resource_budget_boundaries(self):
        for value in [None,'a'*63,'A'*64,True]:
            with self.assertRaisesRegex(ValueError,'Invalid authority reservation'):P['capability'](value,'b'*64)
            with self.assertRaises(ValueError):P['capability']('a'*64,value)
        r=P['resource_budget'](0x80000,128720,12288);self.assertEqual(r['application_capacity'],765952);self.assertEqual(r['ram_after_static_and_workspace'],96560)
        for args in [(True,0,0),(0x26000,-1,0),(0x26000,0,None),(0x26000,237568,1),(0x26000,0,12289),(P['START']+1,0,0),(0x25fff,0,0)]:
            with self.assertRaises(ValueError):P['resource_budget'](*args)
    def test_negative_controls_missing_overlap_or_json_type_guard_are_detected(self):
        source=(FOLDER/'policy.py').read_text()
        def altered(old,new):
            self.assertEqual(source.count(old),1);s={'__file__':str(FOLDER/'policy.py')};exec(compile(source.replace(old,new),'<layout-negative-control>','exec'),s);return s
        bad=altered('0x26000<=end<=START','0x26000<=end');m=copy.deepcopy(self.manifest);m['phone_storage_reservation']['__octatrace_image_end']=P['START']+1;self.assertTrue(bad['compatible'](m,self.cap));self.assertFalse(P['compatible'](m,self.cap))
        old="if any(type(metadata.get(k)) is not type(v) for k,v in expected.items()):";bad=altered(old,'if False:');m=copy.deepcopy(self.manifest);m['authority_storage_reservation']['version']=True;self.assertTrue(bad['compatible'](m,self.cap));self.assertFalse(P['compatible'](m,self.cap))

class PinTest(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.folder=self.root/PIN['path'];shutil.copytree(FOLDER,self.folder);(self.root/'authority-layout.lock.json').write_text(json.dumps(PIN))
        for family in ['authority-storage','device-authority','device-credential']:
            p=json.loads((ROOT/(family+'.lock.json')).read_text());(self.root/(family+'.lock.json')).write_text(json.dumps(p));shutil.copytree(ROOT/p['path'],self.root/p['path'])
    def repin(self):
        p=copy.deepcopy(PIN);p['files']={n:hashlib.sha256((self.folder/n).read_bytes()).hexdigest() for n in PIN['files']};(self.root/'authority-layout.lock.json').write_text(json.dumps(p))
    def test_owner_consumer_pins_cli_and_dependency(self):
        self.assertEqual(checker.verify(ROOT)['bytes'],24576);self.assertEqual(checker.verify(self.root)['bytes'],24576);out=io.StringIO()
        with contextlib.redirect_stdout(out):runpy.run_path(str(ROOT/'tools/verify_authority_layout.py'),run_name='__main__')
        self.assertEqual(json.loads(out.getvalue())['start'],'0xe1000')
        p=copy.deepcopy(PIN);p['requires_authority_storage_files_sha256']={};(self.root/'authority-layout.lock.json').write_text(json.dumps(p))
        with self.assertRaisesRegex(ValueError,'dependency mismatch'):checker.verify(self.root)
    def test_inventory_hash_path_symlinks(self):
        for k,v in [('profile','bad'),('version',2),('source_repository','bad'),('path','../bad'),('files',{})]:
            (self.root/'authority-layout.lock.json').write_text(json.dumps({**PIN,k:v}))
            with self.assertRaisesRegex(ValueError,'Unsupported authority layout pin'):checker.verify(self.root)
        (self.root/'authority-layout.lock.json').write_text(json.dumps(PIN));p=self.folder/'extra';p.write_text('x')
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
        p.unlink();p=self.folder/'policy.py';original=p.read_bytes();p.write_bytes(original+b'\n')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        p.write_bytes(original);lock=copy.deepcopy(PIN);lock['files']['policy.py']='bad';(self.root/'authority-layout.lock.json').write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        (self.root/'authority-layout.lock.json').write_text(json.dumps(PIN));p.unlink();p.symlink_to(FOLDER/'policy.py')
        with self.assertRaisesRegex(ValueError,'checksum'):checker.verify(self.root)
        shutil.rmtree(self.folder);self.folder.symlink_to(FOLDER,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'inventory'):checker.verify(self.root)
    def test_repinned_contract_schema_geometry_positive_and_overlap_guards(self):
        cases=[('contract.json',lambda x:x.update(version=True),'contract'),('manifest.schema.json',lambda x:x.update(required=[]),'schema')]
        for name,mutate,message in cases:
            p=self.folder/name;old=p.read_text();v=json.loads(old);mutate(v);p.write_text(json.dumps(v));self.repin()
            with self.assertRaisesRegex(ValueError,message):checker.verify(self.root)
            p.write_text(old);self.repin()
        p=self.folder/'policy.py';old=p.read_text()
        for before,after,message in [('START = 0xe1000','START = 0xe0000','geometry mismatch'),('return type(end) is int and 0x26000<=end<=START','return False','positive manifest rejected'),('return type(end) is int and 0x26000<=end<=START','return True','overlap accepted')]:
            self.assertEqual(old.count(before),1);p.write_text(old.replace(before,after));self.repin()
            with self.assertRaisesRegex(ValueError,message):checker.verify(self.root)
            p.write_text(old);self.repin()

if __name__=='__main__':unittest.main()
