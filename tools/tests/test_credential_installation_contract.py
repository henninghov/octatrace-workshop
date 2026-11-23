"""Pinned installation proof compatibility, signatures and dependency denial."""
import json
from pathlib import Path
import runpy,shutil,sys,tempfile,unittest
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_credential_installation
class InstallationContractTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.snapshot='contracts' if (ROOT/'contracts/credential-installation').exists() else 'vendor'
        shutil.copytree(ROOT/self.snapshot,self.root/self.snapshot)
        for pin in ROOT.glob('*.lock.json'):shutil.copy2(pin,self.root/pin.name)
    def tearDown(self):self.temp.cleanup()
    def test_schema_signed_message_and_each_signed_binding(self):
        self.assertEqual(verify_credential_installation.verify(self.root)['scope'],'confirmed append-only installation')
        folder=self.root/self.snapshot/'credential-installation';vector=json.loads((folder/'vectors.json').read_text());frame=vector['frame']
        schema=Draft202012Validator(json.loads((folder/'response.schema.json').read_text()));self.assertTrue(schema.is_valid(frame))
        policy=runpy.run_path(str(folder/'policy.py'));self.assertEqual(policy['verify'](frame,frame['id'],vector['expected']),frame)
        changes=[{'signature':'00'*64},{'fault':True},{'slots_used':10},{'journal_state':'unknown'},{'journal_revision':1},{'extra':1},
                 {'result':'installed'},{'journal_content_id':'ff'*32},{'fault':2}]
        for change in changes:
            with self.subTest(change=change):
                bad=dict(frame,**change)
                with self.assertRaises(ValueError):policy['verify'](bad,frame['id'],vector['expected'])
        # Still well-shaped, but independently selected bindings/signature fail.
        for field in ('build','boot','hardware','challenge','content_id','envelope_sha256'):
            bad=dict(frame);bad[field]='f'*len(frame[field])
            with self.assertRaises(ValueError):policy['verify'](bad,frame['id'],vector['expected'])
    def test_repin_inventory_and_dependency_changes_fail_closed(self):
        folder=self.root/self.snapshot/'credential-installation';file=folder/'policy.py';original=file.read_text();file.write_text(original+'\n# changed\n')
        with self.assertRaises(ValueError):verify_credential_installation.verify(self.root)
        file.write_text(original);pin=self.root/'credential-installation.lock.json';data=json.loads(pin.read_text());data['files']['policy.py']='0'*64;pin.write_text(json.dumps(data))
        with self.assertRaises(ValueError):verify_credential_installation.verify(self.root)
        shutil.copy2(ROOT/pin.name,pin);(folder/'unexpected').write_text('x')
        with self.assertRaises(ValueError):verify_credential_installation.verify(self.root)
        (folder/'unexpected').unlink();(self.root/self.snapshot/'credential-delivery/policy.py').write_text('changed')
        with self.assertRaises(ValueError):verify_credential_installation.verify(self.root)
if __name__=='__main__':unittest.main()
