"""Consumer compatibility and tamper denial for credential delivery."""
import json
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_credential_delivery

class DeliveryContractTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        shutil.copytree(ROOT/'vendor',self.root/'vendor')
        for path in ROOT.glob('*.lock.json'):shutil.copy2(path,self.root/path.name)
    def tearDown(self):self.temp.cleanup()
    def test_signed_vector_and_schema(self):
        self.assertEqual(verify_credential_delivery.verify(self.root)['scope'],'volatile verification only')
        folder=self.root/'vendor/credential-delivery'
        vector=json.loads((folder/'vectors.json').read_text());frame=vector['frame']
        schema=Draft202012Validator(json.loads((folder/'response.schema.json').read_text()))
        self.assertTrue(schema.is_valid(frame))
        policy=runpy.run_path(str(folder/'policy.py'))
        self.assertEqual(policy['verify'](frame,frame['id'],vector['expected']),frame)
        for change in ({'signature':'00'*64},{'boot':'00'*16},{'transfer_id':0},{'extra':1}):
            bad=dict(frame,**change)
            self.assertFalse(schema.is_valid(bad))
            with self.assertRaises(ValueError):policy['verify'](bad,frame['id'],vector['expected'])
    def test_guide_pins_the_same_contract_and_qualified_builds(self):
        guide=json.loads((ROOT/'assets/bench/credential-delivery.v1.json').read_text())
        pin=json.loads((ROOT/'credential-delivery.lock.json').read_text())
        self.assertEqual(guide['runner']['id'],'p1.credential-delivery')
        for name,digest in pin['files'].items():
            self.assertEqual(guide['runner']['additional_files']['contracts/credential-delivery/'+name],digest)
        self.assertEqual([row['role'] for row in guide['builds']],['Link','Core'])
        self.assertEqual(len({row['source'] for row in guide['builds']}),1)
        update=json.loads((ROOT/'assets/bench/claimed-firmware-update.v3.json').read_text())
        core=next(row for row in guide['builds'] if row['role']=='Core')
        self.assertEqual(update['after_source'],core['source'])
        self.assertEqual(update['after_artifact'],core['artifact'])
    def test_mutated_snapshot_repin_and_dependency_fail_closed(self):
        folder=self.root/'vendor/credential-delivery';file=folder/'policy.py';original=file.read_text()
        file.write_text(original+'\n# changed\n')
        with self.assertRaises(ValueError):verify_credential_delivery.verify(self.root)
        file.write_text(original);pin=self.root/'credential-delivery.lock.json';data=json.loads(pin.read_text())
        data['files']['policy.py']='0'*64;pin.write_text(json.dumps(data))
        with self.assertRaises(ValueError):verify_credential_delivery.verify(self.root)
        shutil.copy2(ROOT/'credential-delivery.lock.json',pin)
        (folder/'unexpected').write_text('x')
        with self.assertRaises(ValueError):verify_credential_delivery.verify(self.root)
        (folder/'unexpected').unlink()
        usb=self.root/'vendor/usb-provisioning.lock.json';value=json.loads(usb.read_text())
        value['files'][next(iter(value['files']))]='0'*64;usb.write_text(json.dumps(value))
        with self.assertRaises(ValueError):verify_credential_delivery.verify(self.root)

if __name__=='__main__':unittest.main()
