import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import verify_credential_readiness

class ReadinessContractTest(unittest.TestCase):
    def test_snapshot_and_guide_pin_same_readiness_contract(self):
        verify_credential_readiness.verify(ROOT)
        lock=json.loads((ROOT/'credential-readiness.lock.json').read_text())
        guide=json.loads((ROOT/'assets/bench/credential-readiness.v1.json').read_text())
        for name,digest in lock['files'].items():
            self.assertEqual(hashlib.sha256((ROOT/'vendor/credential-readiness'/name).read_bytes()).hexdigest(),digest)
            self.assertEqual(guide['runner']['additional_files']['contracts/credential-readiness/'+name],digest)
        self.assertEqual(guide['runner']['id'],'p1.credential-readiness')
        self.assertEqual([r['role'] for r in guide['builds']],['Link','Core'])

if __name__=='__main__': unittest.main()
