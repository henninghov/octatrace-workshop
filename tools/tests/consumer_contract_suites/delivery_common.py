"""Common consumer delivery vector and schema assertions."""
def _delivery_signed_vector_and_schema(self):
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
